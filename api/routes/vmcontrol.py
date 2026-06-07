import base64
import logging
import time
from datetime import timedelta
from core.timezone import now_kst
from fastapi import APIRouter, HTTPException, status, Depends, Request
from sqlalchemy.orm import Session, joinedload
from schemas.vm_schema import VMAction, VMCreate, VMResize, SnapshotCreateRequest
from services.proxmox_client import get_proxmox_for_server, gather_per_server
from models.server import Server
from services.vm_service import create_vm, delete_vm
from core.database import get_db
from models.vm import Vm
from models.user import User, UserRole
from api.dependencies import get_current_user, get_current_active_admin, get_vm_with_owner_check
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/nodes")
def get_nodes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin),
):
    """Proxmox 노드 목록 조회 (관리자 전용)"""
    servers = db.query(Server).filter(Server.is_active == True).all()

    def fetch(server):
        return get_proxmox_for_server(server).nodes(server.name).status.get()

    status_by_id = gather_per_server(servers, fetch)
    result = []
    for server in servers:
        detail = status_by_id.get(server.id)
        if detail is not None:
            result.append({"name": server.name, "status": "online", "detail": detail})
        else:
            result.append({"name": server.name, "status": "offline", "detail": None})
    return {"nodes": result}


def _fetch_node_resources(server):
    """단일 노드의 리소스 사용량 조회 (스레드풀에서 서버별 병렬 실행)."""
    proxmox = get_proxmox_for_server(server)
    s = proxmox.nodes(server.name).status.get()
    cpu_used = round(s.get("cpu", 0) * 100, 1)
    mem = s.get("memory", {})
    mem_used_gb = round(mem.get("used", 0) / (1024 ** 3), 1)
    mem_total_gb = round(mem.get("total", 0) / (1024 ** 3), 1)
    # lvm-thin 스토리지 합산 (data, vm 등 여러 파티션)
    disk_used = 0
    disk_total = 0
    try:
        storages = proxmox.nodes(server.name).storage.get()
        for st in storages:
            if st.get("type") == "lvmthin":
                disk_used += st.get("used", 0)
                disk_total += st.get("total", 0)
    except Exception:
        pass
    return {
        "online": True,
        "cpu_percent": cpu_used,
        "mem_used_gb": mem_used_gb,
        "mem_total_gb": mem_total_gb,
        "disk_used_gb": round(disk_used / (1024 ** 3), 1),
        "disk_total_gb": round(disk_total / (1024 ** 3), 1),
    }


@router.get("/nodes/resources")
def get_nodes_resources(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """노드별 리소스 사용량 조회 (배포 페이지용)"""
    servers = db.query(Server).filter(Server.is_active == True).all()
    res_by_id = gather_per_server(servers, _fetch_node_resources)
    return {
        server.name: res_by_id.get(server.id, {"online": False})
        for server in servers
    }


@router.get("/{node}/vms")
def get_vms(
    node: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """특정 노드의 VM 목록 조회 (관리자: 전체, 일반 사용자: 본인 소유만)"""
    server = db.query(Server).filter(Server.name == node, Server.is_active == True).first()
    if not server:
        raise HTTPException(status_code=404, detail=f"노드 '{node}'을(를) 찾을 수 없습니다.")
    proxmox = get_proxmox_for_server(server)
    try:
        all_vms = proxmox.nodes(node).qemu.get()

        if current_user.role == UserRole.ADMIN:
            return {"vms": all_vms}

        user_vms = db.query(Vm).filter(Vm.owner_id == current_user.id).all()
        user_vmid_set = {vm.hypervisor_vmid for vm in user_vms}
        filtered_vms = [vm for vm in all_vms if vm.get('vmid') in user_vmid_set]
        return {"vms": filtered_vms}
    except Exception as e:
        logger.error(f"[vm] VM 목록 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="서버 오류가 발생했습니다.")


@router.get("/admin/all-vms")
def get_all_vms(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin),
):
    """전체 VM 목록 조회 — 노드별 그룹핑 (관리자 전용)"""
    servers = db.query(Server).filter(Server.is_active == True).all()
    # owner 를 함께 로드(joinedload)해 vm.owner.email 접근 시 발생하던 N+1 제거
    all_db_vms = db.query(Vm).options(joinedload(Vm.owner)).all()

    # DB VM을 server_id별 info dict 리스트로 매핑 (라이브 상태는 이후 병렬로 채움).
    # ORM 속성 접근은 메인 스레드에서 끝내고, 워커 스레드에는 dict 만 넘긴다.
    info_by_server: dict[int, list] = {}
    for vm in all_db_vms:
        info_by_server.setdefault(vm.server_id, []).append({
            "vmid": vm.hypervisor_vmid,
            "name": vm.display_name or vm.name,
            "node": None,  # 아래에서 서버명으로 채움
            "status": "unknown",
            "owner_email": vm.owner.email if vm.owner else None,
            "internal_ip": vm.internal_ip,
            "created_at": str(vm.created_at) if vm.created_at else None,
            "expires_at": str(vm.expires_at) if vm.expires_at else None,
        })
    for server in servers:
        for info in info_by_server.get(server.id, []):
            info["node"] = server.name

    def fetch(server):
        proxmox = get_proxmox_for_server(server)
        for info in info_by_server.get(server.id, []):
            try:
                vm_status = proxmox.nodes(server.name).qemu(info["vmid"]).status.current.get()
                info["status"] = vm_status.get("status", "unknown")
                info["cpu_usage"] = vm_status.get("cpu", 0)
                info["maxmem"] = vm_status.get("maxmem", 0)
                info["mem_usage"] = vm_status.get("mem", 0)
                info["maxdisk"] = vm_status.get("maxdisk", 0)
                info["uptime"] = vm_status.get("uptime", 0)
            except Exception:
                pass

    # VM이 있는 서버만 노드별로 병렬 조회 (서버마다 독립 연결 → 스레드 안전)
    gather_per_server([s for s in servers if info_by_server.get(s.id)], fetch)

    nodes = [
        {"name": server.name, "vms": info_by_server.get(server.id, [])}
        for server in servers
    ]
    return {"nodes": nodes}


@router.get("/my-vms")
def get_my_vms(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """현재 사용자가 소유한 모든 VM 목록 조회 (모든 노드 통합)"""
    # server 를 함께 로드(joinedload)해 vm.server.name 접근 시 발생하던 N+1 제거
    user_vms = (
        db.query(Vm)
        .options(joinedload(Vm.server))
        .filter(Vm.owner_id == current_user.id)
        .all()
    )

    # 서버별로 info dict 그룹핑. ORM 접근은 메인 스레드에서 끝내고,
    # 원래 VM 순서를 유지하기 위해 result 리스트에 같은 dict 참조를 담아둔다.
    from collections import defaultdict
    infos_by_server: dict[int, list] = defaultdict(list)
    servers_by_id: dict[int, object] = {}
    result = []
    for vm in user_vms:
        info = {
            "vmid": vm.hypervisor_vmid,
            "name": vm.display_name or vm.name,
            "node": vm.server.name,
            "status": "unknown",
            "internal_ip": vm.internal_ip,
            "created_at": str(vm.created_at) if vm.created_at else None,
            "expires_at": str(vm.expires_at) if vm.expires_at else None,
        }
        infos_by_server[vm.server_id].append(info)
        servers_by_id[vm.server_id] = vm.server
        result.append(info)

    def fetch(server):
        proxmox = get_proxmox_for_server(server)
        for info in infos_by_server[server.id]:
            try:
                vm_status = proxmox.nodes(server.name).qemu(info["vmid"]).status.current.get()
                info["status"] = vm_status.get("status", "unknown")
                info["cpu_usage"] = vm_status.get("cpu", 0)
                info["maxmem"] = vm_status.get("maxmem", 0)
                info["mem_usage"] = vm_status.get("mem", 0)
                info["maxdisk"] = vm_status.get("maxdisk", 0)
                uptime = vm_status.get("uptime", 0)
                info["uptime"] = uptime
                info["provisioning"] = (
                    vm_status.get("status") == "running" and 0 < uptime < 180
                )
            except Exception:
                pass

    # 노드별로 병렬 조회 (서버마다 독립 연결 → 스레드 안전)
    gather_per_server(list(servers_by_id.values()), fetch)
    return result


@router.get("/{node}/vms/{vmid}/status")
def get_vm_status(
    node: str,
    vmid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """특정 VM의 상세 상태 조회 (소유자 또는 관리자만 가능)"""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    node = vm_record.server.name  # URL 파라미터 대신 DB 값 사용 (IDOR 방지)
    proxmox = get_proxmox_for_server(vm_record.server)

    try:
        vm_status = proxmox.nodes(node).qemu(vmid).status.current.get()

        # cloud-init 완료 여부 확인 (running 상태일 때만)
        provisioning = False
        if vm_status.get("status") == "running":
            uptime = vm_status.get("uptime", 0)
            try:
                result = proxmox.nodes(node).qemu(vmid).agent.exec.post(
                    command="test -f /home/ubuntu/ok.txt && echo OK || echo NOTYET"
                )
                pid = result.get("pid")
                time.sleep(1)
                out = proxmox.nodes(node).qemu(vmid).agent("exec-status").get(pid=pid)
                stdout = base64.b64decode(out.get("out-data", "")).decode(errors="ignore")
                provisioning = "OK" not in stdout and 0 < uptime < 180
            except Exception:
                provisioning = 0 < uptime < 180

        # Proxmox 실시간 데이터 + DB 저장 데이터 통합
        return {
            "name": vm_record.display_name or vm_record.name,
            "status": vm_status.get("status", "unknown"),
            "provisioning": provisioning,
            "cpus": vm_status.get("cpus", vm_record.allocated_cores),
            "maxmem": vm_status.get("maxmem", 0),
            "maxdisk": vm_status.get("maxdisk", 0),
            "uptime": vm_status.get("uptime", 0),
            "cpu": vm_status.get("cpu", 0),
            "mem": vm_status.get("mem", 0),
            # DB 데이터
            "internal_ip": vm_record.internal_ip,
            "vm_password": vm_record.vm_password,
            "created_at": str(vm_record.created_at) if vm_record.created_at else None,
            "expires_at": str(vm_record.expires_at) if vm_record.expires_at else None,
            "node": vm_record.server.name,
            "public_ip": vm_record.server.ip_address,
        }
    except Exception as e:
        logger.error(f"[vm] VM 상태 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="서버 오류가 발생했습니다.")


@router.get("/{node}/vms/{vmid}/metrics")
def get_vm_metrics(
    node: str,
    vmid: int,
    timeframe: str = "hour",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    VM 실시간 메트릭 조회 (Proxmox rrddata).
    timeframe: hour | day (1h → hour, 6h/24h → day)
    """
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    node = vm_record.server.name
    logger.info(f"[metrics] 요청: node={node}, vmid={vmid}, timeframe={timeframe}")
    proxmox = get_proxmox_for_server(vm_record.server)

    if timeframe not in ("hour", "day"):
        timeframe = "hour"

    try:
        rrd = proxmox.nodes(node).qemu(vmid).rrddata.get(timeframe=timeframe)

        data_points = []
        for point in rrd:
            t = point.get("time", 0)
            if not t:
                continue
            cpu_val = point.get("cpu", 0) or 0
            maxmem = point.get("maxmem", 1) or 1
            mem_val = point.get("mem", 0) or 0
            netin = point.get("netin", 0) or 0
            netout = point.get("netout", 0) or 0
            diskread = point.get("diskread", 0) or 0
            diskwrite = point.get("diskwrite", 0) or 0

            data_points.append({
                "time": int(t),
                "cpu": round(cpu_val * 100, 1),
                "mem_used": round(mem_val / (1024 ** 2), 1),  # bytes → MB
                "mem_total": round(maxmem / (1024 ** 2), 1),
                "mem_percent": round((mem_val / maxmem) * 100, 1) if maxmem else 0,
                "netin": round(netin / 1024, 1),   # bytes/s → KB/s
                "netout": round(netout / 1024, 1),
                "diskread": round(diskread / 1024, 1),
                "diskwrite": round(diskwrite / 1024, 1),
            })

        return {"vmid": vmid, "timeframe": timeframe, "data": data_points}
    except Exception as e:
        logger.error(f"[vm] 메트릭 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="서버 오류가 발생했습니다.")


@router.put("/{node}/vms/{vmid}/resize")
def resize_vm(
    node: str,
    vmid: int,
    body: VMResize,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """VM CPU/메모리 핫플러그 변경 (프로젝트 오너/관리자 전용)"""
    if current_user.role not in (UserRole.ADMIN, UserRole.PROJECT_OWNER):
        raise HTTPException(status_code=403, detail="프로젝트 오너 또는 관리자만 사양을 변경할 수 있습니다.")

    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    server = vm_record.server
    proxmox = get_proxmox_for_server(server)

    # 현재 VM 설정 조회
    config = proxmox.nodes(server.name).qemu(vmid).config.get()
    hotplug = config.get("hotplug", "")
    if "cpu" not in hotplug and "memory" not in hotplug:
        raise HTTPException(status_code=400, detail="이 VM은 핫플러그가 활성화되지 않았습니다.")

    if not body.cores and not body.memory:
        raise HTTPException(status_code=400, detail="변경할 값이 없습니다.")

    update_params = {}
    max_memory = 32768  # 32GB

    if body.cores is not None:
        # cores 값은 총 vCPU 수 (2,4,6,8), 소켓 1 고정 + cores로 조절
        if body.cores not in (2, 4, 6, 8):
            raise HTTPException(status_code=400, detail="vCPU는 2, 4, 6, 8 중 선택해주세요.")
        update_params["cores"] = body.cores

    if body.memory is not None:
        if not (4096 <= body.memory <= max_memory):
            raise HTTPException(status_code=400, detail=f"RAM은 4096~{max_memory}MB (4~32GB) 범위입니다.")
        update_params["memory"] = body.memory
        update_params["balloon"] = body.memory // 2

    try:
        proxmox.nodes(server.name).qemu(vmid).config.put(**update_params)

        # DB 업데이트
        if body.cores is not None:
            vm_record.allocated_cores = body.cores
        if body.memory is not None:
            vm_record.allocated_ram_mb = body.memory
        db.commit()

        return {
            "success": True,
            "message": "VM 사양이 변경되었습니다.",
            "cores": vm_record.allocated_cores,
            "memory": vm_record.allocated_ram_mb,
        }
    except Exception as e:
        db.rollback()
        logger.error(f"[vm] 사양 변경 실패: {e}")
        raise HTTPException(status_code=500, detail="사양 변경에 실패했습니다.")


@router.post("/{node}/vms/{vmid}/extend")
def extend_vm(
    node: str,
    vmid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """VM 만료 기간을 30일 연장합니다. 만료 15일 전부터 가능."""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)

    if not vm_record.expires_at:
        raise HTTPException(status_code=400, detail="만료 기한이 없는 VM입니다.")

    now = now_kst()
    days_until_expiry = (vm_record.expires_at - now).days

    if days_until_expiry > 15:
        raise HTTPException(
            status_code=400,
            detail=f"만료 15일 전부터 연장할 수 있습니다. (남은 기간: {days_until_expiry}일)",
        )

    vm_record.expires_at = vm_record.expires_at + timedelta(days=30)
    db.commit()

    return {
        "success": True,
        "message": "VM 사용 기간이 30일 연장되었습니다.",
        "expires_at": str(vm_record.expires_at),
    }


@router.post("/{node}/vms/{vmid}/action")
@limiter.limit("10/minute")
def control_vm(
    request: Request,
    node: str,
    vmid: int,
    action: VMAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """VM 전원 제어 (시작/중지/재시작) — 소유자 또는 관리자만 가능"""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    node = vm_record.server.name
    proxmox = get_proxmox_for_server(vm_record.server)

    try:
        node_qemu = proxmox.nodes(node).qemu(vmid).status
        if action.action == "start":
            result = node_qemu.start.post()
        elif action.action == "stop":
            result = node_qemu.stop.post()
        elif action.action == "shutdown":
            result = node_qemu.shutdown.post()
        elif action.action == "reboot":
            result = node_qemu.reboot.post()
        else:
            raise HTTPException(status_code=400, detail="유효하지 않은 액션입니다.")
        return {"success": True, "result": result, "action": action.action}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[vm] 전원 제어 실패: {e}")
        raise HTTPException(status_code=500, detail="서버 오류가 발생했습니다.")


@router.post("/create", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def create_vm_endpoint(
    request: Request,
    vm_config: VMCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """새로운 VM 생성 (Auto-Provisioning 적용)"""
    return create_vm(
        db=db,
        current_user=current_user,
        tier=vm_config.tier,
        os=vm_config.os,
        node_name=vm_config.node_name,
        name=vm_config.name,
        custom_cores=vm_config.custom_cores,
        custom_memory=vm_config.custom_memory,
        custom_disk=vm_config.custom_disk,
    )


# ── 스냅샷 관리 ─────────────────────────────────────────────


@router.get("/{node}/vms/{vmid}/snapshots")
def list_snapshots(
    node: str,
    vmid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """VM 스냅샷 목록 조회"""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    node = vm_record.server.name
    proxmox = get_proxmox_for_server(vm_record.server)
    try:
        snapshots = proxmox.nodes(node).qemu(vmid).snapshot.get()
        # 'current' 항목(현재 상태)은 제외
        return [s for s in snapshots if s.get("name") != "current"]
    except Exception as e:
        logger.error(f"[vm] 스냅샷 목록 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="서버 오류가 발생했습니다.")


@router.post("/{node}/vms/{vmid}/snapshots")
def create_snapshot(
    node: str,
    vmid: int,
    body: SnapshotCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """VM 스냅샷 생성 (최대 3개)"""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    node = vm_record.server.name
    proxmox = get_proxmox_for_server(vm_record.server)

    snap_name = body.name

    try:
        existing = proxmox.nodes(node).qemu(vmid).snapshot.get()
        real_snaps = [s for s in existing if s.get("name") != "current"]
        manual_snaps = [s for s in real_snaps if not s.get("name", "").startswith("auto-daily")]
        if manual_snaps and len(manual_snaps) >= 2:
            raise HTTPException(status_code=400, detail="수동 스냅샷은 최대 2개까지 생성할 수 있습니다.")
        if len(real_snaps) >= 3:
            raise HTTPException(status_code=400, detail="스냅샷은 최대 3개까지 생성할 수 있습니다.")

        result = proxmox.nodes(node).qemu(vmid).snapshot.post(
            snapname=snap_name,
            description=body.description or "",
            vmstate=0,  # RAM 상태 저장 안 함 (디스크만)
        )
        return {"success": True, "message": f"스냅샷 '{snap_name}'이(가) 생성되었습니다.", "task": result}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[vm] 스냅샷 생성 실패: {e}")
        raise HTTPException(status_code=500, detail="스냅샷 생성에 실패했습니다.")


@router.post("/{node}/vms/{vmid}/snapshots/{snapname}/rollback")
def rollback_snapshot(
    node: str,
    vmid: int,
    snapname: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """VM을 특정 스냅샷 시점으로 복원"""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    node = vm_record.server.name
    proxmox = get_proxmox_for_server(vm_record.server)
    try:
        result = proxmox.nodes(node).qemu(vmid).snapshot(snapname).rollback.post()
        return {"success": True, "message": f"스냅샷 '{snapname}'으로 복원되었습니다.", "task": result}
    except Exception as e:
        logger.error(f"[vm] 스냅샷 복원 실패: {e}")
        raise HTTPException(status_code=500, detail="스냅샷 복원에 실패했습니다.")


@router.delete("/{node}/vms/{vmid}/snapshots/{snapname}")
def delete_snapshot(
    node: str,
    vmid: int,
    snapname: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """VM 스냅샷 삭제"""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    node = vm_record.server.name
    proxmox = get_proxmox_for_server(vm_record.server)
    try:
        result = proxmox.nodes(node).qemu(vmid).snapshot(snapname).delete()
        return {"success": True, "message": f"스냅샷 '{snapname}'이(가) 삭제되었습니다.", "task": result}
    except Exception as e:
        logger.error(f"[vm] 스냅샷 삭제 실패: {e}")
        raise HTTPException(status_code=500, detail="스냅샷 삭제에 실패했습니다.")


@router.get("/{node}/vms/{vmid}/auto-snapshot")
def get_auto_snapshot(
    node: str,
    vmid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """자동 스냅샷 설정 조회"""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    return {"enabled": bool(vm_record.auto_snapshot)}


@router.put("/{node}/vms/{vmid}/auto-snapshot")
def toggle_auto_snapshot(
    node: str,
    vmid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """자동 스냅샷 ON/OFF 토글"""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    vm_record.auto_snapshot = not vm_record.auto_snapshot
    db.commit()
    return {"enabled": bool(vm_record.auto_snapshot)}


@router.delete("/{node}/vms/{vmid}")
@limiter.limit("5/minute")
def delete_vm_endpoint(
    request: Request,
    node: str,
    vmid: int,
    purge: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """VM 삭제 — 소유자 또는 관리자만 가능"""
    vm_record = get_vm_with_owner_check(db, vmid, current_user, node)
    return delete_vm(db=db, vm_record=vm_record, purge=purge)
