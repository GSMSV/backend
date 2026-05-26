import logging
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from schemas.fw_schema import FirewallRule, VmPortCreate
from services.proxmox_client import get_proxmox_for_server, raise_proxmox_http_exception
from services.network_service import allocate_random_port, manage_custom_iptables, calculate_ports
from core.database import get_db
from models.user import User
from models.vm_port import VmPort
from api.dependencies import get_current_user, get_vm_with_owner_check

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/{node}/{vmid}/rules")
async def get_firewall_rules(
    node: str,
    vmid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """특정 VM의 방화벽 규칙 목록 조회 (소유자 또는 관리자)"""
    vm = get_vm_with_owner_check(db, vmid, current_user, node=node)
    server = vm.server
    proxmox = get_proxmox_for_server(server)

    try:
        rules = proxmox.nodes(server.name).qemu(vmid).firewall.rules.get()
        return {"vmid": vmid, "node": server.name, "rules": rules}
    except Exception as e:
        logger.error(f"[firewall] 규칙 조회 실패: {e}")
        raise_proxmox_http_exception(e, default_detail="방화벽 규칙 조회에 실패했습니다.")


@router.post("/{node}/{vmid}/rules", status_code=status.HTTP_201_CREATED)
async def add_firewall_rule(
    node: str,
    vmid: int,
    rule: FirewallRule,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """특정 VM에 방화벽 규칙 추가 (소유자 또는 관리자)"""
    vm = get_vm_with_owner_check(db, vmid, current_user, node=node)
    server = vm.server
    proxmox = get_proxmox_for_server(server)

    try:
        rule_data = rule.model_dump(exclude_none=True)
        if vm.internal_ip:
            rule_data["dest"] = vm.internal_ip
        proxmox.nodes(server.name).qemu(vmid).firewall.rules.post(**rule_data)
        proxmox.nodes(server.name).qemu(vmid).firewall.options.put(enable=1)
        return {"success": True, "message": f"VM {vmid} 방화벽 규칙 추가 완료", "rule": rule_data}
    except Exception as e:
        logger.error(f"[firewall] 규칙 추가 실패: {e}")
        raise_proxmox_http_exception(e, default_detail="방화벽 규칙 추가에 실패했습니다.")


@router.delete("/{node}/{vmid}/rules/{pos}", status_code=status.HTTP_200_OK)
async def delete_firewall_rule(
    node: str,
    vmid: int,
    pos: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """특정 VM의 방화벽 규칙 삭제 (소유자 또는 관리자)"""
    vm = get_vm_with_owner_check(db, vmid, current_user, node=node)
    server = vm.server
    proxmox = get_proxmox_for_server(server)

    try:
        proxmox.nodes(server.name).qemu(vmid).firewall.rules(pos).delete()
        return {"success": True, "message": f"VM {vmid} 방화벽 규칙({pos}번) 삭제 완료"}
    except Exception as e:
        logger.error(f"[firewall] 규칙 삭제 실패: {e}")
        raise_proxmox_http_exception(e, default_detail="방화벽 규칙 삭제에 실패했습니다.")


# ── 커스텀 포트 할당 (30000~39999) ───────────────────────────────────────────

@router.get("/{node}/{vmid}/ports")
async def get_custom_ports(
    node: str,
    vmid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """커스텀 포트 목록 조회 (DB)"""
    vm = get_vm_with_owner_check(db, vmid, current_user, node=node)

    ports = db.query(VmPort).filter(VmPort.vm_id == vm.id).all()
    return {
        "vmid": vmid,
        "ports": [
            {
                "id": p.id,
                "internal_port": p.internal_port,
                "external_port": p.external_port,
                "protocol": p.protocol,
                "action": p.action,
                "source": p.source,
                "description": p.description,
                "is_default": p.is_default,
            }
            for p in ports
        ],
    }


@router.post("/{node}/{vmid}/ports", status_code=201)
async def add_custom_port(
    node: str,
    vmid: int,
    body: VmPortCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """커스텀 포트 추가 — 30000~39999 랜덤 외부 포트 할당 + iptables + Proxmox 방화벽 규칙"""
    vm = get_vm_with_owner_check(db, vmid, current_user, node=node)
    server = vm.server

    custom_count = db.query(VmPort).filter(VmPort.vm_id == vm.id, VmPort.is_default.is_(False)).count()
    if custom_count >= 30:
        raise HTTPException(status_code=409, detail="VM당 커스텀 포트는 최대 30개까지 추가할 수 있습니다.")

    try:
        external_port = allocate_random_port(db)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # DB 먼저 저장 — 포트 선점으로 동시 요청 레이스 컨디션 방지
    vm_port = VmPort(
        vm_id=vm.id,
        internal_port=body.internal_port,
        external_port=external_port,
        protocol=body.protocol,
        action="ACCEPT",
        source=body.source,
        description=body.description,
    )
    db.add(vm_port)
    try:
        db.commit()
        db.refresh(vm_port)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="포트 할당 충돌이 발생했습니다. 다시 시도해 주세요.")
    except Exception as e:
        db.rollback()
        logger.error(f"[firewall] DB 저장 실패: {e}")
        raise HTTPException(status_code=500, detail="포트 저장에 실패했습니다.")

    # iptables DNAT 추가 — 실패 시 DB 레코드 삭제
    if vm.internal_ip:
        success = manage_custom_iptables(
            server=server,
            vm_ip=vm.internal_ip,
            internal_port=body.internal_port,
            external_port=external_port,
            protocol=body.protocol,
            action="ADD",
            source_ip=body.source,
        )
        if not success:
            db.delete(vm_port)
            db.commit()
            raise HTTPException(status_code=502, detail="Gateway 방화벽 규칙 설정에 실패했습니다.")

    return {
        "id": vm_port.id,
        "internal_port": vm_port.internal_port,
        "external_port": vm_port.external_port,
        "protocol": vm_port.protocol,
        "description": vm_port.description,
    }


@router.post("/{node}/{vmid}/ports/defaults/restore")
async def restore_default_ports(
    node: str,
    vmid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """삭제된 기본 포트(SSH/HTTP/SVC) 복원"""
    vm = get_vm_with_owner_check(db, vmid, current_user, node=node)
    server = vm.server

    _DEFAULT_PORTS = [
        (22,    "tcp",     "SSH",  "ssh"),
        (80,    "tcp",     "HTTP", "svc1"),
        (10000, "tcp/udp", "SVC",  "svc2"),
    ]
    existing = {
        p.internal_port
        for p in db.query(VmPort).filter(VmPort.vm_id == vm.id, VmPort.is_default.is_(True)).all()
    }
    missing = [(ip, proto, desc, key) for ip, proto, desc, key in _DEFAULT_PORTS if ip not in existing]

    if not missing:
        return {"restored": 0}

    default_port_map = calculate_ports(server.base_port, vmid)
    for internal_port, protocol, description, port_key in missing:
        external_port = default_port_map[port_key]
        db.add(VmPort(
            vm_id=vm.id,
            internal_port=internal_port,
            external_port=external_port,
            protocol=protocol,
            action="ACCEPT",
            source="0.0.0.0/0",
            description=description,
            is_default=True,
        ))
        if vm.internal_ip:
            for proto in (["tcp", "udp"] if protocol == "tcp/udp" else [protocol]):
                success = manage_custom_iptables(
                    server=server,
                    vm_ip=vm.internal_ip,
                    internal_port=internal_port,
                    external_port=external_port,
                    protocol=proto,
                    action="ADD",
                )
                if not success:
                    logger.error(f"[firewall] 기본 포트 복원 iptables 실패 — {description} ({proto}), DB 저장은 계속 진행")
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"[firewall] 기본 포트 복원 실패: {e}")
        raise HTTPException(status_code=500, detail="기본 포트 복원에 실패했습니다.")

    return {"restored": len(missing)}


@router.delete("/{node}/{vmid}/ports/{port_id}", status_code=status.HTTP_200_OK)
async def delete_custom_port(
    node: str,
    vmid: int,
    port_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """커스텀 포트 삭제 — iptables 제거 + DB 삭제"""
    vm = get_vm_with_owner_check(db, vmid, current_user, node=node)
    server = vm.server

    vm_port = db.query(VmPort).filter(VmPort.id == port_id, VmPort.vm_id == vm.id).first()
    if not vm_port:
        raise HTTPException(status_code=404, detail="포트를 찾을 수 없습니다.")

    # iptables 규칙 삭제 ("tcp/udp" 프로토콜은 두 번 호출)
    # 실패해도 DB 레코드는 삭제 — 삭제 실패 시 영구적으로 못 지우는 것이 더 위험
    if vm.internal_ip:
        # ADD 시 source_ip와 동일한 값으로 DELETE — "0.0.0.0/0"은 플래그 없이 추가된 것이므로 None 처리
        source_ip = vm_port.source if vm_port.source and vm_port.source != "0.0.0.0/0" else None
        protocols = ["tcp", "udp"] if vm_port.protocol == "tcp/udp" else [vm_port.protocol]
        for proto in protocols:
            success = manage_custom_iptables(
                server=server,
                vm_ip=vm.internal_ip,
                internal_port=vm_port.internal_port,
                external_port=vm_port.external_port,
                protocol=proto,
                action="DELETE",
                source_ip=source_ip,
            )
            if not success:
                logger.error(f"[firewall] Gateway iptables 삭제 실패 — port {vm_port.external_port} ({proto}), DB 레코드는 삭제 진행")

    external_port = vm_port.external_port
    internal_port = vm_port.internal_port
    db.delete(vm_port)
    db.commit()
    return {"success": True, "message": f"포트 {external_port}→{internal_port} 삭제 완료"}
