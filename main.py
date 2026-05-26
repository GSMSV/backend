import asyncio
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from core.timezone import now_kst
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from api.routes import (
    vmcontrol,
    firewall,
    auth,
    monitoring,
    network,
    notifications,
    oauth,
    faq,
    serverless,
)
from api.routes.oauth import validate_oauth_store_mode
from core.constants import AUTO_SNAP_PREFIX
from core.config import settings
from sqlalchemy.orm import joinedload
from core.database import Base, engine, SessionLocal
from core.init_servers import sync_servers
from models.vm import Vm
from models.notification import Notification
from models.user import User, UserRole
from models.faq_question import FaqQuestion  # noqa: F401 — create_all 자동 반영
from models.vm_port import VmPort  # noqa: F401 — create_all 자동 반영


import logging

logger = logging.getLogger(__name__)

BACKGROUND_FAILURE_NOTIFY_THRESHOLD = 5
BACKGROUND_FAST_RETRY_SECONDS = 300
EXPIRE_LOOP_INTERVAL_SECONDS = 3600
IPTABLES_BACKUP_INTERVAL_SECONDS = 7 * 24 * 3600
SNAPSHOT_CREATE_DELAY_SECONDS = 60


def _notify_admins_background_failure(task_name: str, consecutive_failures: int):
    db = None
    try:
        db = SessionLocal()
        admins = (
            db.query(User)
            .filter(User.role == UserRole.ADMIN, User.is_active == True)
            .all()
        )
        for admin in admins:
            db.add(
                Notification(
                    user_id=admin.id,
                    type="error",
                    message=f"[{task_name}] 백그라운드 태스크 연속 {consecutive_failures}회 실패 — 점검이 필요합니다.",
                )
            )
        db.commit()
    except Exception as notify_err:
        if db:
            db.rollback()
        logger.warning(
            f"[{task_name}] 관리자 알림 생성 실패: {notify_err}",
            exc_info=True,
        )
    finally:
        if db:
            db.close()


# Rate Limiter
limiter = Limiter(key_func=get_remote_address)


async def _expire_vms_loop():
    """만료된 VM 삭제 + 만료 임박 알림 + 오래된 알림 정리 (1시간 간격)"""
    from services.vm_service import delete_vm
    from datetime import timedelta

    consecutive_failures = 0
    while True:
        db = None
        try:
            db = SessionLocal()
            now = now_kst()

            # 1. 만료된 VM 삭제
            expired_vms = (
                db.query(Vm)
                .filter(
                    Vm.expires_at.isnot(None),
                    Vm.expires_at <= now,
                )
                .all()
            )

            for vm in expired_vms:
                try:
                    logger.info(
                        f"[expire] 만료 VM 삭제: {vm.name} (VMID {vm.hypervisor_vmid})"
                    )
                    # 만료 삭제 알림 생성
                    if vm.owner_id:
                        db.add(
                            Notification(
                                user_id=vm.owner_id,
                                type="error",
                                message=f"VM '{vm.name}'이(가) 만료되어 자동 삭제되었습니다.",
                            )
                        )
                        db.commit()
                    delete_vm(db, vm, purge=True)
                except Exception as e:
                    logger.error(f"[expire] VM {vm.hypervisor_vmid} 삭제 실패: {e}")

            # 2. 만료 임박(15일 이내) VM 알림 (하루 1회)
            soon_vms = (
                db.query(Vm)
                .filter(
                    Vm.expires_at.isnot(None),
                    Vm.expires_at > now,
                    Vm.expires_at <= now + timedelta(days=15),
                )
                .all()
            )

            for vm in soon_vms:
                if not vm.owner_id:
                    continue
                days_left = (vm.expires_at - now).days
                # 이미 오늘 같은 알림이 있는지 확인
                today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
                existing = (
                    db.query(Notification)
                    .filter(
                        Notification.user_id == vm.owner_id,
                        Notification.message.contains(vm.name),
                        Notification.message.contains("만료까지"),
                        Notification.created_at >= today_start,
                    )
                    .first()
                )
                if not existing:
                    db.add(
                        Notification(
                            user_id=vm.owner_id,
                            type="error",
                            message=f"VM '{vm.name}': 만료까지 {days_left}일 남았습니다. 연장해주세요.",
                        )
                    )
            db.commit()

            # 3. 15일 지난 알림 자동 삭제
            cutoff = now - timedelta(days=15)
            db.query(Notification).filter(
                Notification.created_at < cutoff,
            ).delete()
            db.commit()
            consecutive_failures = 0
        except Exception as e:
            if db:
                db.rollback()
            consecutive_failures += 1
            logger.exception(
                f"[expire] 백그라운드 태스크 오류 ({consecutive_failures}회 연속): {e}"
            )
            if consecutive_failures >= BACKGROUND_FAILURE_NOTIFY_THRESHOLD:
                logger.critical(
                    f"[expire] 백그라운드 태스크 연속 {consecutive_failures}회 실패 — 점검 필요"
                )
            if consecutive_failures == BACKGROUND_FAILURE_NOTIFY_THRESHOLD:
                try:
                    await asyncio.to_thread(
                        _notify_admins_background_failure,
                        "expire",
                        consecutive_failures,
                    )
                except Exception as notify_err:
                    logger.exception(f"[expire] 관리자 알림 발송 실패: {notify_err}")
        finally:
            if db:
                db.close()

        if consecutive_failures > 0:
            await asyncio.sleep(BACKGROUND_FAST_RETRY_SECONDS)
        else:
            await asyncio.sleep(EXPIRE_LOOP_INTERVAL_SECONDS)


async def _iptables_weekly_backup_loop():
    """매주 1회 Gateway iptables 규칙을 백업합니다."""
    import paramiko
    from models.server import Server
    from services.network_service import _backup_iptables

    consecutive_failures = 0
    while True:
        db = None
        try:
            db = SessionLocal()
            servers = db.query(Server).all()

            seen_gateways = set()
            for server in servers:
                if not server.gateway_ip or server.gateway_ip in seen_gateways:
                    continue
                seen_gateways.add(server.gateway_ip)

                ssh = None
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
                    ssh.connect(
                        hostname=server.gateway_ip,
                        username=server.gateway_user,
                        password=server.gateway_password or "",
                        timeout=10,
                    )
                    _backup_iptables(ssh, server.gateway_ip)
                except Exception as e:
                    logger.warning(
                        f"[weekly-backup] {server.gateway_ip} 백업 실패: {e}",
                        exc_info=True,
                    )
                finally:
                    if ssh:
                        ssh.close()
            consecutive_failures = 0
        except Exception as e:
            if db:
                db.rollback()
            consecutive_failures += 1
            logger.exception(
                f"[weekly-backup] 백그라운드 태스크 오류 ({consecutive_failures}회 연속): {e}"
            )
            if consecutive_failures >= BACKGROUND_FAILURE_NOTIFY_THRESHOLD:
                logger.critical(
                    f"[weekly-backup] 백그라운드 태스크 연속 {consecutive_failures}회 실패 — 점검 필요"
                )
            if consecutive_failures == BACKGROUND_FAILURE_NOTIFY_THRESHOLD:
                try:
                    await asyncio.to_thread(
                        _notify_admins_background_failure,
                        "weekly-backup",
                        consecutive_failures,
                    )
                except Exception as notify_err:
                    logger.exception(
                        f"[weekly-backup] 관리자 알림 발송 실패: {notify_err}"
                    )
        finally:
            if db:
                db.close()

        if consecutive_failures > 0:
            await asyncio.sleep(BACKGROUND_FAST_RETRY_SECONDS)
        else:
            await asyncio.sleep(IPTABLES_BACKUP_INTERVAL_SECONDS)


async def _wait_snap_delete(
    proxmox, node_name: str, upid: str, timeout: int = 120
) -> None:
    """스냅샷 삭제 UPID 완료를 비동기로 대기합니다."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            task = await asyncio.to_thread(
                proxmox.nodes(node_name).tasks(upid).status.get
            )
            if task.get("status") == "stopped":
                if task.get("exitstatus") != "OK":
                    logger.warning(
                        f"[auto-snap] 삭제 태스크 비정상 종료: {upid} exitstatus={task.get('exitstatus')}"
                    )
                return
        except Exception as e:
            logger.debug(f"[auto-snap] UPID {upid} 상태 조회 실패: {e}")
        await asyncio.sleep(2)
    logger.warning(
        f"[auto-snap] 삭제 UPID {upid} 타임아웃 ({timeout}초) — 생성 단계에서 충돌 가능"
    )


async def _daily_snapshot_loop():
    """
    매일 자동 스냅샷 (auto_snapshot=True인 VM만)
    - 00:00 → 기존 auto-daily 스냅샷 삭제 (UPID 완료를 gather로 병렬 대기)
    - 00:01 → 새 auto-daily 스냅샷 생성 (target_vms 재조회)
    """
    from services.proxmox_client import get_proxmox_for_server

    consecutive_failures = 0
    while True:
        db = None
        try:
            # 실패 재시도 시 자정 대기 스킵 — 의도된 fast retry
            if consecutive_failures == 0:
                now = now_kst()
                tomorrow = (now + timedelta(days=1)).replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
                wait_seconds = (tomorrow - now).total_seconds()
                await asyncio.sleep(wait_seconds)

            # ── 00:00 — 기존 auto-daily 스냅샷 삭제 ──
            logger.info("[auto-snap] 기존 자동 스냅샷 삭제 시작")
            db = SessionLocal()
            try:
                vms = (
                    db.query(Vm)
                    .options(joinedload(Vm.server))
                    .filter(Vm.auto_snapshot == True)
                    .all()
                )
                delete_targets = [
                    (vm.name, vm.hypervisor_vmid, vm.server) for vm in vms
                ]
                db.expunge_all()
            finally:
                db.close()
                db = None

            wait_tasks = []
            for vm_name, vmid, server in delete_targets:
                try:
                    proxmox = get_proxmox_for_server(server)
                    snapshots = proxmox.nodes(server.name).qemu(vmid).snapshot.get()
                    for snap in snapshots:
                        if snap.get("name", "").startswith(AUTO_SNAP_PREFIX):
                            upid = (
                                proxmox.nodes(server.name)
                                .qemu(vmid)
                                .snapshot(snap["name"])
                                .delete()
                            )
                            logger.info(
                                f"[auto-snap] 삭제 요청: {vm_name} / {snap['name']}"
                            )
                            if isinstance(upid, str):
                                wait_tasks.append(
                                    _wait_snap_delete(proxmox, server.name, upid)
                                )
                except Exception as e:
                    logger.warning(f"[auto-snap] 삭제 실패 ({vm_name}): {e}")

            if wait_tasks:
                await asyncio.gather(*wait_tasks, return_exceptions=True)

            # ── 00:01 — 새 스냅샷 생성 ──
            await asyncio.sleep(SNAPSHOT_CREATE_DELAY_SECONDS)

            today_str = now_kst().strftime("%Y%m%d")
            snap_name = f"{AUTO_SNAP_PREFIX}-{today_str}"
            logger.info(f"[auto-snap] 자동 스냅샷 생성 시작: {snap_name}")

            # 생성 직전 재조회 — sleep 사이 auto_snapshot 변경분 반영
            db = SessionLocal()
            try:
                vms = (
                    db.query(Vm)
                    .options(joinedload(Vm.server))
                    .filter(Vm.auto_snapshot == True)
                    .all()
                )
                create_targets = [
                    (vm.name, vm.hypervisor_vmid, vm.server) for vm in vms
                ]
                db.expunge_all()
            finally:
                db.close()
                db = None

            for vm_name, vmid, server in create_targets:
                try:
                    proxmox = get_proxmox_for_server(server)
                    proxmox.nodes(server.name).qemu(vmid).snapshot.post(
                        snapname=snap_name,
                        description="자동 일일 스냅샷",
                        vmstate=0,
                    )
                    logger.info(f"[auto-snap] 생성: {vm_name} / {snap_name}")
                except Exception as e:
                    logger.warning(f"[auto-snap] 생성 실패 ({vm_name}): {e}")

            consecutive_failures = 0
        except Exception as e:
            if db:
                db.rollback()
            consecutive_failures += 1
            logger.exception(
                f"[auto-snap] 백그라운드 태스크 오류 ({consecutive_failures}회 연속): {e}"
            )
            if consecutive_failures >= BACKGROUND_FAILURE_NOTIFY_THRESHOLD:
                logger.critical(
                    f"[auto-snap] 백그라운드 태스크 연속 {consecutive_failures}회 실패 — 점검 필요"
                )
            if consecutive_failures == BACKGROUND_FAILURE_NOTIFY_THRESHOLD:
                try:
                    await asyncio.to_thread(
                        _notify_admins_background_failure,
                        "auto-snap",
                        consecutive_failures,
                    )
                except Exception as notify_err:
                    logger.exception(f"[auto-snap] 관리자 알림 발송 실패: {notify_err}")
        finally:
            if db:
                db.close()

        if consecutive_failures > 0:
            await asyncio.sleep(BACKGROUND_FAST_RETRY_SECONDS)


async def _oauth_store_cleanup_loop():
    """OAuth PKCE/토큰 인메모리 스토어 주기적 정리 (메모리 누수 방지)"""
    from api.routes.oauth import _cleanup_stores

    while True:
        try:
            _cleanup_stores()
        except Exception as e:
            logger.warning(f"[oauth-cleanup] 정리 실패: {e}", exc_info=True)
        await asyncio.sleep(BACKGROUND_FAST_RETRY_SECONDS)  # 5분마다


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── 시작 시 ──
    validate_oauth_store_mode()
    Base.metadata.create_all(bind=engine)  # 테이블 자동 생성
    sync_servers()  # .env → servers 테이블 동기화

    # 등록된 라우트 목록 출력 (디버그)
    for route in app.routes:
        if hasattr(route, "methods"):
            logger.info(f"[route] {route.methods} {route.path}")

    # 만료 VM 자동 삭제 백그라운드 태스크 시작
    expire_task = asyncio.create_task(_expire_vms_loop())
    # iptables 주간 백업 태스크 시작
    iptables_task = asyncio.create_task(_iptables_weekly_backup_loop())
    # 자동 일일 스냅샷 태스크 시작
    snapshot_task = asyncio.create_task(_daily_snapshot_loop())
    # OAuth PKCE/토큰 스토어 주기적 정리 (5분 간격)
    oauth_cleanup_task = asyncio.create_task(_oauth_store_cleanup_loop())

    yield
    # ── 종료 시 ──
    expire_task.cancel()
    iptables_task.cancel()
    snapshot_task.cancel()
    oauth_cleanup_task.cancel()
    await serverless._http_client.aclose()


app = FastAPI(
    title="VM Control Platform API",
    description="A multi-server, multi-port VM management backend",
    version="1.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "요청이 너무 많습니다. 잠시 후 다시 시도해주세요."},
    )


# CORS 설정 — settings.CORS_ORIGINS에서 허용 도메인 관리
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# 모듈화된 라우터 등록
# 신규: 인증 라우터 추가
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(oauth.router, prefix=f"{settings.API_V1_STR}/oauth", tags=["oauth"])

app.include_router(
    vmcontrol.router, prefix=f"{settings.API_V1_STR}/vm", tags=["vmcontrol"]
)
app.include_router(
    network.router, prefix=f"{settings.API_V1_STR}/network", tags=["network"]
)
app.include_router(
    firewall.router, prefix=f"{settings.API_V1_STR}/firewall", tags=["firewall"]
)
app.include_router(
    monitoring.router, prefix=f"{settings.API_V1_STR}/monitoring", tags=["monitoring"]
)
app.include_router(
    notifications.router,
    prefix=f"{settings.API_V1_STR}/notifications",
    tags=["notifications"],
)
app.include_router(faq.router, prefix=f"{settings.API_V1_STR}/faq", tags=["faq"])
app.include_router(serverless.router, prefix=f"{settings.API_V1_STR}/serverless/functions", tags=["serverless"])

# 업로드 파일 서빙
os.makedirs("uploads/avatars", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")


@app.get("/")
def read_root():
    return {
        "message": "SVC Proxmox Web Console is running",
        "status": "running",
        "version": "1.0.0",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8765)
