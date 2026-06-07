import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from services.proxmox_client import get_proxmox_for_server, gather_per_server
from core.database import get_db
from models.server import Server
from models.user import User, UserRole
from models.vm import Vm
from api.dependencies import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()


def _fetch_node_stats(server):
    """단일 노드 상태 조회 (스레드풀에서 서버별 병렬 실행)."""
    proxmox = get_proxmox_for_server(server)
    node_status = proxmox.nodes(server.name).status.get()

    cpu_usage = node_status.get("cpu", 0) * 100  # 소수점(0.05)을 백분율(5%)로
    memory = node_status.get("memory", {})
    total_ram_gb = memory.get("total", 0) / (1024**3)
    used_ram_gb = memory.get("used", 0) / (1024**3)
    free_ram_gb = total_ram_gb - used_ram_gb

    return {
        "status": "online",
        "cpu_usage_percent": round(cpu_usage, 1),
        "ram_total_gb": round(total_ram_gb, 1),
        "ram_used_gb": round(used_ram_gb, 1),
        "ram_free_gb": round(free_ram_gb, 1),
        "uptime_seconds": node_status.get("uptime", 0),
    }


@router.get("/nodes")
def get_system_stats(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """
    활성 서버(Node)의 리소스 취합 조회.
    ADMIN/PROJECT_OWNER: 전체 노드 조회 / USER: 본인 VM이 위치한 노드만 조회
    """
    query = db.query(Server).filter(Server.is_active == True)
    if current_user.role not in (UserRole.ADMIN, UserRole.PROJECT_OWNER):
        user_server_ids = (
            db.query(Vm.server_id)
            .filter(Vm.owner_id == current_user.id)
            .distinct()
            .scalar_subquery()
        )
        query = query.filter(Server.id.in_(user_server_ids))
    servers = query.all()
    if not servers:
        return {"message": "등록된 활성 서버가 없습니다.", "stats": {}}

    # 노드별 상태를 동시에 조회 (서버마다 독립 Proxmox 연결 → 스레드 안전)
    stats_by_id = gather_per_server(servers, _fetch_node_stats)

    all_stats = {}
    for server in servers:
        result = stats_by_id.get(server.id)
        if result is not None:
            all_stats[server.name] = result
        else:
            all_stats[server.name] = {
                "status": "offline",
                "error": "노드에 연결할 수 없습니다.",
            }

    return {"stats": all_stats}
