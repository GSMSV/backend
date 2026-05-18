import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from services.proxmox_client import get_proxmox_for_server
from core.database import get_db
from models.server import Server
from models.user import User, UserRole
from models.vm import Vm
from api.dependencies import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/nodes")
async def get_system_stats(
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

    all_stats = {}

    for server in servers:
        try:
            proxmox = get_proxmox_for_server(server)

            # 각 노드의 상태 조회
            node_status = proxmox.nodes(server.name).status.get()

            # 데이터 가공
            cpu_usage = node_status.get("cpu", 0) * 100  # 소수점(0.05)을 백분율(5%)로

            memory = node_status.get("memory", {})
            total_ram_gb = memory.get("total", 0) / (1024**3)
            used_ram_gb = memory.get("used", 0) / (1024**3)
            free_ram_gb = total_ram_gb - used_ram_gb

            all_stats[server.name] = {
                "status": "online",
                "cpu_usage_percent": round(cpu_usage, 1),
                "ram_total_gb": round(total_ram_gb, 1),
                "ram_used_gb": round(used_ram_gb, 1),
                "ram_free_gb": round(free_ram_gb, 1),
                "uptime_seconds": node_status.get("uptime", 0),
            }
        except Exception as e:
            logger.error(f"[monitoring] 노드 {server.name} 조회 실패: {e}")
            all_stats[server.name] = {
                "status": "offline",
                "error": "노드에 연결할 수 없습니다.",
            }

    return {"stats": all_stats}
