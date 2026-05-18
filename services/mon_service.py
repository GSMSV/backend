from sqlalchemy.orm import Session
from models.server import Server
from services.proxmox_client import get_proxmox_for_server
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)

def update_server_stats(db: Session, server: Server):
    """
    특정 서버(Proxmox Node)에 비동기로 접속하여 잔여 RAM 용량을 조회하고 DB를 업데이트합니다.
    """
    try:
        # 실제 API 호출
        proxmox = get_proxmox_for_server(server)
        # 노드 상태 정보 가져오기 (이름 매칭 필요)
        # Proxmox 클러스터 내의 노드 이름은 보통 server.name 과 일치해야 합니다.
        node_status = proxmox.nodes(server.name).status.get()
        
        # 전체 RAM - 사용 중인 RAM = 여유 RAM (바이트 -> MB 변환)
        total_memory = node_status.get('memory', {}).get('total', 0)
        used_memory = node_status.get('memory', {}).get('used', 0)
        free_ram_mb = (total_memory - used_memory) // (1024 * 1024)
        
        # DB 업데이트
        server.last_free_ram_mb = free_ram_mb
        db.commit()
        return free_ram_mb
    except Exception as e:
        logger.error(f"서버 {server.name} 상태 업데이트 실패: {e}")
        return 0

def get_best_server(db: Session, required_ram_mb: int) -> Server:
    """
    요구되는 RAM(MB)를 감당할 수 있으면서, 가장 여유 자원이 많은 서버를 찾습니다.
    (Resource-Based Auto Provisioning)
    """
    # 1. 활성화된 모든 서버 목록 가져오기
    active_servers = db.query(Server).filter(Server.is_active == True).all()
    
    if not active_servers:
        raise HTTPException(status_code=500, detail="사용 가능한 활성 서버가 없습니다.")
    
    # 2. (옵션) 실시간에 가깝게 하기 위해 할당 전 모든 서버의 RAM 상태를 1회 갱신 (트래픽이 적을 때 유효)
    # 트래픽이 많다면 이 부분은 백그라운드 스케줄러(ex: Celery, APScheduler)로 빼는 것이 좋습니다.
    for server in active_servers:
        update_server_stats(db, server)
        
    # 3. 요구사항을 충족(required_ram_mb 이상 여유)하는 서버들만 필터링
    capable_servers = [s for s in active_servers if s.last_free_ram_mb >= required_ram_mb]
    
    if not capable_servers:
        raise HTTPException(
            status_code=507, 
            detail=f"요청한 RAM({required_ram_mb}MB)을 할당할 여유 자원을 가진 서버가 없습니다."
        )
    
    # 4. 여유 RAM이 가장 많은 서버(가장 한가한 녀석) 선택 후 반환
    # (Python 내장 함수 max를 활용하여 last_free_ram_mb 기준으로 정렬)
    best_server = max(capable_servers, key=lambda s: s.last_free_ram_mb)
    
    return best_server
