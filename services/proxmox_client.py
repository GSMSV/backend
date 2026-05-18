import logging
import threading
import time
from proxmoxer import ProxmoxAPI
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# 서버별 Proxmox 연결 캐시 (TTL 5분)
_proxmox_cache: dict[int, tuple[object, float]] = {}  # server_id → (proxmox, expires_at)
_cache_lock = threading.Lock()
_CACHE_TTL = 300  # 5분


def get_proxmox_for_server(server):
    """
    서버(Server) 모델 기반으로 Proxmox에 연결합니다.
    서버별 연결을 캐싱하여 불필요한 재연결을 방지합니다 (TTL 5분).
    """
    now = time.time()

    with _cache_lock:
        cached = _proxmox_cache.get(server.id)
        if cached and cached[1] > now:
            return cached[0]

    try:
        proxmox = ProxmoxAPI(
            server.ip_address,
            user=server.api_user,
            password=server.api_password,
            port=str(server.port),
            verify_ssl=False,
            timeout=180,
        )
        with _cache_lock:
            _proxmox_cache[server.id] = (proxmox, now + _CACHE_TTL)
        return proxmox
    except Exception as e:
        logger.error(f"Proxmox 연결 실패 ({server.name}): {e}")
        raise HTTPException(
            status_code=500,
            detail="서버에 연결할 수 없습니다. 잠시 후 다시 시도해주세요."
        )
