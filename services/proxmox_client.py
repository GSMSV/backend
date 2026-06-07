import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from proxmoxer import ProxmoxAPI
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# 서버별 Proxmox 연결 캐시 (TTL 5분)
_proxmox_cache: dict[int, tuple[object, float]] = {}  # server_id → (proxmox, expires_at)
_cache_lock = threading.Lock()
_CACHE_TTL = 300  # 5분

# 여러 노드(서버)의 Proxmox 상태를 동시에 조회하기 위한 공용 스레드풀.
# 각 서버는 서로 다른 Proxmox 연결(requests.Session)을 쓰므로 "서버 단위" 병렬은 안전하다.
# (동일 서버 내 호출은 세션을 공유하므로 각 작업 함수 내부에서는 순차 처리한다.)
_node_executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="pmox-node")


def gather_per_server(servers, fn):
    """servers 각각에 대해 fn(server)를 스레드풀에서 병렬 실행한다.

    반환: {server.id: 결과}. fn 이 예외를 던지면 해당 server.id 는 결과에서
    제외된다(호출부에서 누락을 offline 등으로 처리).

    주의: fn 내부에서는 이미 로드된 ORM 컬럼만 읽어야 한다(지연 로딩/refresh 금지).
    SQLAlchemy Session 은 스레드 안전하지 않으므로 관계 접근은 호출 전에 끝낸다.
    """
    if not servers:
        return {}
    results: dict[int, object] = {}
    future_map = {_node_executor.submit(fn, s): s for s in servers}
    for future, server in future_map.items():
        try:
            results[server.id] = future.result()
        except Exception as e:
            logger.warning(f"[proxmox] 노드 병렬 조회 실패 (server_id={server.id}): {e}")
    return results


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
