import logging
import threading
import time
import requests
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# 서버별 Proxmox 연결 캐시 (TTL 5분)
_proxmox_cache: dict[int, tuple[object, float]] = {}  # server_id → (proxmox, expires_at)
_cache_lock = threading.Lock()
_CACHE_TTL = 300  # 5분


def proxmox_http_exception(
    exc: Exception,
    *,
    default_detail: str = "서버 오류가 발생했습니다.",
) -> HTTPException:
    """Proxmox 관련 예외를 클라이언트가 구분 가능한 HTTPException으로 변환."""
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, (TimeoutError, requests.exceptions.Timeout)):
        return HTTPException(
            status_code=503,
            detail="Proxmox API 응답 시간이 초과되었습니다. 잠시 후 다시 시도해주세요.",
        )
    if isinstance(exc, requests.exceptions.ConnectionError):
        return HTTPException(
            status_code=503,
            detail="Proxmox API에 연결할 수 없습니다. 잠시 후 다시 시도해주세요.",
        )
    if isinstance(exc, ResourceException):
        content = f"{exc.content} {exc.errors or ''}".lower()
        if exc.status_code in (401, 403):
            return HTTPException(status_code=401, detail="Proxmox 인증에 실패했습니다.")
        if exc.status_code == 404:
            return HTTPException(status_code=404, detail="Proxmox 리소스를 찾을 수 없습니다.")
        if exc.status_code == 409:
            return HTTPException(status_code=409, detail="Proxmox 리소스 상태가 충돌합니다.")
        if exc.status_code == 507 or any(
            marker in content
            for marker in ("insufficient", "not enough", "no space", "resource")
        ):
            return HTTPException(status_code=507, detail="Proxmox 리소스가 부족합니다.")
        if exc.status_code >= 500:
            return HTTPException(status_code=502, detail="Proxmox API 처리 중 오류가 발생했습니다.")
    return HTTPException(status_code=500, detail=default_detail)


def raise_proxmox_http_exception(
    exc: Exception,
    *,
    default_detail: str = "서버 오류가 발생했습니다.",
) -> None:
    raise proxmox_http_exception(exc, default_detail=default_detail)


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
        raise proxmox_http_exception(
            e,
            default_detail="서버에 연결할 수 없습니다. 잠시 후 다시 시도해주세요.",
        )
