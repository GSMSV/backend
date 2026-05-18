import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from api.dependencies import get_current_user
from models.user import User
from core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()
_http_client = httpx.AsyncClient(timeout=httpx.Timeout(65.0))


async def _proxy(request: Request, path: str, current_user: User) -> Response:
    body = await request.body()
    headers = {
        "Content-Type": request.headers.get("Content-Type", "application/json"),
        "X-User-Id": str(current_user.id),
        "X-User-Role": current_user.role.value,
    }
    if path:
        url = f"{settings.SERVERLESS_SERVICE_URL}/functions/{path}"
    else:
        url = f"{settings.SERVERLESS_SERVICE_URL}/functions"

    try:
        upstream = await _http_client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
            params=dict(request.query_params),
        )
    except (httpx.ConnectError, httpx.TimeoutException):
        logger.exception("serverless upstream unreachable: %s", url)
        raise HTTPException(status_code=502, detail="Serverless service unavailable")
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("Content-Type", "application/json"),
    )


@router.api_route("", methods=["GET", "POST"])
async def functions_root(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    return await _proxy(request, "", current_user)


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def functions_proxy(
    path: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    return await _proxy(request, path, current_user)
