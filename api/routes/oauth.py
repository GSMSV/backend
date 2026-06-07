"""
DataGSM OAuth 2.0 + PKCE 인증 라우트
흐름: authorize → DataGSM 로그인 → callback → 임시코드 발급 → POST /exchange → JWT 발급
"""

import hashlib
import base64
import secrets
import time
import httpx
import logging
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Depends, Request
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.config import settings
from core.database import get_db
from models.user import User, UserRole
from core.security import create_access_token, create_refresh_token

limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)
router = APIRouter()

# 임시 저장소 (프로덕션에서는 Redis 사용 권장)
_pkce_store: dict[str, tuple[str, float]] = {}  # state → (code_verifier, expires_at)
_token_store: dict[str, dict] = {}  # temp_code → {access, refresh, expires}
_STORE_TTL = 300  # 5분


def validate_oauth_store_mode():
    if settings.OAUTH_STORE_MODE == "memory" and settings.WEB_CONCURRENCY > 1:
        logger.error(
            "[OAuth] memory store is not shared across multi-workers. Set OAUTH_STORE_MODE=redis or WEB_CONCURRENCY=1."
        )
        raise RuntimeError(
            "OAuth memory store cannot be used with multi-workers. Configure redis store mode or set WEB_CONCURRENCY=1."
        )


def _cleanup_stores():
    """만료된 항목 정리"""
    now = time.time()
    expired_pkce = [
        k for k, v in _pkce_store.items() if isinstance(v, tuple) and v[1] < now
    ]
    for k in expired_pkce:
        _pkce_store.pop(k, None)
    expired_tokens = [k for k, v in _token_store.items() if v.get("expires", 0) < now]
    for k in expired_tokens:
        _token_store.pop(k, None)


def _generate_pkce() -> tuple[str, str]:
    """PKCE code_verifier / code_challenge 생성"""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


@router.get("/authorize")
@limiter.limit("10/minute")
def oauth_authorize(request: Request):
    """DataGSM OAuth 인증 시작 — 사용자를 DataGSM 로그인 페이지로 리다이렉트"""
    state = secrets.token_urlsafe(32)
    verifier, challenge = _generate_pkce()

    # state → (verifier, 만료시간) 저장
    _cleanup_stores()
    if len(_pkce_store) > 1000:
        raise HTTPException(
            status_code=503, detail="서버가 바쁩니다. 잠시 후 다시 시도해주세요."
        )
    _pkce_store[state] = (verifier, time.time() + _STORE_TTL)

    params = {
        "client_id": settings.DATAGSM_CLIENT_ID,
        "redirect_uri": settings.OAUTH_REDIRECT_URI,
        "response_type": "code",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    query = urlencode(params)
    return RedirectResponse(f"{settings.DATAGSM_OAUTH_URL}/v1/oauth/authorize?{query}")


@router.get("/callback")
async def oauth_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db),
):
    """DataGSM 콜백 — code로 토큰 교환 → userinfo 조회 → 우리 JWT 발급"""

    # 1. PKCE verifier 꺼내기
    entry = _pkce_store.pop(state, None)
    if not entry or (isinstance(entry, tuple) and entry[1] < time.time()):
        raise HTTPException(
            status_code=400,
            detail="유효하지 않거나 만료된 state입니다. 다시 로그인해주세요.",
        )
    verifier = entry[0] if isinstance(entry, tuple) else entry
    if not verifier:
        raise HTTPException(
            status_code=400, detail="유효하지 않은 state입니다. 다시 로그인해주세요."
        )

    async with httpx.AsyncClient(timeout=30) as client:
        # 2. Authorization Code → Access Token 교환
        token_res = await client.post(
            f"{settings.DATAGSM_OAUTH_URL}/v1/oauth/token",
            json={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": settings.DATAGSM_CLIENT_ID,
                "client_secret": settings.DATAGSM_CLIENT_SECRET,
                "redirect_uri": settings.OAUTH_REDIRECT_URI,
                "code_verifier": verifier,
            },
        )

        if token_res.status_code != 200:
            try:
                err = token_res.json()
            except ValueError:
                err = {}
            logger.error(
                "[OAuth] 토큰 교환 실패: status=%s error=%s description=%s",
                token_res.status_code,
                err.get("error"),
                err.get("error_description"),
            )
            raise HTTPException(status_code=400, detail="토큰 교환에 실패했습니다.")

        token_data = token_res.json()
        token_inner = token_data.get("data", token_data)
        access_token = token_inner.get("access_token")

        # 3. Access Token으로 UserInfo 조회
        userinfo_res = await client.get(
            f"{settings.DATAGSM_USERINFO_URL}/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if userinfo_res.status_code != 200:
            try:
                err = userinfo_res.json()
            except ValueError:
                err = {}
            logger.error(
                "[OAuth] UserInfo 조회 실패: status=%s error=%s",
                userinfo_res.status_code,
                err.get("error"),
            )
            raise HTTPException(
                status_code=400, detail="사용자 정보 조회에 실패했습니다."
            )

        userinfo_raw = userinfo_res.json()
        userinfo = userinfo_raw.get("data", userinfo_raw)

    # 4. 유저 정보 파싱
    email = userinfo.get("email")
    oauth_sub = str(userinfo.get("id") or userinfo.get("sub", ""))
    name = userinfo.get("name", "")
    grade = userinfo.get("grade")
    class_num = userinfo.get("classNum") or userinfo.get("class_num")
    number = userinfo.get("number")
    major = userinfo.get("major", "")

    if not email:
        raise HTTPException(status_code=400, detail="이메일 정보를 가져올 수 없습니다.")

    # 5. 기존 유저 매칭 (이메일 기준)
    # 복합 유니크 제약(email, role)으로 동일 이메일에 여러 역할 계정이 존재할 수 있으므로
    # 관리자/오너 계정 존재 여부를 먼저 명시적으로 차단
    if db.query(User).filter(User.email == email, User.role != UserRole.USER).first():
        raise HTTPException(
            status_code=409,
            detail="해당 이메일은 다른 권한 계정으로 이미 존재합니다.",
        )
    user = (
        db.query(User).filter(User.email == email, User.role == UserRole.USER).first()
    )

    if user:
        # 기존 계정에 OAuth 연결
        if not user.oauth_provider:
            user.oauth_provider = "datagsm"
            user.oauth_sub = oauth_sub
        # 학생 정보 업데이트
        if name:
            user.name = name
        if grade is not None:
            user.grade = grade
        if class_num is not None:
            user.class_num = class_num
        if number is not None:
            user.number = number
        if major:
            user.major = major
        db.commit()
    else:
        # 새 계정 생성 (비밀번호 없음 — OAuth 전용)
        user = User(
            email=email,
            hashed_password=None,
            role=UserRole.USER,
            is_active=True,
            oauth_provider="datagsm",
            oauth_sub=oauth_sub,
            name=name,
            grade=grade,
            class_num=class_num,
            number=number,
            major=major,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="비활성화된 계정입니다.")

    # 6. 우리 JWT 발급
    our_access = create_access_token(subject=str(user.id))
    our_refresh = create_refresh_token(subject=str(user.id))

    # 7. 임시 코드 발급 → 프론트에서 POST /exchange로 교환
    temp_code = secrets.token_urlsafe(48)
    _token_store[temp_code] = {
        "access_token": our_access,
        "refresh_token": our_refresh,
        "expires": time.time() + 60,  # 1분 유효
    }

    redirect_url = f"{settings.FRONTEND_URL}/auth/callback?code={temp_code}"
    return RedirectResponse(redirect_url)


class TokenExchangeRequest(BaseModel):
    code: str


@router.post("/exchange")
def exchange_temp_code(body: TokenExchangeRequest):
    """임시 코드를 JWT 토큰으로 교환 (1회용) — httpOnly 쿠키에 설정"""
    entry = _token_store.pop(body.code, None)
    if not entry or entry["expires"] < time.time():
        raise HTTPException(
            status_code=400, detail="유효하지 않거나 만료된 코드입니다."
        )

    is_prod = settings.FRONTEND_URL.startswith("https")
    response = JSONResponse(content={"message": "ok"})
    response.set_cookie(
        key="access_token",
        value=entry["access_token"],
        httponly=True,
        secure=is_prod,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=entry["refresh_token"],
        httponly=True,
        secure=is_prod,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
        path="/api/v1/auth/refresh",
    )
    return response
