from datetime import datetime, timedelta
from typing import Any, Union
from jose import jwt
import bcrypt
from core.config import settings


MAX_PASSWORD_BYTES = 72  # bcrypt 5.x 한계


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """평문 비밀번호와 해시된 비밀번호를 비교합니다.

    DB에 잘못된 형식의 해시가 저장된 경우 ValueError를 잡아 False로 반환합니다.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except ValueError:
        return False


def get_password_hash(password: str) -> str:
    """비밀번호를 해싱합니다. 72바이트 초과 시 ValueError 발생."""
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"비밀번호가 너무 깁니다. UTF-8 기준 {MAX_PASSWORD_BYTES}바이트 이하여야 합니다."
        )
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def create_access_token(
    subject: Union[str, Any], expires_delta: timedelta = None
) -> str:
    """JWT Access Token을 생성합니다. (짧은 수명)"""
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {"exp": expire, "sub": str(subject), "type": "access"}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(
    subject: Union[str, Any], expires_delta: timedelta = None
) -> str:
    """JWT Refresh Token을 생성합니다. (긴 수명)"""
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {"exp": expire, "sub": str(subject), "type": "refresh"}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
