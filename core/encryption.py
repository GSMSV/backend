"""
Fernet 대칭키 암호화 유틸리티
SECRET_KEY에서 파생된 키로 민감 데이터를 암호화/복호화합니다.
"""
import base64
import hashlib
from cryptography.fernet import Fernet
from core.config import settings


def _derive_key(secret: str) -> bytes:
    """SECRET_KEY에서 Fernet 호환 32바이트 키를 파생합니다."""
    digest = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)


_fernet = Fernet(_derive_key(settings.SECRET_KEY))


def encrypt(value: str) -> str:
    """평문을 암호화하여 base64 문자열로 반환합니다."""
    if not value:
        return value
    return _fernet.encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    """암호화된 문자열을 복호화합니다."""
    if not token:
        return token
    return _fernet.decrypt(token.encode()).decode()
