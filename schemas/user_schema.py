import re
from pydantic import BaseModel, EmailStr, field_validator

from core.security import MAX_PASSWORD_BYTES

_PW_PATTERN = re.compile(
    r'^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:\'",.<>?/~`]).{8,}$'
)
_PW_MSG = "비밀번호는 8자 이상, 영문+숫자+특수기호를 포함해야 합니다."


def _validate_pw(v: str) -> str:
    if not _PW_PATTERN.match(v):
        raise ValueError(_PW_MSG)
    if len(v.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"비밀번호가 너무 깁니다. UTF-8 기준 {MAX_PASSWORD_BYTES}바이트 이하여야 합니다."
        )
    return v


class UserCreate(BaseModel):
    """회원가입 요청 모델 (1단계: 이메일 인증 코드 발송)"""

    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        return _validate_pw(v)


class ProjectCheckRequest(BaseModel):
    """프로젝트 오너 가입 1단계: 이메일로 참여 프로젝트 조회"""

    email: EmailStr


class ProjectSignupRequest(BaseModel):
    """프로젝트 오너 가입 2단계: 프로젝트 선택 + 비밀번호 + 신청사유"""

    email: EmailStr
    password: str
    project_name: str
    reason: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        return _validate_pw(v)


class VerifyCodeRequest(BaseModel):
    """이메일 인증 코드 확인 요청 모델 (2단계: 코드 검증 → 계정 생성)"""

    email: EmailStr
    code: str


class ResendCodeRequest(BaseModel):
    """인증 코드 재발송 요청 모델"""

    email: EmailStr


class Token(BaseModel):
    """JWT 토큰 응답 모델 (Access + Refresh)"""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """Refresh Token 요청 모델 (쿠키 우선, body는 선택)"""

    refresh_token: str = ""


_RESET_ROLES = {"user", "project_owner"}


class PasswordResetRequest(BaseModel):
    """비밀번호 재설정 요청 (이메일로 인증 코드 발송)"""

    email: EmailStr
    login_role: str = "user"

    @field_validator("login_role")
    @classmethod
    def validate_role(cls, v):
        if v not in _RESET_ROLES:
            raise ValueError("login_role은 user 또는 project_owner여야 합니다.")
        return v


class PasswordResetConfirm(BaseModel):
    """비밀번호 재설정 확인 (코드 + 새 비밀번호)"""

    email: EmailStr
    code: str
    new_password: str
    login_role: str = "user"

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v):
        return _validate_pw(v)

    @field_validator("login_role")
    @classmethod
    def validate_role(cls, v):
        if v not in _RESET_ROLES:
            raise ValueError("login_role은 user 또는 project_owner여야 합니다.")
        return v


class ChangePasswordRequest(BaseModel):
    """로그인 상태 비밀번호 변경 요청"""

    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v):
        return _validate_pw(v)
