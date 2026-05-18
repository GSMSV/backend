from sqlalchemy import Column, Integer, String, DateTime, Boolean
from core.database import Base
from core.timezone import now_kst


class EmailVerification(Base):
    """이메일 인증 대기 테이블 — 회원가입 시 6자리 코드를 저장합니다."""
    __tablename__ = "email_verifications"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    code = Column(String(6), nullable=False)
    student_info = Column(String, nullable=True)  # DataGSM 학생 정보 JSON
    signup_role = Column(String, default="user")  # "user" 또는 "project_owner"
    project_name = Column(String, nullable=True)  # 프로젝트 오너 가입 시 프로젝트명
    project_reason = Column(String, nullable=True)  # 프로젝트 오너 신청 사유
    created_at = Column(DateTime(timezone=True), default=now_kst)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    verified = Column(Boolean, default=False)
    attempts = Column(Integer, server_default="0", default=0, nullable=False)
