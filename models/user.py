from sqlalchemy import Boolean, Column, Integer, String, Enum, UniqueConstraint
import enum
from core.database import Base

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    PROJECT_OWNER = "project_owner"
    USER = "user"

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", "role", name="uq_email_role"),
    )

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)  # unique 제거, email+role 조합으로 유니크
    hashed_password = Column(String, nullable=True)      # OAuth 전용 유저는 비밀번호 없을 수 있음
    role = Column(Enum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)

    # OAuth 연동 정보
    oauth_provider = Column(String, nullable=True)       # "datagsm" 등
    oauth_sub = Column(String, nullable=True)            # OAuth 유저 고유 ID

    # DataGSM 학생 정보
    name = Column(String, nullable=True)
    grade = Column(Integer, nullable=True)
    class_num = Column(Integer, nullable=True)
    number = Column(Integer, nullable=True)
    major = Column(String, nullable=True)

    # 프로필
    avatar_url = Column(String, nullable=True)

    # 프로젝트 오너 전용
    project_name = Column(String, nullable=True)
    project_reason = Column(String, nullable=True)
