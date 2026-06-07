from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Index
from sqlalchemy.orm import relationship
from core.database import Base
from core.timezone import now_kst


class Notification(Base):
    __tablename__ = "notifications"

    # 알림 목록 조회는 항상 "user_id = ? ORDER BY created_at DESC" 형태이므로
    # (user_id, created_at) 복합 인덱스로 필터 + 정렬을 한 번에 커버한다.
    __table_args__ = (
        Index("ix_notifications_user_created", "user_id", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    type = Column(String, nullable=False)       # info, success, error
    message = Column(String, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=now_kst)

    user = relationship("User", backref="notifications")
