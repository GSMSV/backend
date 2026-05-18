"""_notify_admins_background_failure 단위 테스트."""

import pytest
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.database import Base
from core.security import get_password_hash
from models.user import User, UserRole
from models.notification import Notification

TEST_DB_URL = "sqlite:///./test_background_tasks.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    s = TestSession()
    try:
        yield s
    finally:
        s.close()


def _call_notify(task_name: str, failures: int):
    from main import _notify_admins_background_failure
    with patch("main.SessionLocal", return_value=TestSession()):
        _notify_admins_background_failure(task_name, failures)


class TestNotifyAdminsBackgroundFailure:
    def test_creates_notification_for_each_admin(self, db):
        """ADMIN 유저 수만큼 Notification 생성."""
        for email in ("a@gsm.hs.kr", "b@gsm.hs.kr"):
            db.add(User(
                email=email,
                hashed_password=get_password_hash("Pass1!aa"),
                role=UserRole.ADMIN,
                is_active=True,
            ))
        db.commit()

        from main import _notify_admins_background_failure
        with patch("main.SessionLocal", return_value=db):
            _notify_admins_background_failure("expire", 5)

        db.expire_all()
        notifs = db.query(Notification).all()
        assert len(notifs) == 2
        assert all("expire" in n.message for n in notifs)
        assert all("5회" in n.message for n in notifs)

    def test_no_notification_when_no_admin(self, db):
        """ADMIN이 없으면 Notification 생성 안 됨."""
        db.add(User(
            email="user@gsm.hs.kr",
            hashed_password=get_password_hash("Pass1!aa"),
            role=UserRole.USER,
            is_active=True,
        ))
        db.commit()

        from main import _notify_admins_background_failure
        with patch("main.SessionLocal", return_value=db):
            _notify_admins_background_failure("expire", 5)

        assert db.query(Notification).count() == 0

    def test_db_error_triggers_rollback_and_warning(self, db):
        """DB 오류 시 rollback 후 logger.warning 호출, 예외 전파 없음."""
        db.add(User(
            email="admin@gsm.hs.kr",
            hashed_password=get_password_hash("Pass1!aa"),
            role=UserRole.ADMIN,
            is_active=True,
        ))
        db.commit()

        from main import _notify_admins_background_failure
        broken_session = TestSession()
        broken_session.commit = lambda: (_ for _ in ()).throw(Exception("DB error"))

        import logging
        with patch("main.SessionLocal", return_value=broken_session), \
             patch.object(logging.getLogger("main"), "warning") as mock_warn:
            _notify_admins_background_failure("expire", 5)  # 예외 전파 없어야 함

        assert mock_warn.called
        broken_session.close()

    def test_inactive_admin_excluded(self, db):
        """is_active=False인 ADMIN에게는 알림 발송 안 됨."""
        db.add(User(
            email="inactive@gsm.hs.kr",
            hashed_password=get_password_hash("Pass1!aa"),
            role=UserRole.ADMIN,
            is_active=False,
        ))
        db.commit()

        from main import _notify_admins_background_failure
        with patch("main.SessionLocal", return_value=db):
            _notify_admins_background_failure("expire", 5)

        assert db.query(Notification).count() == 0
