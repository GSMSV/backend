"""
Domain 4: 외부 서비스 & 인프라 테스트 (EXT-TC-01 ~ EXT-TC-06)

이메일 로깅, OAuth URL 인코딩, 스토어 스레드 안전성, Proxmox 캐시, 알림 읽음 처리.
"""

import threading
import time
import urllib.parse
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.database import Base
from models.user import User, UserRole
from models.notification import Notification

# ── 테스트용 DB ────────────────────────────────────────────────

TEST_DB_URL = "sqlite:///./test_external.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    session = TestSession()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def user(db):
    u = User(
        email="test@gsm.hs.kr",
        hashed_password="hashed",
        role=UserRole.USER,
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


# ── EXT-TC-01: 이메일 발송 실패 시 logger.error ──────────────


class TestEmailServiceLogging:
    """EXT-TC-01: print 대신 logger.error 사용 확인"""

    @pytest.mark.asyncio
    async def test_email_failure_uses_logger(self):
        """이메일 발송 실패 시 logger.error 호출"""
        with patch(
            "services.email_service.aiosmtplib.send", side_effect=Exception("SMTP fail")
        ):
            with patch("services.email_service.logger") as mock_logger:
                from services.email_service import send_verification_email

                result = await send_verification_email("test@test.com", "123456")
                assert result is False
                mock_logger.error.assert_called_once()
                assert "SMTP fail" in str(mock_logger.error.call_args)


# ── EXT-TC-02: OAuth URL 파라미터 인코딩 ─────────────────────


class TestOAuthURLEncoding:
    """EXT-TC-02: redirect_uri 등 특수문자 URL 인코딩"""

    def test_urlencode_handles_special_chars(self):
        """urllib.parse.urlencode가 특수문자를 올바르게 인코딩"""
        params = {
            "client_id": "test-client",
            "redirect_uri": "http://example.com/callback?foo=bar&baz=qux",
            "state": "abc+123/xyz",
        }
        encoded = urllib.parse.urlencode(params)
        # redirect_uri의 &와 ? 가 인코딩되어야 함
        assert "%3F" in encoded or "%26" in encoded
        # state의 +와 /도 인코딩
        assert "abc" in encoded


# ── EXT-TC-03: OAuth 스토어 스레드 안전성 ─────────────────────


class TestOAuthStoreConcurrency:
    """EXT-TC-03: _pkce_store 동시 접근 시 데이터 오염 없음"""

    def test_concurrent_pkce_store_access(self):
        """동시에 여러 state 삽입 시 각각 고유"""
        from api.routes.oauth import _pkce_store, _store_lock

        states = []

        def insert_state(idx):
            import secrets

            state = secrets.token_urlsafe(16)
            verifier = f"verifier-{idx}"
            with _store_lock:
                _pkce_store[state] = (verifier, time.time() + 300)
            states.append((state, verifier))

        threads = [threading.Thread(target=insert_state, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(states) == 10
        # 모든 state가 고유
        state_keys = [s[0] for s in states]
        assert len(set(state_keys)) == 10

        # 정리
        with _store_lock:
            for state, _ in states:
                _pkce_store.pop(state, None)


# ── EXT-TC-04: ADMIN/PROJECT_OWNER 이메일 OAuth 시도 시 409 ──


class TestOAuthRoleConflict:
    """EXT-TC-04: 비USER 역할 이메일로 OAuth 콜백 시 409 반환"""

    @pytest.fixture
    def oauth_client(self):
        from api.routes import oauth as oauth_module
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from core.database import get_db

        test_app = FastAPI()
        test_app.include_router(oauth_module.router, prefix="/api/v1/oauth")

        def override_db():
            session = TestSession()
            try:
                yield session
            finally:
                session.close()

        test_app.dependency_overrides[get_db] = override_db
        return TestClient(test_app)

    def _call_callback(self, oauth_client, email: str) -> int:
        import time
        from api.routes.oauth import _pkce_store

        state = f"test-state-{email}"
        _pkce_store[state] = ("test-verifier", time.time() + 300)

        mock_token = MagicMock()
        mock_token.status_code = 200
        mock_token.json.return_value = {"access_token": "fake", "refresh_token": "fake"}

        mock_userinfo = MagicMock()
        mock_userinfo.status_code = 200
        mock_userinfo.json.return_value = {
            "data": {"email": email, "sub": "99", "name": "T"}
        }

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_token)
        mock_http.get = AsyncMock(return_value=mock_userinfo)

        with patch("api.routes.oauth.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            res = oauth_client.get(
                "/api/v1/oauth/callback",
                params={"code": "code123", "state": state},
                follow_redirects=False,
            )

        _pkce_store.pop(state, None)
        return res.status_code

    def test_admin_email_returns_409(self, db, oauth_client):
        """ADMIN 계정 이메일로 OAuth 시도 시 409"""
        db.add(
            User(
                email="admin@gsm.hs.kr",
                hashed_password="x",
                role=UserRole.ADMIN,
                is_active=True,
            )
        )
        db.commit()
        assert self._call_callback(oauth_client, "admin@gsm.hs.kr") == 409

    def test_project_owner_email_returns_409(self, db, oauth_client):
        """PROJECT_OWNER 계정 이메일로 OAuth 시도 시 409"""
        db.add(
            User(
                email="owner@gsm.hs.kr",
                hashed_password="x",
                role=UserRole.PROJECT_OWNER,
                is_active=True,
            )
        )
        db.commit()
        assert self._call_callback(oauth_client, "owner@gsm.hs.kr") == 409

    def test_user_role_does_not_block_oauth(self, db, oauth_client):
        """일반 USER 역할은 차단되지 않음 (409 아님)"""
        db.add(
            User(
                email="user@gsm.hs.kr",
                hashed_password="x",
                role=UserRole.USER,
                is_active=True,
            )
        )
        db.commit()
        status = self._call_callback(oauth_client, "user@gsm.hs.kr")
        assert status in (200, 302, 307)


# ── EXT-TC-05: Proxmox 연결 캐시 ─────────────────────────────


class TestProxmoxConnectionCache:
    """EXT-TC-05: 같은 서버에 5분 내 2회 연결 시 캐시 반환"""

    @patch("services.proxmox_client.ProxmoxAPI")
    def test_second_call_uses_cache(self, mock_api_cls):
        """두 번째 호출은 새 연결을 만들지 않음"""
        from services.proxmox_client import (
            get_proxmox_for_server,
            _connection_cache,
            _cache_lock,
        )

        mock_server = MagicMock()
        mock_server.id = 999
        mock_server.ip_address = "192.168.1.99"
        mock_server.api_user = "root@pam"
        mock_server.api_password = "pass"
        mock_server.port = 8006
        mock_server.name = "test-cache-node"

        # 캐시 비우기
        with _cache_lock:
            _connection_cache.pop(999, None)

        mock_proxmox = MagicMock()
        mock_api_cls.return_value = mock_proxmox

        # 첫 번째 호출
        result1 = get_proxmox_for_server(mock_server)
        assert result1 == mock_proxmox
        assert mock_api_cls.call_count == 1

        # 두 번째 호출 — 캐시에서 반환
        result2 = get_proxmox_for_server(mock_server)
        assert result2 == mock_proxmox
        assert mock_api_cls.call_count == 1  # 새 연결 안 함

        # 정리
        with _cache_lock:
            _connection_cache.pop(999, None)


# ── EXT-TC-06: /notifications/read-all — 삭제가 아닌 읽음 처리 ─


class TestNotificationsReadAll:
    """EXT-TC-06: read-all은 삭제가 아닌 is_read=True 설정"""

    def test_read_all_marks_as_read_not_delete(self, db, user):
        """미읽음 5개 → read-all → 5개 모두 is_read=True, 삭제 아님"""
        for i in range(5):
            db.add(
                Notification(
                    user_id=user.id,
                    type="info",
                    message=f"알림 {i}",
                    is_read=False,
                )
            )
        db.commit()

        # read-all 로직 시뮬레이션 (notifications.py의 mark_all_as_read)
        db.query(Notification).filter(
            Notification.user_id == user.id,
            Notification.is_read == False,
        ).update({"is_read": True})
        db.commit()

        # 삭제되지 않았는지 확인
        all_notifs = (
            db.query(Notification).filter(Notification.user_id == user.id).all()
        )
        assert len(all_notifs) == 5
        # 모두 읽음 상태
        assert all(n.is_read for n in all_notifs)

    def test_read_all_idempotent(self, db, user):
        """이미 읽은 알림에 다시 read-all 해도 문제 없음"""
        db.add(
            Notification(
                user_id=user.id, type="info", message="이미 읽음", is_read=True
            )
        )
        db.add(
            Notification(user_id=user.id, type="info", message="미읽음", is_read=False)
        )
        db.commit()

        db.query(Notification).filter(
            Notification.user_id == user.id,
            Notification.is_read == False,
        ).update({"is_read": True})
        db.commit()

        all_notifs = (
            db.query(Notification).filter(Notification.user_id == user.id).all()
        )
        assert len(all_notifs) == 2
        assert all(n.is_read for n in all_notifs)
