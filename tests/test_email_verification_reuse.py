"""이메일 인증 코드 재사용 취약점 테스트 (issue #56)

SQLite는 timezone-aware datetime을 지원하지 않으므로
now_kst()를 naive datetime으로 패치해서 테스트합니다.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from core.database import Base, get_db
from models.email_verification import EmailVerification
from models.user import User

TEST_DB_URL = "sqlite:///./test_email_reuse.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# SQLite 호환 naive datetime 반환
def _naive_now():
    return datetime.utcnow()


def get_test_app():
    from api.routes import auth

    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")

    def override_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    return app


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)
    app = get_test_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


def _insert_verification(email: str, code: str, signup_role: str = "user") -> None:
    db = TestSession()
    try:
        record = EmailVerification(
            email=email,
            hashed_password="$2b$12$fakehashfortest000000000000000000000000000000000000000",
            code=code,
            signup_role=signup_role,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        db.add(record)
        db.commit()
    finally:
        db.close()


def _cleanup() -> None:
    db = TestSession()
    try:
        db.query(EmailVerification).delete()
        db.query(User).delete()
        db.commit()
    finally:
        db.close()


class TestEmailVerificationReuse:
    """이메일 인증 코드 재사용 취약점 픽스 검증"""

    def setup_method(self):
        _cleanup()

    def test_verify_code_reuse_blocked(self, client):
        """인증 완료 후 동일 코드로 재요청 시 400 반환 — record 삭제로 차단"""
        _insert_verification("reuse1@gsm.hs.kr", "111111")

        with patch("api.routes.auth.now_kst", _naive_now):
            res1 = client.post("/api/v1/auth/verify", json={"email": "reuse1@gsm.hs.kr", "code": "111111"})
            assert res1.status_code == 200

            res2 = client.post("/api/v1/auth/verify", json={"email": "reuse1@gsm.hs.kr", "code": "111111"})
            assert res2.status_code == 400

    def test_resend_invalidates_old_code(self, client):
        """/resend-code 호출 후 이전 코드로 인증 불가"""
        _insert_verification("reuse2@gsm.hs.kr", "222222")

        with patch("api.routes.auth.now_kst", _naive_now), \
             patch("api.routes.auth.send_verification_email", return_value=True):
            client.post("/api/v1/auth/resend-code", json={"email": "reuse2@gsm.hs.kr"})

            # 이전 코드로 인증 시도 → 최신 레코드와 코드 불일치 → 400
            res = client.post("/api/v1/auth/verify", json={"email": "reuse2@gsm.hs.kr", "code": "222222"})
            assert res.status_code == 400

    def test_already_registered_returns_400(self, client):
        """인증 완료 후 같은 이메일로 재인증 시도 시 400 반환"""
        _insert_verification("reuse3@gsm.hs.kr", "333333")

        with patch("api.routes.auth.now_kst", _naive_now):
            # 첫 번째 인증 성공 — User 생성
            client.post("/api/v1/auth/verify", json={"email": "reuse3@gsm.hs.kr", "code": "333333"})

            # 같은 이메일로 재인증 레코드 삽입 후 시도 → 이미 가입된 계정 → 400
            _insert_verification("reuse3@gsm.hs.kr", "333333")
            res = client.post("/api/v1/auth/verify", json={"email": "reuse3@gsm.hs.kr", "code": "333333"})
            assert res.status_code == 400
