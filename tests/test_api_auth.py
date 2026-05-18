"""인증 API 엔드포인트 테스트
TestClient가 main.py의 lifespan(PostgreSQL 연결)을 실행하므로,
DB 의존성을 오버라이드하고 lifespan 없는 별도 앱으로 테스트합니다.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from core.database import Base, get_db

# 테스트 전용 앱 (lifespan 없이 라우터만 등록)
TEST_DB_URL = "sqlite:///./test_api.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_test_app():
    from api.routes import auth, vmcontrol, notifications, faq

    test_app = FastAPI()
    test_app.include_router(auth.router, prefix="/api/v1/auth")
    test_app.include_router(vmcontrol.router, prefix="/api/v1/vm")
    test_app.include_router(notifications.router, prefix="/api/v1/notifications")
    test_app.include_router(faq.router, prefix="/api/v1/faq")

    def override_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    test_app.dependency_overrides[get_db] = override_db
    return test_app


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)
    app = get_test_app()
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


class TestAuthEndpoints:
    """인증 관련 API"""

    def test_me_unauthenticated(self, client):
        """비로그인 상태에서 /me 호출 시 401"""
        res = client.get("/api/v1/auth/me")
        assert res.status_code == 401

    def test_refresh_unauthenticated(self, client):
        """비로그인 상태에서 /refresh 호출 시 401"""
        res = client.post("/api/v1/auth/refresh")
        assert res.status_code == 401

    def test_login_invalid_credentials(self, client):
        """존재하지 않는 계정으로 로그인 시 실패"""
        res = client.post(
            "/api/v1/auth/login",
            data={"username": "noexist@gsm.hs.kr", "password": "Pass1234!", "role": "user"},
        )
        assert res.status_code in (401, 400)

    def test_signup_weak_password(self, client):
        """약한 비밀번호로 회원가입 시 422"""
        res = client.post(
            "/api/v1/auth/signup",
            json={"email": "test@gsm.hs.kr", "password": "weak"},
        )
        assert res.status_code == 422

    def test_signup_invalid_email(self, client):
        """잘못된 이메일 형식으로 가입 시 422"""
        res = client.post(
            "/api/v1/auth/signup",
            json={"email": "not-email", "password": "Pass1234!"},
        )
        assert res.status_code == 422

    def test_verify_no_record(self, client):
        """존재하지 않는 인증 요청에 코드 확인 시 400"""
        res = client.post(
            "/api/v1/auth/verify",
            json={"email": "noexist@gsm.hs.kr", "code": "123456"},
        )
        assert res.status_code == 400

    def test_vm_list_unauthenticated(self, client):
        """비로그인 상태에서 VM 목록 조회 시 401"""
        res = client.get("/api/v1/vm/my-vms")
        assert res.status_code == 401

    def test_notifications_unauthenticated(self, client):
        """비로그인 상태에서 알림 조회 시 401"""
        res = client.get("/api/v1/notifications")
        assert res.status_code == 401

    def test_faq_unauthenticated(self, client):
        """비로그인 상태에서 FAQ 조회 시 401"""
        res = client.get("/api/v1/faq")
        assert res.status_code == 401
