"""비밀번호 변경 (PUT /auth/change-password) 동작 검증 테스트."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.database import Base, get_db
from core.security import create_access_token, get_password_hash, verify_password
from models.user import User, UserRole

TEST_DB_URL = "sqlite:///./test_change_password.db"
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


@pytest.fixture
def app(db):
    from api.routes import auth as auth_route

    test_app = FastAPI()
    test_app.include_router(auth_route.router, prefix="/api/v1/auth")

    def override_db():
        try:
            yield db
        finally:
            pass

    test_app.dependency_overrides[get_db] = override_db
    return test_app


@pytest.fixture
def client(app):
    from api.routes.auth import limiter

    limiter._limiter.storage.reset()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _make_user(db, email="user@gsm.hs.kr", password="OldPass1!", oauth=False):
    u = User(
        email=email,
        hashed_password="" if oauth else get_password_hash(password),
        role=UserRole.USER,
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _auth_cookie(user_id: int) -> dict:
    return {"access_token": create_access_token(subject=str(user_id))}


class TestChangePassword:
    def test_success(self, client, db):
        user = _make_user(db, password="OldPass1!")
        res = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass1!", "new_password": "NewPass2@"},
            cookies=_auth_cookie(user.id),
        )
        assert res.status_code == 200, res.text
        db.refresh(user)
        assert verify_password("NewPass2@", user.hashed_password)
        assert not verify_password("OldPass1!", user.hashed_password)

    def test_wrong_current_password(self, client, db):
        user = _make_user(db, password="OldPass1!")
        res = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "WrongPass1!", "new_password": "NewPass2@"},
            cookies=_auth_cookie(user.id),
        )
        assert res.status_code == 400
        assert "현재 비밀번호" in res.json()["detail"]

    def test_weak_new_password(self, client, db):
        user = _make_user(db, password="OldPass1!")
        res = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass1!", "new_password": "weak"},
            cookies=_auth_cookie(user.id),
        )
        assert res.status_code == 422
        assert "8자" in res.text

    def test_oauth_user_blocked(self, client, db):
        user = _make_user(db, oauth=True)
        res = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "anything", "new_password": "NewPass2@"},
            cookies=_auth_cookie(user.id),
        )
        assert res.status_code == 400
        assert "OAuth" in res.json()["detail"]

    def test_unauthenticated(self, client):
        res = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass1!", "new_password": "NewPass2@"},
        )
        assert res.status_code == 401

    def test_long_ascii_password_72plus(self, client, db):
        """72바이트 초과 ASCII 비밀번호 → 422."""
        user = _make_user(db, password="OldPass1!")
        long_pw = "Aa1!" + "x" * 70  # 74 bytes
        res = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass1!", "new_password": long_pw},
            cookies=_auth_cookie(user.id),
        )
        assert res.status_code == 422, res.text
        assert "72바이트" in res.text

    def test_unicode_password_long_bytes(self, client, db):
        """한글 포함 + 72바이트 초과 비밀번호 → 422."""
        user = _make_user(db, password="OldPass1!")
        unicode_pw = "Aa1!" + "한" * 30  # 4 + 90 = 94 bytes
        res = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass1!", "new_password": unicode_pw},
            cookies=_auth_cookie(user.id),
        )
        assert res.status_code == 422
        assert "72바이트" in res.text

    def test_dual_role_account_isolated_on_change(self, client, db):
        """USER+PROJECT_OWNER 듀얼 계정은 별개로 취급 — PO에서 변경해도 USER는 그대로."""
        _make_user(db, email="dup@gsm.hs.kr", password="OldPass1!")
        po_row = User(
            email="dup@gsm.hs.kr",
            hashed_password=get_password_hash("OldPass1!"),
            role=UserRole.PROJECT_OWNER,
            is_active=True,
        )
        db.add(po_row)
        db.commit()
        db.refresh(po_row)

        change = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass1!", "new_password": "NewPass2@"},
            cookies=_auth_cookie(po_row.id),
        )
        assert change.status_code == 200

        # PO 탭은 새 비밀번호로 성공
        login_po = client.post(
            "/api/v1/auth/login?login_role=project_owner",
            data={"username": "dup@gsm.hs.kr", "password": "NewPass2@"},
        )
        assert login_po.status_code == 200

        # USER 탭은 옛 비밀번호 그대로
        login_user_old = client.post(
            "/api/v1/auth/login",
            data={"username": "dup@gsm.hs.kr", "password": "OldPass1!"},
        )
        assert login_user_old.status_code == 200

        # USER 탭에서 PO의 새 비밀번호는 실패해야 함
        login_user_new = client.post(
            "/api/v1/auth/login",
            data={"username": "dup@gsm.hs.kr", "password": "NewPass2@"},
        )
        assert login_user_new.status_code == 401

    def test_db_direct_plaintext_password_login(self, client, db):
        """hashed_password 컬럼에 비-bcrypt 형식이 들어 있어도 500이 아닌 401."""
        u = User(
            email="direct@gsm.hs.kr",
            hashed_password="Pass1!aa",  # 평문 (bcrypt 해시 아님)
            role=UserRole.USER,
            is_active=True,
        )
        db.add(u)
        db.commit()

        res = client.post(
            "/api/v1/auth/login",
            data={"username": "direct@gsm.hs.kr", "password": "Pass1!aa"},
        )
        assert res.status_code == 401, res.text

    def test_db_direct_change_then_login(self, client, db):
        """DB에 올바른 bcrypt 해시를 직접 삽입한 정상 케이스 → 변경 → 새 비번 로그인."""
        u = User(
            email="dbgood@gsm.hs.kr",
            hashed_password=get_password_hash("OldPass1!"),
            role=UserRole.USER,
            is_active=True,
        )
        db.add(u)
        db.commit()
        db.refresh(u)

        change = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass1!", "new_password": "NewPass2@"},
            cookies=_auth_cookie(u.id),
        )
        assert change.status_code == 200, change.text

        new_login = client.post(
            "/api/v1/auth/login",
            data={"username": "dbgood@gsm.hs.kr", "password": "NewPass2@"},
        )
        assert new_login.status_code == 200, new_login.text

    def test_change_password_does_not_touch_other_role_row(self, client, db):
        """DB 레벨에서 PO row 변경 시 USER row의 해시는 그대로인지 확인."""
        old_hash = get_password_hash("OldPass1!")
        u_user = User(
            email="multi@gsm.hs.kr",
            hashed_password=old_hash,
            role=UserRole.USER,
            is_active=True,
        )
        u_po = User(
            email="multi@gsm.hs.kr",
            hashed_password=old_hash,
            role=UserRole.PROJECT_OWNER,
            is_active=True,
        )
        db.add_all([u_user, u_po])
        db.commit()
        db.refresh(u_user)
        db.refresh(u_po)

        change = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass1!", "new_password": "NewPass2@"},
            cookies=_auth_cookie(u_po.id),
        )
        assert change.status_code == 200

        db.expire_all()
        u_user_reloaded = db.query(User).filter_by(id=u_user.id).first()
        u_po_reloaded = db.query(User).filter_by(id=u_po.id).first()
        assert verify_password("NewPass2@", u_po_reloaded.hashed_password)
        assert verify_password("OldPass1!", u_user_reloaded.hashed_password), (
            "USER row는 PO 변경의 영향을 받지 않아야 함 (별개 계정 정책)"
        )

    def test_password_reset_request_creates_role_specific_record(self, client, db):
        """비밀번호 재설정 요청은 login_role에 따라 분리된 EmailVerification을 만든다."""
        from models.email_verification import EmailVerification

        u_user = User(
            email="reset@gsm.hs.kr",
            hashed_password=get_password_hash("OldPass1!"),
            role=UserRole.USER,
            is_active=True,
        )
        u_po = User(
            email="reset@gsm.hs.kr",
            hashed_password=get_password_hash("OldPass1!"),
            role=UserRole.PROJECT_OWNER,
            is_active=True,
        )
        db.add_all([u_user, u_po])
        db.commit()

        # SMTP 호출은 모킹 — 단위 환경에선 실제 발송 안 됨
        from unittest.mock import patch

        with patch("api.routes.auth.send_verification_email", return_value=True):
            res_user = client.post(
                "/api/v1/auth/password-reset/request",
                json={"email": "reset@gsm.hs.kr", "login_role": "user"},
            )
            res_po = client.post(
                "/api/v1/auth/password-reset/request",
                json={
                    "email": "reset@gsm.hs.kr",
                    "login_role": "project_owner",
                },
            )
        assert res_user.status_code == 200, res_user.text
        assert res_po.status_code == 200, res_po.text

        db.expire_all()
        records = (
            db.query(EmailVerification)
            .filter(EmailVerification.email == "reset@gsm.hs.kr")
            .all()
        )
        roles = {r.signup_role for r in records}
        assert "password_reset:user" in roles
        assert "password_reset:project_owner" in roles

    def test_password_reset_confirm_rejects_code_for_other_role(self, client, db):
        """PO 재설정 코드를 user role로 confirm하면 실패하고 양쪽 비밀번호는 유지된다."""
        from datetime import timedelta

        from core.timezone import now_kst
        from models.email_verification import EmailVerification

        user_row = User(
            email="cross-reset@gsm.hs.kr",
            hashed_password=get_password_hash("UserPass1!"),
            role=UserRole.USER,
            is_active=True,
        )
        po_row = User(
            email="cross-reset@gsm.hs.kr",
            hashed_password=get_password_hash("OwnerPass1!"),
            role=UserRole.PROJECT_OWNER,
            is_active=True,
        )
        reset_record = EmailVerification(
            email="cross-reset@gsm.hs.kr",
            hashed_password="",
            code="654321",
            signup_role="password_reset:project_owner",
            expires_at=now_kst() + timedelta(minutes=10),
            verified=False,
            attempts=0,
        )
        db.add_all([user_row, po_row, reset_record])
        db.commit()

        res = client.post(
            "/api/v1/auth/password-reset/confirm",
            json={
                "email": "cross-reset@gsm.hs.kr",
                "code": "654321",
                "new_password": "NewPass2@",
                "login_role": "user",
            },
        )
        assert res.status_code == 400, res.text
        assert "재설정 요청" in res.json()["detail"]

        db.expire_all()
        user_reloaded = db.query(User).filter_by(id=user_row.id).first()
        po_reloaded = db.query(User).filter_by(id=po_row.id).first()
        record_reloaded = (
            db.query(EmailVerification).filter_by(id=reset_record.id).first()
        )
        assert verify_password("UserPass1!", user_reloaded.hashed_password)
        assert verify_password("OwnerPass1!", po_reloaded.hashed_password)
        assert record_reloaded is not None

    def test_password_reset_request_role_mismatch_silently_succeeds(self, client, db):
        """존재하지 않는 role 조합 요청도 보안상 같은 메시지 — 레코드는 생성 안 됨."""
        from models.email_verification import EmailVerification
        from unittest.mock import patch

        # USER만 존재
        _make_user(db, email="onlyuser@gsm.hs.kr")

        with patch("api.routes.auth.send_verification_email", return_value=True):
            res = client.post(
                "/api/v1/auth/password-reset/request",
                json={
                    "email": "onlyuser@gsm.hs.kr",
                    "login_role": "project_owner",
                },
            )
        assert res.status_code == 200
        recs = (
            db.query(EmailVerification)
            .filter(EmailVerification.email == "onlyuser@gsm.hs.kr")
            .all()
        )
        assert len(recs) == 0, "PO 계정이 없으므로 레코드도 생성되지 않아야 함"

    def test_login_with_new_password_after_change(self, client, db):
        """변경 → 새 비밀번호 로그인 성공, 옛 비밀번호 로그인 실패."""
        user = _make_user(db, email="login@gsm.hs.kr", password="OldPass1!")

        change = client.put(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass1!", "new_password": "NewPass2@"},
            cookies=_auth_cookie(user.id),
        )
        assert change.status_code == 200, change.text

        new_login = client.post(
            "/api/v1/auth/login",
            data={"username": "login@gsm.hs.kr", "password": "NewPass2@"},
        )
        assert new_login.status_code == 200, new_login.text

        old_login = client.post(
            "/api/v1/auth/login",
            data={"username": "login@gsm.hs.kr", "password": "OldPass1!"},
        )
        assert old_login.status_code == 401

    def test_admin_password_reset_request_creates_record(self, client, db):
        """ADMIN 계정은 user 탭(login_role=user)으로 재설정 요청 시 레코드가 생성된다."""
        from models.email_verification import EmailVerification
        from unittest.mock import patch

        admin = User(
            email="admin@gsm.hs.kr",
            hashed_password=get_password_hash("OldPass1!"),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(admin)
        db.commit()

        with patch("api.routes.auth.send_verification_email", return_value=True):
            req = client.post(
                "/api/v1/auth/password-reset/request",
                json={"email": "admin@gsm.hs.kr", "login_role": "user"},
            )
        assert req.status_code == 200, req.text

        db.expire_all()
        record = (
            db.query(EmailVerification)
            .filter_by(email="admin@gsm.hs.kr", signup_role="password_reset:user")
            .first()
        )
        assert record is not None, "ADMIN 계정의 재설정 레코드가 생성되어야 함"

    def test_admin_password_reset_confirm_changes_password(self, client, db):
        """ADMIN 계정은 user 탭 코드로 confirm 시 비밀번호가 변경된다."""
        from datetime import datetime, timedelta
        from unittest.mock import patch
        from models.email_verification import EmailVerification

        admin = User(
            email="admin2@gsm.hs.kr",
            hashed_password=get_password_hash("OldPass1!"),
            role=UserRole.ADMIN,
            is_active=True,
        )
        reset_record = EmailVerification(
            email="admin2@gsm.hs.kr",
            hashed_password="",
            code="123456",
            signup_role="password_reset:user",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            verified=False,
            attempts=0,
        )
        db.add_all([admin, reset_record])
        db.commit()
        db.refresh(admin)

        # SQLite는 timezone-naive datetime을 저장하므로 now_kst()도 naive로 패치
        with patch("api.routes.auth.now_kst", lambda: datetime.utcnow()):
            confirm = client.post(
                "/api/v1/auth/password-reset/confirm",
                json={
                    "email": "admin2@gsm.hs.kr",
                    "code": "123456",
                    "new_password": "NewPass2@",
                    "login_role": "user",
                },
            )
        assert confirm.status_code == 200, confirm.text

        db.expire_all()
        admin_reloaded = db.query(User).filter_by(id=admin.id).first()
        assert verify_password("NewPass2@", admin_reloaded.hashed_password)
