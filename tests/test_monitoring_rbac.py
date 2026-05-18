"""
모니터링 RBAC 테스트 (MONITORING-TC-01 ~ 04)
Proxmox 호출은 mock 처리, DB는 SQLite 인메모리 사용
"""
import pytest
from unittest.mock import MagicMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.database import Base, get_db
from api.dependencies import get_current_user
from models.user import User, UserRole
from models.server import Server
from models.vm import Vm

TEST_DB_URL = "sqlite:///./test_monitoring.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

MOCK_NODE_STATUS = {
    "cpu": 0.1,
    "memory": {"total": 8 * 1024**3, "used": 2 * 1024**3},
    "uptime": 3600,
}


def get_test_app():
    from api.routes import monitoring

    test_app = FastAPI()
    test_app.include_router(monitoring.router, prefix="/api/v1/monitoring")

    def override_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    test_app.dependency_overrides[get_db] = override_db
    return test_app


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
def server1(db):
    s = Server(
        name="node1", ip_address="192.168.0.1", port=8006,
        api_user="root@pam", api_password="pass", is_active=True,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


@pytest.fixture
def server2(db):
    s = Server(
        name="node2", ip_address="192.168.0.2", port=8006,
        api_user="root@pam", api_password="pass", is_active=True,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


@pytest.fixture
def admin_user(db):
    u = User(email="admin@gsm.hs.kr", hashed_password="h", role=UserRole.ADMIN, is_active=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture
def project_owner(db):
    u = User(email="po@gsm.hs.kr", hashed_password="h", role=UserRole.PROJECT_OWNER, is_active=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture
def regular_user(db):
    u = User(email="user@gsm.hs.kr", hashed_password="h", role=UserRole.USER, is_active=True)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def make_client_with_user(user):
    app = get_test_app()
    app.dependency_overrides[get_current_user] = lambda: user
    mock_px = MagicMock()
    mock_px.nodes.return_value.status.get.return_value = MOCK_NODE_STATUS
    return app, mock_px


class TestMonitoringRBAC:
    """MONITORING-TC-01~04: GET /monitoring/nodes RBAC 분기 검증"""

    def test_admin_sees_all_nodes(self, db, server1, server2, admin_user):
        """TC-01: ADMIN은 모든 활성 노드를 조회한다"""
        app, mock_px = make_client_with_user(admin_user)
        with patch("api.routes.monitoring.get_proxmox_for_server", return_value=mock_px):
            with TestClient(app) as c:
                res = c.get("/api/v1/monitoring/nodes")
        assert res.status_code == 200
        stats = res.json()["stats"]
        assert "node1" in stats
        assert "node2" in stats

    def test_project_owner_sees_all_nodes(self, db, server1, server2, project_owner):
        """TC-02: PROJECT_OWNER는 ADMIN과 동일하게 모든 활성 노드를 조회한다"""
        app, mock_px = make_client_with_user(project_owner)
        with patch("api.routes.monitoring.get_proxmox_for_server", return_value=mock_px):
            with TestClient(app) as c:
                res = c.get("/api/v1/monitoring/nodes")
        assert res.status_code == 200
        stats = res.json()["stats"]
        assert "node1" in stats
        assert "node2" in stats

    def test_user_sees_only_own_vm_nodes(self, db, server1, server2, regular_user):
        """TC-03: USER는 본인 VM이 위치한 노드만 조회된다"""
        vm = Vm(
            hypervisor_vmid=100, name="vm-test",
            server_id=server1.id, owner_id=regular_user.id,
        )
        db.add(vm)
        db.commit()

        app, mock_px = make_client_with_user(regular_user)
        with patch("api.routes.monitoring.get_proxmox_for_server", return_value=mock_px):
            with TestClient(app) as c:
                res = c.get("/api/v1/monitoring/nodes")
        assert res.status_code == 200
        stats = res.json()["stats"]
        assert "node1" in stats
        assert "node2" not in stats

    def test_user_with_no_vms_gets_empty_stats(self, db, server1, server2, regular_user):
        """TC-04: VM이 없는 USER 요청 시 빈 stats 반환"""
        app, _ = make_client_with_user(regular_user)
        with TestClient(app) as c:
            res = c.get("/api/v1/monitoring/nodes")
        assert res.status_code == 200
        data = res.json()
        assert data.get("stats") == {}
