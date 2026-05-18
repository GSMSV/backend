"""
Domain 1: VM 라이프사이클 테스트 (VM-TC-01 ~ VM-TC-14)

Proxmox/SSH/iptables는 mock으로 대체, DB는 SQLite 인메모리 사용.
"""
import threading
import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.database import Base
from models.user import User, UserRole
from models.server import Server
from models.vm import Vm
from models.notification import Notification
from schemas.vm_schema import VMCreate, VMTier
from services.vm_service import (
    create_vm,
    delete_vm,
    _allocate_internal_ip,
    _get_next_vmid,
)
from services.network_service import calculate_ports, manage_iptables
from services.mon_service import update_server_stats

# ── 테스트용 DB 엔진 ──────────────────────────────────────────

TEST_DB_URL = "sqlite:///./test_vm_lifecycle.db"
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


# ── 공용 Fixture ──────────────────────────────────────────────

@pytest.fixture
def user(db):
    u = User(
        email="testuser@gsm.hs.kr",
        hashed_password="hashed",
        role=UserRole.USER,
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture
def admin_user(db):
    u = User(
        email="admin@gsm.hs.kr",
        hashed_password="hashed",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture
def server(db):
    s = Server(
        name="test-node",
        ip_address="192.168.1.10",
        port=8006,
        api_user="root@pam",
        api_password="password",
        ssh_user="root",
        ssh_password="sshpass",
        is_active=True,
        gateway_ip="192.168.1.1",
        gateway_user="admin",
        gateway_password="gwpass",
        base_port=21000,
        last_free_ram_mb=16000,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _make_mock_proxmox(vmid=200):
    """Proxmox API mock 생성"""
    proxmox = MagicMock()
    proxmox.cluster.nextid.get.return_value = str(vmid)
    node = proxmox.nodes.return_value
    node.qemu.return_value.clone.post.return_value = None
    node.qemu.return_value.config.get.return_value = {"name": "test"}
    node.qemu.return_value.config.put.return_value = None
    node.qemu.return_value.resize.put.return_value = None
    node.qemu.return_value.status.start.post.return_value = None
    node.qemu.return_value.status.current.get.return_value = {"status": "running"}
    node.qemu.return_value.status.stop.post.return_value = None
    node.qemu.return_value.delete.return_value = None
    return proxmox


# ── VM-TC-01: 동시 VM 생성 시 서로 다른 IP 할당 ──────────────

class TestConcurrentVMCreation:
    """VM-TC-01/03: 동시 VM 생성 시 IP 충돌 방지"""

    def test_concurrent_ip_allocation_no_duplicates(self, db, user, server):
        """VM-TC-01: 같은 유저가 아닌 여러 세션에서 동시 IP 할당 시 중복 없음"""
        allocated = []
        errors = []

        def allocate():
            session = TestSession()
            try:
                ip = _allocate_internal_ip(session)
                # 실제 VM을 DB에 추가해야 다음 할당에서 중복 방지
                vm = Vm(
                    hypervisor_vmid=100 + len(allocated),
                    name=f"test-{threading.current_thread().name}",
                    server_id=server.id,
                    owner_id=user.id,
                    internal_ip=ip,
                )
                session.add(vm)
                session.commit()
                allocated.append(ip)
            except Exception as e:
                errors.append(str(e))
            finally:
                session.close()

        threads = [threading.Thread(target=allocate) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 중복 IP가 없어야 함
        assert len(allocated) + len(errors) == 5
        assert len(set(allocated)) == len(allocated), f"중복 IP 발견: {allocated}"


# ── VM-TC-02: IP 풀 소진 시 507 반환 ─────────────────────────

class TestIPExhaustion:
    """VM-TC-02: 모든 IP가 사용 중일 때 적절한 에러"""

    @patch("services.vm_service.settings")
    def test_no_available_ip_raises_507(self, mock_settings, db, user, server):
        """할당 가능한 IP가 없으면 HTTP 507"""
        mock_settings.INTERNAL_SUBNET = "10.0.0"
        mock_settings.INTERNAL_IP_START = 100
        mock_settings.INTERNAL_IP_END = 102  # 100, 101, 102 총 3개만

        # 3개 IP 모두 사용 중으로 등록
        for i in range(100, 103):
            db.add(Vm(
                hypervisor_vmid=i,
                name=f"vm-{i}",
                server_id=server.id,
                owner_id=user.id,
                internal_ip=f"10.0.0.{i}",
            ))
        db.commit()

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _allocate_internal_ip(db)
        assert exc_info.value.status_code == 507


# ── VM-TC-04/05: 생성 실패 시 정리(cleanup) ─────────────────

class TestVMCreationCleanup:
    """VM-TC-04/05: VM 생성 중 실패 시 Proxmox VM + iptables 정리"""

    @patch("services.vm_service._delete_snippet")
    @patch("services.vm_service._upload_snippet")
    @patch("services.vm_service.manage_iptables", return_value=True)
    @patch("services.vm_service.get_proxmox_for_server")
    @patch("services.vm_service._allocate_internal_ip", return_value="10.0.0.100")
    def test_boot_failure_triggers_cleanup(
        self, mock_alloc, mock_proxmox_fn, mock_iptables,
        mock_upload, mock_del_snippet, db, user, server
    ):
        """VM-TC-04: 부팅 실패 시 Proxmox 삭제 + iptables DELETE + DB 롤백"""
        proxmox = _make_mock_proxmox(200)
        mock_proxmox_fn.return_value = proxmox
        # 부팅(start) 시 에러 발생
        proxmox.nodes.return_value.qemu.return_value.status.start.post.side_effect = Exception("boot failed")

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            create_vm(db, user, VMTier.MICRO, node_name="test-node")

        assert exc_info.value.status_code == 500
        # Proxmox VM 삭제 시도 확인
        proxmox.nodes.return_value.qemu.return_value.delete.assert_called()
        # iptables DELETE 호출 확인 (cleanup)
        calls = mock_iptables.call_args_list
        assert any(c.kwargs.get("action") == "DELETE" or (len(c.args) > 3 and c.args[3] == "DELETE")
                   for c in calls), "iptables DELETE가 호출되어야 합니다"

    @patch("services.vm_service._delete_snippet")
    @patch("services.vm_service._upload_snippet")
    @patch("services.vm_service.manage_iptables", return_value=False)
    @patch("services.vm_service.get_proxmox_for_server")
    @patch("services.vm_service._allocate_internal_ip", return_value="10.0.0.100")
    def test_iptables_failure_triggers_cleanup(
        self, mock_alloc, mock_proxmox_fn, mock_iptables,
        mock_upload, mock_del_snippet, db, user, server
    ):
        """VM-TC-05: manage_iptables(ADD) 반환 False → RuntimeError → cleanup"""
        proxmox = _make_mock_proxmox(200)
        mock_proxmox_fn.return_value = proxmox

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            create_vm(db, user, VMTier.MICRO, node_name="test-node")

        assert exc_info.value.status_code == 500
        # Proxmox VM 삭제 시도
        proxmox.nodes.return_value.qemu.return_value.delete.assert_called()
        # DB에 VM이 남아있지 않아야 함
        assert db.query(Vm).count() == 0


# ── VM-TC-06: iptables 개별 명령 실패 추적 ────────────────────

class TestIptablesErrorTracking:
    """VM-TC-06: iptables 개별 명령 stderr → False 반환"""

    @patch("services.network_service.settings")
    @patch("services.network_service.paramiko.SSHClient")
    def test_stderr_causes_false_return(self, mock_ssh_class, mock_settings, server):
        """개별 iptables 명령이 stderr 출력 시 False 반환"""
        mock_settings.GATEWAY_PUBLIC_IP = "1.2.3.4"

        mock_ssh = MagicMock()
        mock_ssh_class.return_value = mock_ssh

        # exec_command가 stderr를 반환하도록 설정
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b"iptables: Bad rule"
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        result = manage_iptables(server, 200, "10.0.0.100", action="ADD")
        assert result is False


# ── VM-TC-07: VM 삭제 시 Gateway SSH 불가 ─────────────────────

class TestVMDeletionIptablesFailure:
    """VM-TC-07: 삭제 시 iptables 실패해도 DB 레코드는 삭제됨"""

    @patch("services.vm_service.manage_iptables", return_value=False)
    @patch("services.vm_service.get_proxmox_for_server")
    def test_delete_succeeds_despite_iptables_failure(
        self, mock_proxmox_fn, mock_iptables, db, user, server
    ):
        """Gateway SSH 불가 시에도 VM DB 레코드 삭제 + ERROR 로그"""
        proxmox = _make_mock_proxmox()
        mock_proxmox_fn.return_value = proxmox

        vm = Vm(
            hypervisor_vmid=200,
            name="test-vm",
            server_id=server.id,
            owner_id=user.id,
            internal_ip="10.0.0.100",
        )
        db.add(vm)
        db.commit()
        db.refresh(vm)

        delete_vm(db, vm)
        db.commit()

        # DB에서 VM 삭제 확인
        assert db.query(Vm).filter(Vm.id == vm.id).first() is None
        # 알림 생성 확인
        notif = db.query(Notification).filter(Notification.user_id == user.id).first()
        assert notif is not None


# ── VM-TC-08/09/10: VM 이름 검증 ─────────────────────────────

class TestVMNameValidation:
    """VM-TC-08/09/10: VMCreate.name 필드 검증"""

    def test_command_injection_rejected(self):
        """VM-TC-08: 명령어 인젝션 시도 → 422"""
        with pytest.raises(ValueError):
            VMCreate(tier=VMTier.MICRO, name="test; rm -rf /")

    def test_too_long_name_rejected(self):
        """VM-TC-09: 41자 이상 이름 → 422"""
        with pytest.raises(ValueError):
            VMCreate(tier=VMTier.MICRO, name="a" * 41)

    def test_valid_name_accepted(self):
        """VM-TC-10: 정상 이름 통과"""
        vm = VMCreate(tier=VMTier.MICRO, name="valid-name_1")
        assert vm.name == "valid-name_1"

    def test_none_name_accepted(self):
        """이름 미지정 시 자동 생성 (None 통과)"""
        vm = VMCreate(tier=VMTier.MICRO, name=None)
        assert vm.name is None

    def test_name_starting_with_dash_rejected(self):
        """대시로 시작하는 이름 거부"""
        with pytest.raises(ValueError):
            VMCreate(tier=VMTier.MICRO, name="-invalid")

    def test_korean_name_rejected(self):
        """한글 이름 거부"""
        with pytest.raises(ValueError):
            VMCreate(tier=VMTier.MICRO, name="테스트VM")

    def test_name_with_spaces_rejected(self):
        """공백 포함 이름 거부"""
        with pytest.raises(ValueError):
            VMCreate(tier=VMTier.MICRO, name="my vm")


# ── VM-TC-11: Proxmox 오프라인 시 update_server_stats ─────────

class TestMonServiceFailure:
    """VM-TC-11: Proxmox 접속 실패 시 DB 값 유지"""

    @patch("services.mon_service.get_proxmox_for_server")
    def test_failure_returns_none_keeps_db_value(self, mock_proxmox, db, server):
        """Proxmox 실패 시 None 반환, last_free_ram_mb 이전 값 유지"""
        server.last_free_ram_mb = 8000
        db.commit()

        mock_proxmox.side_effect = Exception("connection refused")

        result = update_server_stats(db, server)
        assert result is None
        # DB 값이 변경되지 않아야 함
        db.refresh(server)
        assert server.last_free_ram_mb == 8000


# ── VM-TC-12: MAX_VMS_PER_USER 한도 초과 ─────────────────────

class TestVMCountLimit:
    """VM-TC-12: 최대 VM 개수 초과 시 409"""

    @patch("services.vm_service.settings")
    def test_exceeds_max_vms(self, mock_settings, db, user, server):
        """MAX_VMS_PER_USER 도달 시 HTTP 409"""
        mock_settings.MAX_VMS_PER_USER = 2

        # 이미 2개 VM 존재
        for i in range(2):
            db.add(Vm(
                hypervisor_vmid=200 + i,
                name=f"vm-{i}",
                server_id=server.id,
                owner_id=user.id,
                internal_ip=f"10.0.0.{100 + i}",
            ))
        db.commit()

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            create_vm(db, user, VMTier.MICRO, node_name="test-node")
        assert exc_info.value.status_code == 409


# ── VM-TC-13: 정상 VM 생성 흐름 ──────────────────────────────

class TestVMCreationHappyPath:
    """VM-TC-13: 정상 경로 VM 생성"""

    @patch("services.vm_service._delete_snippet")
    @patch("services.vm_service._upload_snippet")
    @patch("services.vm_service.manage_iptables", return_value=True)
    @patch("services.vm_service.get_proxmox_for_server")
    @patch("services.vm_service._allocate_internal_ip", return_value="10.0.0.100")
    def test_create_vm_returns_expected_fields(
        self, mock_alloc, mock_proxmox_fn, mock_iptables,
        mock_upload, mock_del_snippet, db, user, server
    ):
        """생성 결과에 vmid, name, internal_ip, ssh 자격증명 포함"""
        proxmox = _make_mock_proxmox(200)
        mock_proxmox_fn.return_value = proxmox

        result = create_vm(db, user, VMTier.MICRO, node_name="test-node")

        assert result["success"] is True
        assert result["vmid"] == 200
        assert result["internal_ip"] == "10.0.0.100"
        assert "ssh_user" in result
        assert "ssh_password" in result
        assert result["tier"] == "micro"

        # DB에 VM 레코드 생성 확인
        vm = db.query(Vm).filter(Vm.hypervisor_vmid == 200).first()
        assert vm is not None
        assert vm.owner_id == user.id
        assert vm.internal_ip == "10.0.0.100"

        # 알림 생성 확인
        notif = db.query(Notification).filter(
            Notification.user_id == user.id,
            Notification.type == "success",
        ).first()
        assert notif is not None


# ── VM-TC-14: 정상 VM 삭제 흐름 ──────────────────────────────

class TestVMDeletionHappyPath:
    """VM-TC-14: 정상 경로 VM 삭제"""

    @patch("services.vm_service.manage_iptables", return_value=True)
    @patch("services.vm_service.get_proxmox_for_server")
    def test_delete_vm_full_flow(self, mock_proxmox_fn, mock_iptables, db, user, server):
        """정지 → Proxmox 삭제 → iptables DELETE → DB 삭제 → 알림"""
        proxmox = _make_mock_proxmox()
        mock_proxmox_fn.return_value = proxmox

        vm = Vm(
            hypervisor_vmid=200,
            name="test-vm",
            server_id=server.id,
            owner_id=user.id,
            internal_ip="10.0.0.100",
        )
        db.add(vm)
        db.commit()
        db.refresh(vm)

        delete_vm(db, vm)
        db.commit()

        # DB 삭제 확인
        assert db.query(Vm).filter(Vm.hypervisor_vmid == 200).first() is None
        # iptables DELETE 호출 확인
        mock_iptables.assert_called_once()
        call_args = mock_iptables.call_args
        assert call_args.kwargs.get("action") == "DELETE" or call_args[0][3] == "DELETE"
        # Proxmox stop + delete 호출 확인
        proxmox.nodes.return_value.qemu.return_value.status.stop.post.assert_called()
        proxmox.nodes.return_value.qemu.return_value.delete.assert_called()
        # 알림 생성 확인
        notif = db.query(Notification).filter(Notification.user_id == user.id).first()
        assert notif is not None


# ── 포트 범위 검증 ────────────────────────────────────────────

class TestPortCalculationValidation:
    """calculate_ports 포트 범위 검증"""

    def test_valid_ports(self):
        ports = calculate_ports(21000, 100)
        assert ports["ssh"] == 21100
        assert ports["svc1"] == 22100
        assert ports["svc2"] == 23100

    def test_overflow_raises_error(self):
        """포트 65535 초과 시 ValueError"""
        with pytest.raises(ValueError, match="유효 범위"):
            calculate_ports(60000, 10000)

    def test_zero_base_port(self):
        """base_port=0 + vmid=0 → 포트 0은 유효 범위 아님 (1~65535)"""
        with pytest.raises(ValueError):
            calculate_ports(0, 0)


# ── VMID 재시도 로직 ──────────────────────────────────────────

class TestVMIDRetry:
    """_get_next_vmid fallback 로직"""

    def test_nextid_api_success(self):
        """정상: cluster.nextid 반환"""
        proxmox = MagicMock()
        proxmox.cluster.nextid.get.return_value = "300"
        assert _get_next_vmid(proxmox, "node1") == 300

    def test_nextid_api_failure_fallback(self):
        """nextid 실패 시 기존 VM 목록에서 max+1"""
        proxmox = MagicMock()
        proxmox.cluster.nextid.get.side_effect = Exception("API error")
        proxmox.nodes.return_value.qemu.get.return_value = [
            {"vmid": 100}, {"vmid": 200}, {"vmid": 150}
        ]
        assert _get_next_vmid(proxmox, "node1") == 201

    def test_nextid_api_failure_empty_node(self):
        """nextid 실패 + 노드에 VM 없음 → 100"""
        proxmox = MagicMock()
        proxmox.cluster.nextid.get.side_effect = Exception("API error")
        proxmox.nodes.return_value.qemu.get.return_value = []
        assert _get_next_vmid(proxmox, "node1") == 100
