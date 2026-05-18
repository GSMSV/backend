"""DB 모델 테스트 (암호화 프로퍼티 포함)"""
from models.vm import Vm
from models.server import Server
from models.user import User
from core.security import get_password_hash


class TestVmModel:
    """VM 모델 암호화 프로퍼티"""

    def test_password_encrypted_in_db(self, db):
        """vm_password가 암호화되어 저장되는지 확인"""
        # 먼저 서버와 유저 생성
        server = Server(
            name="test-node", ip_address="10.0.0.1", port=8006,
            api_user="test@pve", api_password="testpass",
        )
        db.add(server)
        db.flush()

        user = User(email="test@gsm.hs.kr", hashed_password=get_password_hash("Pass1234!"))
        db.add(user)
        db.flush()

        vm = Vm(
            hypervisor_vmid=100, name="test-vm", server_id=server.id,
            owner_id=user.id, internal_ip="10.0.0.130",
        )
        vm.vm_password = "MySecret123!"
        db.add(vm)
        db.commit()

        # DB에서 직접 읽으면 암호화된 값
        assert vm._vm_password != "MySecret123!"
        assert vm._vm_password is not None
        # 프로퍼티로 읽으면 복호화된 값
        assert vm.vm_password == "MySecret123!"

    def test_password_none(self, db):
        """비밀번호 None 처리"""
        server = Server(
            name="test-node2", ip_address="10.0.0.2", port=8006,
            api_user="test@pve", api_password="testpass",
        )
        db.add(server)
        db.flush()

        vm = Vm(
            hypervisor_vmid=101, name="test-vm2", server_id=server.id,
        )
        vm.vm_password = None
        db.add(vm)
        db.commit()

        assert vm.vm_password is None


class TestServerModel:
    """Server 모델 암호화 프로퍼티"""

    def test_all_passwords_encrypted(self, db):
        """서버의 모든 비밀번호가 암호화되는지"""
        server = Server(
            name="enc-test", ip_address="10.0.0.1", port=8006,
            api_user="test@pve",
        )
        server.api_password = "api_secret"
        server.ssh_password = "ssh_secret"
        server.gateway_password = "gw_secret"
        db.add(server)
        db.commit()

        # 암호화된 값은 원문과 다름
        assert server._api_password != "api_secret"
        assert server._ssh_password != "ssh_secret"
        assert server._gateway_password != "gw_secret"

        # 프로퍼티로 읽으면 복호화
        assert server.api_password == "api_secret"
        assert server.ssh_password == "ssh_secret"
        assert server.gateway_password == "gw_secret"
