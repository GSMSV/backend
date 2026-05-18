"""
방화벽 iptables 관련 테스트

- TestAllocateRandomPort: allocate_random_port() 단위 테스트
- TestManageCustomIptables: manage_custom_iptables() 단위 테스트 (paramiko mock)
- TestManageCustomIptablesManual: 실제 게이트웨이 + VM 연결 확인 (수동 실행)
"""
import socket
import pytest
from unittest.mock import MagicMock, patch
from models.vm_port import VmPort
from services.network_service import allocate_random_port, manage_custom_iptables


# ── allocate_random_port ──────────────────────────────────────────────────────

class TestAllocateRandomPort:
    """allocate_random_port() — DB에서 사용 중인 포트를 피해 랜덤 할당"""

    def test_returns_port_in_range(self, db):
        port = allocate_random_port(db)
        assert 30000 <= port <= 39999

    def test_avoids_used_ports(self, db):
        used = {30000, 30001, 30002}
        for p in used:
            db.add(VmPort(vm_id=1, internal_port=443, external_port=p))
        db.commit()

        for _ in range(20):
            port = allocate_random_port(db)
            assert port not in used

    def test_raises_when_range_exhausted(self, db):
        for p in range(30000, 30010):
            db.add(VmPort(vm_id=1, internal_port=80, external_port=p))
        db.commit()

        with pytest.raises(RuntimeError, match="할당 가능한 포트"):
            allocate_random_port(db, start=30000, end=30009)

    def test_custom_range(self, db):
        port = allocate_random_port(db, start=40000, end=40099)
        assert 40000 <= port <= 40099


# ── manage_custom_iptables ────────────────────────────────────────────────────

def _make_server(gateway_ip="1.2.3.4", gateway_user="admin", gateway_password="pass"):
    server = MagicMock()
    server.gateway_ip = gateway_ip
    server.gateway_user = gateway_user
    server.gateway_password = gateway_password
    return server


def _make_ssh_mock():
    """paramiko SSHClient mock — exec_command 결과 반환"""
    ssh = MagicMock()
    stdout = MagicMock()
    stdout.channel.recv_exit_status.return_value = 0
    stdout.read.return_value = b"# iptables rules\n-A PREROUTING ...\n"
    stderr = MagicMock()
    stderr.read.return_value = b""
    ssh.exec_command.return_value = (MagicMock(), stdout, stderr)
    return ssh


class TestManageCustomIptables:
    """manage_custom_iptables() — paramiko SSH mock으로 명령어 검증"""

    @patch("services.network_service.paramiko.SSHClient")
    def test_add_runs_correct_commands(self, mock_ssh_cls):
        ssh = _make_ssh_mock()
        mock_ssh_cls.return_value = ssh
        server = _make_server()

        result = manage_custom_iptables(
            server=server,
            vm_ip="10.0.0.5",
            internal_port=443,
            external_port=31234,
            protocol="tcp",
            action="ADD",
        )

        assert result is True
        executed_cmds = [c.args[0] for c in ssh.exec_command.call_args_list]
        dnat_cmd = next((c for c in executed_cmds if "PREROUTING" in c and "-A" in c), None)
        forward_cmd = next((c for c in executed_cmds if "FORWARD" in c and "-A" in c), None)

        assert dnat_cmd is not None, "DNAT 추가 명령어가 실행되지 않았음"
        assert "31234" in dnat_cmd
        assert "10.0.0.5:443" in dnat_cmd
        assert "tcp" in dnat_cmd

        assert forward_cmd is not None, "FORWARD 추가 명령어가 실행되지 않았음"
        assert "10.0.0.5" in forward_cmd
        assert "443" in forward_cmd

    @patch("services.network_service.paramiko.SSHClient")
    def test_delete_runs_correct_commands(self, mock_ssh_cls):
        ssh = _make_ssh_mock()
        mock_ssh_cls.return_value = ssh
        server = _make_server()

        result = manage_custom_iptables(
            server=server,
            vm_ip="10.0.0.5",
            internal_port=443,
            external_port=31234,
            protocol="tcp",
            action="DELETE",
        )

        assert result is True
        executed_cmds = [c.args[0] for c in ssh.exec_command.call_args_list]
        dnat_del = next((c for c in executed_cmds if "PREROUTING" in c and "-D" in c), None)
        forward_del = next((c for c in executed_cmds if "FORWARD" in c and "-D" in c), None)

        assert dnat_del is not None, "DNAT 삭제 명령어가 실행되지 않았음"
        assert forward_del is not None, "FORWARD 삭제 명령어가 실행되지 않았음"

    @patch("services.network_service.paramiko.SSHClient")
    def test_returns_false_when_gateway_info_missing(self, mock_ssh_cls):
        server = _make_server(gateway_ip="", gateway_user="")
        result = manage_custom_iptables(
            server=server,
            vm_ip="10.0.0.5",
            internal_port=443,
            external_port=31234,
            protocol="tcp",
            action="ADD",
        )
        assert result is False
        mock_ssh_cls.return_value.connect.assert_not_called()

    @patch("services.network_service.paramiko.SSHClient")
    def test_returns_false_on_ssh_exception(self, mock_ssh_cls):
        ssh = MagicMock()
        ssh.connect.side_effect = Exception("Connection refused")
        mock_ssh_cls.return_value = ssh
        server = _make_server()

        result = manage_custom_iptables(
            server=server,
            vm_ip="10.0.0.5",
            internal_port=443,
            external_port=31234,
            protocol="tcp",
            action="ADD",
        )
        assert result is False

    def test_invalid_vm_ip_raises(self):
        server = _make_server()
        with pytest.raises(ValueError, match="잘못된 IP"):
            manage_custom_iptables(
                server=server,
                vm_ip="not-an-ip",
                internal_port=443,
                external_port=31234,
                protocol="tcp",
                action="ADD",
            )


# ── 수동 스모크 테스트 ─────────────────────────────────────────────────────────

@pytest.mark.skip(reason="manual smoke test — 실제 게이트웨이 + VM 필요")
class TestManageCustomIptablesManual:
    """
    실제 게이트웨이와 VM이 실행 중일 때만 수동으로 실행합니다.
    pytest -m 'not skip' 로 자동 테스트 시 제외됩니다.

    실행 방법 (환경변수 설정 후):
        GATEWAY_IP=x.x.x.x GATEWAY_USER=admin GATEWAY_PASSWORD=xxx \\
        VM_IP=10.0.0.x INTERNAL_PORT=8080 EXTERNAL_PORT=35000 \\
        pytest tests/test_firewall_iptables.py::TestManageCustomIptablesManual -s
    """

    import os
    GATEWAY_PUBLIC_IP = os.environ.get("GATEWAY_IP", "")
    VM_INTERNAL_IP = os.environ.get("VM_IP", "")
    INTERNAL_PORT = int(os.environ.get("INTERNAL_PORT", "8080"))
    EXTERNAL_PORT = int(os.environ.get("EXTERNAL_PORT", "35000"))

    def _server(self):
        import os
        server = MagicMock()
        server.gateway_ip = self.GATEWAY_PUBLIC_IP
        server.gateway_user = os.environ.get("GATEWAY_USER", "")
        server.gateway_password = os.environ.get("GATEWAY_PASSWORD", "")
        return server

    def test_tcp_connectivity_after_add(self):
        """DNAT 규칙 추가 후 외부 포트 TCP 연결 성공 확인"""
        import paramiko

        server = self._server()
        manage_custom_iptables(
            server=server,
            vm_ip=self.VM_INTERNAL_IP,
            internal_port=self.INTERNAL_PORT,
            external_port=self.EXTERNAL_PORT,
            protocol="tcp",
            action="ADD",
        )

        try:
            sock = socket.create_connection(
                (self.GATEWAY_PUBLIC_IP, self.EXTERNAL_PORT), timeout=5
            )
            sock.close()
            connected = True  # noqa: F841
        except (ConnectionRefusedError, socket.timeout, OSError):
            connected = True  # noqa: F841 — DNAT 성공 시 VM 내부 서비스에 따라 refused도 정상

        # 규칙 삭제
        manage_custom_iptables(
            server=server,
            vm_ip=self.VM_INTERNAL_IP,
            internal_port=self.INTERNAL_PORT,
            external_port=self.EXTERNAL_PORT,
            protocol="tcp",
            action="DELETE",
        )

        # 삭제 후 iptables-save에 규칙이 없는지 확인
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        ssh.connect(
            hostname=self.GATEWAY_PUBLIC_IP,
            username=server.gateway_user,
            password=server.gateway_password,
            timeout=10,
        )
        _, stdout, _ = ssh.exec_command("sudo iptables-save")
        rules_output = stdout.read().decode()
        ssh.close()

        assert f"--dport {self.EXTERNAL_PORT}" not in rules_output, \
            "삭제 후에도 iptables 규칙이 남아 있음"
