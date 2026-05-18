"""IP 검증 및 네트워크 서비스 테스트"""
import pytest
from services.network_service import _validate_ip, calculate_ports


class TestValidateIp:
    """SSH 명령어 인젝션 방지를 위한 IP 검증"""

    def test_valid_ip(self):
        """정상 IP 통과"""
        assert _validate_ip("10.0.0.130") == "10.0.0.130"
        assert _validate_ip("192.168.1.1") == "192.168.1.1"
        assert _validate_ip("0.0.0.0") == "0.0.0.0"
        assert _validate_ip("255.255.255.255") == "255.255.255.255"

    def test_command_injection_semicolon(self):
        """세미콜론 인젝션 차단"""
        with pytest.raises(ValueError, match="잘못된 IP 형식"):
            _validate_ip("10.0.0.1; rm -rf /")

    def test_command_injection_pipe(self):
        """파이프 인젝션 차단"""
        with pytest.raises(ValueError, match="잘못된 IP 형식"):
            _validate_ip("10.0.0.1 | cat /etc/passwd")

    def test_command_injection_backtick(self):
        """백틱 인젝션 차단"""
        with pytest.raises(ValueError, match="잘못된 IP 형식"):
            _validate_ip("`whoami`")

    def test_command_injection_dollar(self):
        """$() 인젝션 차단"""
        with pytest.raises(ValueError, match="잘못된 IP 형식"):
            _validate_ip("$(cat /etc/shadow)")

    def test_command_injection_newline(self):
        """개행문자 인젝션 차단"""
        with pytest.raises(ValueError, match="잘못된 IP 형식"):
            _validate_ip("10.0.0.1\nrm -rf /")

    def test_invalid_octet_range(self):
        """옥텟 범위 초과"""
        with pytest.raises(ValueError, match="잘못된 IP 범위"):
            _validate_ip("10.0.0.999")

    def test_invalid_format(self):
        """형식 오류"""
        with pytest.raises(ValueError):
            _validate_ip("not-an-ip")
        with pytest.raises(ValueError):
            _validate_ip("")
        with pytest.raises(ValueError):
            _validate_ip("10.0.0")

    def test_negative_octet(self):
        """음수 옥텟"""
        with pytest.raises(ValueError):
            _validate_ip("10.0.0.-1")


class TestCalculatePorts:
    """포트 계산"""

    def test_basic_calculation(self):
        """기본 포트 계산"""
        ports = calculate_ports(21000, 101)
        assert ports["ssh"] == 21101      # 21000 + 0 + 101
        assert ports["svc1"] == 22101     # 21000 + 1000 + 101
        assert ports["svc2"] == 23101     # 21000 + 2000 + 101

    def test_different_base_port(self):
        """다른 base_port"""
        ports = calculate_ports(30000, 200)
        assert ports["ssh"] == 30200
        assert ports["svc1"] == 31200
        assert ports["svc2"] == 32200
