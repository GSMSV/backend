"""
Domain 3: 입력 검증 & 스키마 테스트 (VAL-TC-01 ~ VAL-TC-12)

스냅샷 이름, VM 액션, 방화벽 규칙, 아바타 업로드 검증.
"""
import pytest
from pydantic import ValidationError

from schemas.vm_schema import VMAction, VMActionType, SnapshotCreateRequest
from schemas.fw_schema import FirewallRule


# ── VAL-TC-01/02: 스냅샷 이름 검증 ──────────────────────────

class TestSnapshotNameValidation:
    """SnapshotCreateRequest 스키마 기반 스냅샷 이름 검증"""

    def test_korean_name_rejected(self):
        """VAL-TC-01: 한글 스냅샷 이름 거부"""
        with pytest.raises(ValidationError):
            SnapshotCreateRequest(name="테스트스냅샷")

    def test_valid_name_accepted(self):
        """VAL-TC-02: 정상 스냅샷 이름 통과"""
        req = SnapshotCreateRequest(name="valid-snap")
        assert req.name == "valid-snap"

    def test_path_traversal_rejected(self):
        """VAL-TC-03: 경로 순회 공격 거부"""
        with pytest.raises(ValidationError):
            SnapshotCreateRequest(name="../../../etc/passwd")

    def test_dash_start_rejected(self):
        """대시로 시작 거부"""
        with pytest.raises(ValidationError):
            SnapshotCreateRequest(name="-invalid")

    def test_number_start_rejected(self):
        """숫자로 시작 거부 — Proxmox 식별자 규칙"""
        with pytest.raises(ValidationError):
            SnapshotCreateRequest(name="1snap")

    def test_auto_daily_prefix_accepted(self):
        """auto-daily 프리픽스 통과"""
        req = SnapshotCreateRequest(name="auto-daily-20260409")
        assert req.name == "auto-daily-20260409"


# ── VAL-TC-04/05: VMAction Enum 검증 ─────────────────────────

class TestVMActionValidation:
    """VMAction.action Enum 검증"""

    def test_invalid_action_rejected(self):
        """VAL-TC-04: 유효하지 않은 액션 거부"""
        with pytest.raises(ValidationError):
            VMAction(action="format_disk")

    def test_valid_actions(self):
        """VAL-TC-05: 유효한 액션 통과"""
        for action in ["start", "stop", "shutdown", "reboot"]:
            vm_action = VMAction(action=action)
            assert vm_action.action == action

    def test_action_enum_values(self):
        """Enum 값 목록 확인"""
        expected = {"start", "stop", "shutdown", "reboot"}
        actual = {e.value for e in VMActionType}
        assert actual == expected


# ── VAL-TC-06~10: FirewallRule 검증 ──────────────────────────

class TestFirewallRuleValidation:
    """FirewallRule 필드 검증"""

    def test_invalid_action_rejected(self):
        """VAL-TC-06: 유효하지 않은 action 거부"""
        with pytest.raises(ValidationError):
            FirewallRule(action="EXEC")

    def test_valid_dport(self):
        """VAL-TC-07: 유효한 포트 통과"""
        rule = FirewallRule(dport="80")
        assert rule.dport == "80"

    def test_invalid_dport_out_of_range(self):
        """VAL-TC-08: 범위 초과 포트 거부"""
        with pytest.raises(ValidationError):
            FirewallRule(dport="99999")

    def test_sql_injection_source_rejected(self):
        """VAL-TC-09: SQL 인젝션 시도 거부"""
        with pytest.raises(ValidationError):
            FirewallRule(source="'; DROP TABLE;--")

    def test_valid_port_range_and_cidr(self):
        """VAL-TC-10: 포트 범위 + CIDR 통과"""
        rule = FirewallRule(dport="80:443", source="10.0.0.0/24")
        assert rule.dport == "80:443"
        assert rule.source == "10.0.0.0/24"

    def test_valid_actions(self):
        """유효한 action 값들"""
        for action in ["ACCEPT", "DROP", "REJECT"]:
            rule = FirewallRule(action=action)
            assert rule.action == action

    def test_valid_protos(self):
        """유효한 proto 값들"""
        for proto in ["tcp", "udp", "icmp"]:
            rule = FirewallRule(proto=proto)
            assert rule.proto == proto

    def test_invalid_proto_rejected(self):
        """유효하지 않은 proto 거부"""
        with pytest.raises(ValidationError):
            FirewallRule(proto="gre")

    def test_invalid_type_rejected(self):
        """유효하지 않은 type 거부"""
        with pytest.raises(ValidationError):
            FirewallRule(type="forward")

    def test_dport_zero_rejected(self):
        """포트 0 거부"""
        with pytest.raises(ValidationError):
            FirewallRule(dport="0")

    def test_invalid_cidr_prefix(self):
        """CIDR 프리픽스 /33 거부"""
        with pytest.raises(ValidationError):
            FirewallRule(source="10.0.0.0/33")

    def test_invalid_ip_octet(self):
        """IP 옥텟 256 거부"""
        with pytest.raises(ValidationError):
            FirewallRule(source="256.0.0.1")

    def test_dest_validation(self):
        """dest 필드도 IP 검증"""
        rule = FirewallRule(dest="192.168.1.1")
        assert rule.dest == "192.168.1.1"

        with pytest.raises(ValidationError):
            FirewallRule(dest="not-an-ip")


# ── VAL-TC-11/12: 아바타 업로드 magic bytes 검증 ─────────────

class TestAvatarMagicBytes:
    """아바타 이미지 magic bytes 검증 로직"""

    def _check_magic(self, contents: bytes) -> bool:
        """auth.py의 magic bytes 검증 로직 재현"""
        return (
            contents[:3] == b'\xff\xd8\xff'
            or contents[:8] == b'\x89PNG\r\n\x1a\n'
            or (contents[:4] == b'RIFF' and contents[8:12] == b'WEBP')
        )

    def test_exe_disguised_as_png_rejected(self):
        """VAL-TC-11: .exe를 .png로 위장 — magic bytes 불일치"""
        exe_bytes = b'MZ' + b'\x00' * 100  # PE 파일 시그니처
        assert not self._check_magic(exe_bytes)

    def test_valid_jpeg(self):
        """VAL-TC-12: 유효한 JPEG"""
        jpeg_bytes = b'\xff\xd8\xff\xe0' + b'\x00' * 100
        assert self._check_magic(jpeg_bytes)

    def test_valid_png(self):
        """유효한 PNG"""
        png_bytes = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        assert self._check_magic(png_bytes)

    def test_valid_webp(self):
        """유효한 WebP"""
        webp_bytes = b'RIFF' + b'\x00' * 4 + b'WEBP' + b'\x00' * 100
        assert self._check_magic(webp_bytes)

    def test_empty_file_rejected(self):
        """빈 파일 거부"""
        assert not self._check_magic(b'')

    def test_random_bytes_rejected(self):
        """랜덤 바이트 거부"""
        assert not self._check_magic(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08')
