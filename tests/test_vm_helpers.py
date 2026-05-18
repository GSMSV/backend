"""VM 서비스 헬퍼 함수 테스트"""
import string
from unittest.mock import MagicMock
from services.vm_service import _generate_password, _generate_vm_name


class TestGeneratePassword:
    """VM 비밀번호 생성"""

    def test_default_length(self):
        """기본 길이 8자"""
        pw = _generate_password()
        assert len(pw) == 8

    def test_custom_length(self):
        """커스텀 길이"""
        pw = _generate_password(16)
        assert len(pw) == 16

    def test_contains_letter(self):
        """영문 포함"""
        for _ in range(50):
            pw = _generate_password()
            assert any(c in string.ascii_letters for c in pw)

    def test_contains_digit(self):
        """숫자 포함"""
        for _ in range(50):
            pw = _generate_password()
            assert any(c in string.digits for c in pw)

    def test_contains_special(self):
        """특수문자 포함"""
        for _ in range(50):
            pw = _generate_password()
            assert any(c in "!@#$%&*" for c in pw)

    def test_unique_passwords(self):
        """매번 다른 비밀번호 생성"""
        passwords = {_generate_password() for _ in range(100)}
        assert len(passwords) > 90  # 거의 모두 고유해야 함


class TestGenerateVmName:
    """VM 이름 생성"""

    def _mock_user(self, email="testuser@gsm.hs.kr"):
        user = MagicMock()
        user.email = email
        return user

    def test_custom_name(self):
        """커스텀 이름 지정 시"""
        user = self._mock_user()
        full_name, display_name = _generate_vm_name(user, "micro", "myvm")
        assert full_name == "testuser-myvm"
        assert display_name == "myvm"

    def test_auto_name(self):
        """자동 이름 생성 시"""
        user = self._mock_user()
        full_name, display_name = _generate_vm_name(user, "micro")
        assert full_name.startswith("testuser-micro-")
        assert display_name.startswith("micro-")
        assert len(display_name.split("-")[-1]) == 4  # suffix 4자

    def test_email_prefix_extraction(self):
        """이메일에서 사용자 이름 추출"""
        user = self._mock_user("s24019@gsm.hs.kr")
        full_name, _ = _generate_vm_name(user, "small", "test")
        assert full_name == "s24019-test"

    def test_auto_name_uniqueness(self):
        """자동 이름은 매번 달라야 함"""
        user = self._mock_user()
        names = {_generate_vm_name(user, "micro")[0] for _ in range(50)}
        assert len(names) > 40
