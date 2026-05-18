"""비밀번호 검증 로직 테스트"""
import pytest
from pydantic import ValidationError
from schemas.user_schema import UserCreate, ProjectSignupRequest, PasswordResetConfirm


class TestPasswordValidation:
    """회원가입/비밀번호 변경 시 비밀번호 강도 검증"""

    def test_valid_password(self):
        """정상 비밀번호: 8자 이상 + 영문 + 숫자 + 특수기호"""
        user = UserCreate(email="test@gsm.hs.kr", password="Pass1234!")
        assert user.password == "Pass1234!"

    def test_too_short(self):
        """7자 비밀번호는 거부"""
        with pytest.raises(ValidationError, match="비밀번호는 8자 이상"):
            UserCreate(email="test@gsm.hs.kr", password="Pa1!aaa")

    def test_no_number(self):
        """숫자 없는 비밀번호 거부"""
        with pytest.raises(ValidationError, match="비밀번호는 8자 이상"):
            UserCreate(email="test@gsm.hs.kr", password="Password!")

    def test_no_special_char(self):
        """특수기호 없는 비밀번호 거부"""
        with pytest.raises(ValidationError, match="비밀번호는 8자 이상"):
            UserCreate(email="test@gsm.hs.kr", password="Password1")

    def test_no_letter(self):
        """영문 없는 비밀번호 거부"""
        with pytest.raises(ValidationError, match="비밀번호는 8자 이상"):
            UserCreate(email="test@gsm.hs.kr", password="12345678!")

    def test_numbers_only(self):
        """숫자만으로 된 비밀번호 거부"""
        with pytest.raises(ValidationError):
            UserCreate(email="test@gsm.hs.kr", password="12345678")

    def test_project_signup_password(self):
        """프로젝트 오너 가입도 동일한 검증 적용"""
        with pytest.raises(ValidationError, match="비밀번호는 8자 이상"):
            ProjectSignupRequest(
                email="test@gsm.hs.kr",
                password="weak",
                project_name="test",
                reason="test",
            )

    def test_password_reset_validation(self):
        """비밀번호 재설정도 동일한 검증 적용"""
        with pytest.raises(ValidationError, match="비밀번호는 8자 이상"):
            PasswordResetConfirm(
                email="test@gsm.hs.kr",
                code="123456",
                new_password="weak",
            )

    def test_various_valid_passwords(self):
        """다양한 유효 비밀번호"""
        valid_passwords = [
            "Abcd1234!",
            "a1!aaaaa",
            "MyP@ssw0rd",
            "Test123$%^",
            "Complex!1pw",
        ]
        for pw in valid_passwords:
            user = UserCreate(email="test@gsm.hs.kr", password=pw)
            assert user.password == pw

    def test_invalid_email(self):
        """이메일 형식 검증"""
        with pytest.raises(ValidationError):
            UserCreate(email="not-an-email", password="Pass1234!")
