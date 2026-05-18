"""암호화/복호화 모듈 테스트"""
from core.encryption import encrypt, decrypt


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        """암호화 후 복호화하면 원본과 동일해야 함"""
        original = "gsmserver@Admin#1234"
        encrypted = encrypt(original)
        assert encrypted != original  # 암호화되었는지
        assert decrypt(encrypted) == original  # 복호화 결과 일치

    def test_encrypt_produces_different_output(self):
        """같은 값을 두 번 암호화하면 다른 결과 (Fernet은 timestamp 포함)"""
        value = "testpassword"
        enc1 = encrypt(value)
        enc2 = encrypt(value)
        assert enc1 != enc2  # 매번 다른 암호문
        assert decrypt(enc1) == decrypt(enc2) == value  # 복호화는 동일

    def test_encrypt_empty_returns_empty(self):
        """빈 문자열은 암호화하지 않고 그대로 반환"""
        assert encrypt("") == ""
        assert encrypt(None) is None

    def test_decrypt_empty_returns_empty(self):
        """빈 문자열은 복호화하지 않고 그대로 반환"""
        assert decrypt("") == ""
        assert decrypt(None) is None

    def test_special_characters(self):
        """특수문자 포함된 비밀번호 처리"""
        passwords = [
            "p@ss!w0rd#$%",
            "한글비밀번호123!",
            "emoji🔑key",
            'quo"ted\'pass',
        ]
        for pw in passwords:
            assert decrypt(encrypt(pw)) == pw

    def test_long_string(self):
        """긴 문자열 암호화/복호화"""
        long_str = "A" * 10000
        assert decrypt(encrypt(long_str)) == long_str
