"""
이메일 발송 서비스 — SMTP를 통해 인증 코드를 전송합니다.
"""

import logging
import secrets
import string
import aiosmtplib
from email.message import EmailMessage
from core.config import settings

logger = logging.getLogger(__name__)


def generate_verification_code() -> str:
    """6자리 숫자 인증 코드를 생성합니다."""
    return "".join(secrets.choice(string.digits) for _ in range(6))


async def send_verification_email(to_email: str, code: str) -> bool:
    """
    인증 코드를 이메일로 발송합니다.
    성공 시 True, 실패 시 False를 반환합니다.
    """
    msg = EmailMessage()
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_USER}>"
    msg["To"] = to_email
    msg["Subject"] = f"[GSM SV] 이메일 인증 코드: {code}"

    html_body = f"""
    <div style="font-family: 'Apple SD Gothic Neo', 'Noto Sans KR', sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 24px;">
        <div style="text-align: center; margin-bottom: 32px;">
            <h1 style="font-size: 24px; font-weight: 700; color: #0c0d11; margin: 0;">GSM SV</h1>
            <p style="font-size: 14px; color: #64748b; margin-top: 4px;">IaaS Platform</p>
        </div>

        <div style="background: #f8fafc; border-radius: 16px; padding: 32px; text-align: center; border: 1px solid #e2e8f0;">
            <p style="font-size: 14px; color: #475569; margin: 0 0 20px;">
                회원가입을 완료하려면 아래 인증 코드를 입력해주세요.
            </p>
            <div style="font-size: 36px; font-weight: 700; letter-spacing: 8px; color: #0c0d11; font-family: 'JetBrains Mono', monospace; padding: 16px; background: white; border-radius: 12px; border: 1px solid #e2e8f0;">
                {code}
            </div>
            <p style="font-size: 12px; color: #94a3b8; margin-top: 20px;">
                이 코드는 {settings.VERIFICATION_CODE_EXPIRE_MINUTES}분 후 만료됩니다.
            </p>
        </div>

        <p style="font-size: 11px; color: #94a3b8; text-align: center; margin-top: 24px;">
            본인이 요청하지 않은 경우 이 이메일을 무시해주세요.
        </p>
    </div>
    """

    msg.set_content(
        f"GSM SV 인증 코드: {code}\n이 코드는 {settings.VERIFICATION_CODE_EXPIRE_MINUTES}분 후 만료됩니다."
    )
    msg.add_alternative(html_body, subtype="html")

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            start_tls=True,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
        )
        return True
    except Exception as e:
        logger.error(
            "[이메일 발송 실패] %s: %s", to_email[:3] + "***", e, exc_info=True
        )
        return False
