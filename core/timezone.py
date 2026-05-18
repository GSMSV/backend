"""KST 시간대 유틸리티"""

from datetime import datetime, timezone, timedelta

KST = timezone(timedelta(hours=9))


def now_kst() -> datetime:
    """현재 한국 시간을 반환합니다."""
    return datetime.now(KST)
