"""
DataGSM OpenAPI를 통해 학생/프로젝트 정보를 조회하는 서비스.
SDK 대신 httpx로 직접 호출하여 의존성을 최소화합니다.
"""
import logging
import httpx
from core.config import settings

logger = logging.getLogger(__name__)

# 전공 코드 → 한글 매핑
MAJOR_MAP = {
    "SW_DEVELOPMENT": "소프트웨어개발과",
    "SMART_IOT": "스마트IoT과",
    "AI": "인공지능과",
}


def _get_headers() -> dict:
    return {"X-API-KEY": settings.DATAGSM_API_KEY}


async def lookup_student_by_email(email: str) -> dict | None:
    """
    DataGSM API로 이메일 기반 학생 조회.

    Returns:
        재학생이면 학생 정보 dict, 아니면 None
    """
    if not settings.DATAGSM_API_KEY:
        logger.warning("DATAGSM_API_KEY가 설정되지 않았습니다. 학생 검증을 건너뜁니다.")
        return {"name": None, "grade": None, "class_num": None, "number": None, "major": None}

    url = f"{settings.DATAGSM_API_URL}/v1/students"
    params = {
        "email": email,
        "onlyEnrolled": "true",
        "size": 1,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=_get_headers(), params=params)

        if resp.status_code != 200:
            logger.error(f"DataGSM Students API 오류: {resp.status_code} - {resp.text}")
            raise RuntimeError("DataGSM API 오류")

        data = resp.json()
        students = data.get("data", {}).get("students", [])

        if not students:
            return None  # 재학생 아님

        student = students[0]
        return {
            "name": student.get("name"),
            "grade": student.get("grade"),
            "class_num": student.get("classNum"),
            "number": student.get("number"),
            "major": MAJOR_MAP.get(student.get("major"), student.get("major")),
        }

    except httpx.TimeoutException:
        logger.error("DataGSM Students API 요청 타임아웃")
        raise RuntimeError("DataGSM API 타임아웃")
    except RuntimeError:
        raise
    except Exception as e:
        logger.error(f"DataGSM Students API 호출 실패: {e}")
        raise RuntimeError("DataGSM API 호출 실패")


async def lookup_projects_by_email(email: str) -> list[dict]:
    """
    DataGSM 프로젝트 API에서 해당 이메일이 참여자로 등록된 프로젝트 목록을 반환합니다.

    Returns:
        참여 중인 프로젝트 목록 [{"id": 1, "name": "프로젝트명", "club": "동아리명"}, ...]
        참여 프로젝트가 없으면 빈 리스트 []
    """
    if not settings.DATAGSM_API_KEY:
        logger.warning("DATAGSM_API_KEY가 설정되지 않았습니다. 프로젝트 검증을 건너뜁니다.")
        return []

    url = f"{settings.DATAGSM_API_URL}/v1/projects"
    all_projects = []
    page = 0

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # 페이지네이션으로 전체 프로젝트 조회
            while True:
                resp = await client.get(
                    url,
                    headers=_get_headers(),
                    params={"page": page, "size": 100},
                )

                if resp.status_code != 200:
                    logger.error(f"DataGSM Projects API 오류: {resp.status_code} - {resp.text}")
                    break

                data = resp.json()
                projects = data.get("data", {}).get("projects", [])
                if not projects:
                    break

                all_projects.extend(projects)

                total_pages = data.get("data", {}).get("totalPages", 1)
                page += 1
                if page >= total_pages:
                    break

        # 참여자 이메일로 필터링
        matched = []
        for project in all_projects:
            participants = project.get("participants", [])
            for p in participants:
                if p.get("email", "").lower() == email.lower():
                    club_info = project.get("club")
                    matched.append({
                        "id": project.get("id"),
                        "name": project.get("name"),
                        "club": club_info.get("name") if club_info else None,
                    })
                    break

        return matched

    except httpx.TimeoutException:
        logger.error("DataGSM Projects API 요청 타임아웃")
        return []
    except Exception as e:
        logger.error(f"DataGSM Projects API 호출 실패: {e}")
        return []
