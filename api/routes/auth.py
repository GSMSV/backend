import asyncio
import json
import time
from datetime import timedelta
from pathlib import Path
from core.timezone import now_kst
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    Request,
    UploadFile,
    File,
)
from sqlalchemy.exc import IntegrityError
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from core.database import get_db
from core.config import settings
from core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
)
from models.user import User, UserRole
from models.email_verification import EmailVerification
from api.dependencies import get_current_user
from schemas.user_schema import (
    UserCreate,
    VerifyCodeRequest,
    ResendCodeRequest,
    Token,
    RefreshRequest,
    ProjectCheckRequest,
    ProjectSignupRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
    ChangePasswordRequest,
)
from services.email_service import generate_verification_code, send_verification_email
from services.datagsm_service import lookup_student_by_email, lookup_projects_by_email
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

router = APIRouter()


def _issue_tokens(user_id: int) -> dict:
    """Access Token + Refresh Token 쌍을 발급합니다."""
    return {
        "access_token": create_access_token(subject=user_id),
        "refresh_token": create_refresh_token(subject=user_id),
        "token_type": "bearer",
    }


def _set_auth_cookies(response: JSONResponse, access_token: str, refresh_token: str):
    """httpOnly 쿠키에 JWT 토큰을 설정합니다."""
    is_prod = settings.FRONTEND_URL.startswith("https")
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=is_prod,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=is_prod,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
        path="/api/v1/auth/refresh",  # refresh 엔드포인트에서만 전송
    )


def _clear_auth_cookies(response: JSONResponse):
    """인증 쿠키를 삭제합니다."""
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/api/v1/auth/refresh")


def _find_user_by_email_role(db: Session, email: str, role: UserRole):
    """이메일 + 역할 조합으로 유저를 조회합니다."""
    return db.query(User).filter(User.email == email, User.role == role).first()


# ── 일반 학생 회원가입 ───────────────────────────────────────


@router.post("/signup")
@limiter.limit("5/minute")
async def signup(request: Request, user_in: UserCreate, db: Session = Depends(get_db)):
    """
    일반 회원가입 1단계: 재학생 검증 후 이메일 인증 코드를 발송합니다.
    """
    # 같은 이메일 + USER 역할로 이미 가입되었는지 확인
    existing = _find_user_by_email_role(db, user_in.email, UserRole.USER)
    if existing:
        raise HTTPException(
            status_code=400, detail="이미 일반 계정으로 가입된 이메일입니다."
        )

    # DataGSM API로 재학생 검증
    try:
        student_info = await lookup_student_by_email(user_in.email)
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="서버 오류입니다. 잠시 후 다시 시도해주세요.",
        )
    if student_info is None:
        raise HTTPException(
            status_code=403,
            detail="재학생이 아니라면 가입이 불가능합니다. GSM 재학생 이메일로 가입해주세요.",
        )

    # 기존 미인증 레코드 삭제 (같은 이메일 + 같은 role)
    db.query(EmailVerification).filter(
        EmailVerification.email == user_in.email,
        EmailVerification.signup_role == "user",
        EmailVerification.verified == False,
    ).delete()
    db.commit()

    code = generate_verification_code()
    verification = EmailVerification(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        code=code,
        student_info=json.dumps(student_info, ensure_ascii=False),
        signup_role="user",
        expires_at=now_kst()
        + timedelta(minutes=settings.VERIFICATION_CODE_EXPIRE_MINUTES),
    )
    db.add(verification)
    db.commit()

    sent = await send_verification_email(user_in.email, code)
    if not sent:
        raise HTTPException(
            status_code=500,
            detail="인증 이메일 발송에 실패했습니다. 잠시 후 다시 시도해주세요.",
        )

    return {
        "message": "인증 코드가 이메일로 발송되었습니다.",
        "email": user_in.email,
        "expires_in_minutes": settings.VERIFICATION_CODE_EXPIRE_MINUTES,
    }


# ── 프로젝트 오너 회원가입 (2단계 분리) ──────────────────────


@router.post("/signup/project/check")
async def check_project_eligibility(
    body: ProjectCheckRequest, db: Session = Depends(get_db)
):
    """
    프로젝트 오너 가입 1단계: 이메일로 재학생 + 프로젝트 참여 여부를 확인합니다.
    """
    # 같은 이메일 + PROJECT_OWNER 역할로 이미 가입되었는지 확인
    existing = _find_user_by_email_role(db, body.email, UserRole.PROJECT_OWNER)
    if existing:
        raise HTTPException(
            status_code=400, detail="이미 프로젝트 오너로 가입된 이메일입니다."
        )

    # 재학생 검증
    try:
        student_info = await lookup_student_by_email(body.email)
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="서버 오류입니다. 잠시 후 다시 시도해주세요.",
        )
    if student_info is None:
        raise HTTPException(
            status_code=403,
            detail="재학생이 아니라면 가입이 불가능합니다. GSM 재학생 이메일로 가입해주세요.",
        )

    # 프로젝트 참여자 검증
    projects = await lookup_projects_by_email(body.email)
    if not projects:
        raise HTTPException(
            status_code=403,
            detail="DataGSM에서 조회되는 프로젝트 참여자만 가입할 수 있습니다.",
        )

    # 이미 오너가 있는 프로젝트 표시
    taken_projects = set()
    existing_owners = (
        db.query(User.project_name)
        .filter(
            User.role == UserRole.PROJECT_OWNER,
            User.project_name.isnot(None),
        )
        .all()
    )
    for (pname,) in existing_owners:
        taken_projects.add(pname)

    available_projects = [
        {"name": p["name"], "club": p.get("club"), "taken": p["name"] in taken_projects}
        for p in projects
    ]

    return {
        "email": body.email,
        "student": student_info,
        "projects": available_projects,
    }


@router.post("/signup/project")
async def signup_project(body: ProjectSignupRequest, db: Session = Depends(get_db)):
    """
    프로젝트 오너 가입 2단계: 프로젝트 선택 + 비밀번호 + 신청사유 → 이메일 인증 코드 발송.
    """
    existing = _find_user_by_email_role(db, body.email, UserRole.PROJECT_OWNER)
    if existing:
        raise HTTPException(
            status_code=400, detail="이미 프로젝트 오너로 가입된 이메일입니다."
        )

    # 프로젝트당 오너 1명 제한
    existing_owner = (
        db.query(User)
        .filter(
            User.role == UserRole.PROJECT_OWNER,
            User.project_name == body.project_name,
            User.is_active == True,
        )
        .first()
    )
    if existing_owner:
        raise HTTPException(
            status_code=409,
            detail=f"'{body.project_name}' 프로젝트에는 이미 오너가 등록되어 있습니다.",
        )

    pending_owner = (
        db.query(User)
        .filter(
            User.role == UserRole.PROJECT_OWNER,
            User.project_name == body.project_name,
            User.is_active == False,
        )
        .first()
    )
    if pending_owner:
        raise HTTPException(
            status_code=409,
            detail=f"'{body.project_name}' 프로젝트의 오너 승인이 대기 중입니다.",
        )

    # 재학생 + 프로젝트 참여 재확인
    try:
        student_info = await lookup_student_by_email(body.email)
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="서버 오류입니다. 잠시 후 다시 시도해주세요.",
        )
    if student_info is None:
        raise HTTPException(status_code=403, detail="재학생 검증에 실패했습니다.")

    projects = await lookup_projects_by_email(body.email)
    project_names = [p["name"] for p in projects]
    if body.project_name not in project_names:
        raise HTTPException(
            status_code=403,
            detail=f"'{body.project_name}' 프로젝트에 참여하고 있지 않습니다.",
        )

    student_info["projects"] = projects

    # 기존 미인증 레코드 삭제
    db.query(EmailVerification).filter(
        EmailVerification.email == body.email,
        EmailVerification.signup_role == "project_owner",
        EmailVerification.verified == False,
    ).delete()
    db.commit()

    code = generate_verification_code()
    verification = EmailVerification(
        email=body.email,
        hashed_password=get_password_hash(body.password),
        code=code,
        student_info=json.dumps(student_info, ensure_ascii=False),
        signup_role="project_owner",
        project_name=body.project_name,
        project_reason=body.reason,
        expires_at=now_kst()
        + timedelta(minutes=settings.VERIFICATION_CODE_EXPIRE_MINUTES),
    )
    db.add(verification)
    db.commit()

    sent = await send_verification_email(body.email, code)
    if not sent:
        raise HTTPException(status_code=500, detail="인증 이메일 발송에 실패했습니다.")

    return {
        "message": "인증 코드가 이메일로 발송되었습니다. 이메일 인증 후 관리자 승인이 필요합니다.",
        "email": body.email,
        "project_name": body.project_name,
        "expires_in_minutes": settings.VERIFICATION_CODE_EXPIRE_MINUTES,
    }


# ── 이메일 인증 (공통) ──────────────────────────────────────


@router.post("/verify")
@limiter.limit("10/minute")
async def verify_email(
    request: Request, body: VerifyCodeRequest, db: Session = Depends(get_db)
):
    """
    회원가입 2단계: 인증 코드를 확인하고 계정을 생성합니다.
    같은 이메일이라도 role이 다르면 별도 계정으로 생성됩니다.
    """
    record = (
        db.query(EmailVerification)
        .filter(
            EmailVerification.email == body.email,
            EmailVerification.verified == False,
        )
        .order_by(EmailVerification.created_at.desc())
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=400,
            detail="인증 요청을 찾을 수 없습니다. 회원가입을 다시 진행해주세요.",
        )

    if now_kst() > record.expires_at:
        raise HTTPException(
            status_code=400, detail="인증 코드가 만료되었습니다. 코드를 재발송해주세요."
        )

    if record.attempts >= 5:
        raise HTTPException(
            status_code=429,
            detail="인증 시도 횟수를 초과했습니다. 코드를 재발송해주세요.",
        )

    if record.code != body.code.strip():
        record.attempts = (record.attempts or 0) + 1
        db.commit()
        raise HTTPException(status_code=400, detail="인증 코드가 일치하지 않습니다.")

    # 역할 결정
    is_project_owner = record.signup_role == "project_owner"
    role = UserRole.PROJECT_OWNER if is_project_owner else UserRole.USER

    # 같은 이메일 + 같은 역할로 이미 존재하는지 확인
    existing = _find_user_by_email_role(db, body.email, role)
    if existing:
        raise HTTPException(status_code=400, detail="이미 가입된 계정입니다.")

    # 학생 정보 복원 (삭제 전에 읽기)
    student_info = {}
    if record.student_info:
        try:
            student_info = json.loads(record.student_info)
        except Exception:
            pass

    new_user = User(
        email=record.email,
        hashed_password=record.hashed_password,
        role=role,
        is_active=not is_project_owner,
        name=student_info.get("name"),
        grade=student_info.get("grade"),
        class_num=student_info.get("class_num"),
        number=student_info.get("number"),
        major=student_info.get("major"),
        project_name=record.project_name if is_project_owner else None,
        project_reason=record.project_reason if is_project_owner else None,
    )
    try:
        db.delete(record)
        db.add(new_user)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="이미 가입된 계정입니다.")
    db.refresh(new_user)

    if is_project_owner:
        return {
            "status": "pending_approval",
            "message": "이메일 인증이 완료되었습니다. 관리자 승인 후 로그인이 가능합니다.",
        }

    tokens = _issue_tokens(new_user.id)
    tokens["status"] = "active"
    response = JSONResponse(content=tokens)
    _set_auth_cookies(response, tokens["access_token"], tokens["refresh_token"])
    return response


# ── 관리자: 프로젝트 오너 승인/거절 ─────────────────────────


@router.get("/pending-approvals")
async def get_pending_approvals(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """관리자 전용: 승인 대기 중인 프로젝트 오너 목록을 조회합니다."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="관리자만 접근 가능합니다.")

    pending = (
        db.query(User)
        .filter(User.role == UserRole.PROJECT_OWNER, User.is_active == False)
        .all()
    )

    return [
        {
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "grade": u.grade,
            "class_num": u.class_num,
            "number": u.number,
            "major": u.major,
            "project_name": u.project_name,
            "project_reason": u.project_reason,
        }
        for u in pending
    ]


@router.post("/approve/{user_id}")
async def approve_project_owner(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """관리자 전용: 프로젝트 오너 가입 승인."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="관리자만 접근 가능합니다.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="이미 승인된 사용자입니다.")

    user.is_active = True
    db.commit()

    return {"message": f"{user.email} 계정이 승인되었습니다.", "user_id": user.id}


@router.post("/reject/{user_id}")
async def reject_project_owner(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """관리자 전용: 프로젝트 오너 가입 거절 (계정 삭제)."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="관리자만 접근 가능합니다.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    if user.is_active:
        raise HTTPException(
            status_code=400, detail="이미 승인된 사용자는 거절할 수 없습니다."
        )

    db.delete(user)
    db.commit()

    return {"message": f"{user.email} 가입 신청이 거절되었습니다."}


# ── 인증 코드 재발송 ────────────────────────────────────────


@router.post("/resend-code")
@limiter.limit("3/minute")
async def resend_code(
    request: Request, body: ResendCodeRequest, db: Session = Depends(get_db)
):
    """인증 코드를 재발송합니다."""
    latest = (
        db.query(EmailVerification)
        .filter(
            EmailVerification.email == body.email,
            EmailVerification.verified == False,
        )
        .order_by(EmailVerification.created_at.desc())
        .first()
    )

    if not latest:
        raise HTTPException(status_code=400, detail="인증 대기 중인 요청이 없습니다.")

    # 기존 미인증 레코드를 모두 삭제하고 새 레코드 삽입
    signup_role = latest.signup_role
    hashed_password = latest.hashed_password
    student_info = latest.student_info
    project_name = latest.project_name
    project_reason = latest.project_reason

    db.query(EmailVerification).filter(
        EmailVerification.email == body.email,
        EmailVerification.verified == False,
        EmailVerification.signup_role == signup_role,
    ).delete(synchronize_session="fetch")

    new_code = generate_verification_code()
    new_record = EmailVerification(
        email=body.email,
        hashed_password=hashed_password,
        code=new_code,
        student_info=student_info,
        signup_role=signup_role,
        project_name=project_name,
        project_reason=project_reason,
        expires_at=now_kst()
        + timedelta(minutes=settings.VERIFICATION_CODE_EXPIRE_MINUTES),
    )
    try:
        db.add(new_record)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="잠시 후 다시 시도해주세요.")

    sent = await send_verification_email(body.email, new_code)
    if not sent:
        raise HTTPException(status_code=500, detail="인증 이메일 발송에 실패했습니다.")

    return {
        "message": "새 인증 코드가 발송되었습니다.",
        "expires_in_minutes": settings.VERIFICATION_CODE_EXPIRE_MINUTES,
    }


# ── 로그인 ──────────────────────────────────────────────────


@router.post("/login", response_model=Token)
@limiter.limit("10/minute")
async def login(
    request: Request,
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
    login_role: str = Query(
        default="user", description="로그인 역할: user 또는 project_owner"
    ),
):
    """
    로그인을 수행하고 JWT 토큰 쌍을 발급합니다.
    같은 이메일로 일반/프로젝트 오너 계정이 모두 있을 수 있으므로 role로 구분합니다.
    """
    # role 매핑
    role_map = {
        "user": UserRole.USER,
        "project_owner": UserRole.PROJECT_OWNER,
        "admin": UserRole.ADMIN,
    }
    target_role = role_map.get(login_role)

    if target_role:
        user = _find_user_by_email_role(db, form_data.username, target_role)
    else:
        user = None

    # admin은 login_role=user로도 로그인 가능하게 (fallback)
    if not user and login_role == "user":
        user = _find_user_by_email_role(db, form_data.username, UserRole.ADMIN)

    if (
        not user
        or not user.hashed_password
        or not verify_password(form_data.password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="이메일 또는 비밀번호가 일치하지 않습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자 승인 대기 중입니다. 승인 후 로그인이 가능합니다.",
        )

    tokens = _issue_tokens(user.id)
    response = JSONResponse(content=tokens)
    _set_auth_cookies(response, tokens["access_token"], tokens["refresh_token"])
    return response


# ── 토큰 갱신 ───────────────────────────────────────────────


@router.post("/refresh")
async def refresh_token(
    request: Request,
    body: RefreshRequest = None,
    db: Session = Depends(get_db),
):
    """Refresh Token으로 새 Access Token + Refresh Token 쌍을 발급합니다.
    쿠키 또는 JSON body에서 refresh_token을 읽습니다."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="유효하지 않은 Refresh Token입니다.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 쿠키 우선, 없으면 body에서
    rt = request.cookies.get("refresh_token")
    if not rt and body and body.refresh_token:
        rt = body.refresh_token
    if not rt:
        raise credentials_exception

    try:
        payload = jwt.decode(rt, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise credentials_exception
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None or not user.is_active:
        raise credentials_exception

    tokens = _issue_tokens(user.id)
    response = JSONResponse(content=tokens)
    _set_auth_cookies(response, tokens["access_token"], tokens["refresh_token"])
    return response


# ── 내 정보 ─────────────────────────────────────────────────


@router.get("/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    """현재 로그인된 사용자의 정보를 조회합니다."""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "name": current_user.name,
        "grade": current_user.grade,
        "class_num": current_user.class_num,
        "number": current_user.number,
        "major": current_user.major,
        "project_name": current_user.project_name,
        "avatar_url": current_user.avatar_url,
    }


# ── 비밀번호 재설정 ──────────────────────────────────────────


_RESET_ROLE_MAP = {"user": UserRole.USER, "project_owner": UserRole.PROJECT_OWNER}
_PASSWORD_RESET_MIN_RESPONSE_SECONDS = 0.5


async def _pad_password_reset_response(started_at: float) -> None:
    remaining = _PASSWORD_RESET_MIN_RESPONSE_SECONDS - (time.monotonic() - started_at)
    if remaining > 0:
        await asyncio.sleep(remaining)


def _password_reset_request_response(email: str) -> dict[str, str]:
    return {
        "message": "등록된 이메일이라면 인증 코드가 발송됩니다.",
        "email": email,
    }


def _reset_signup_role(login_role: str) -> str:
    """role별로 인증 레코드를 분리하기 위한 signup_role 인코딩."""
    return f"password_reset:{login_role}"


@router.post("/password-reset/request")
@limiter.limit("3/minute")
async def request_password_reset(
    request: Request, body: PasswordResetRequest, db: Session = Depends(get_db)
):
    """비밀번호 재설정 1단계: 이메일+role로 인증 코드를 발송합니다."""
    started_at = time.monotonic()
    target_role = _RESET_ROLE_MAP[body.login_role]
    # 해당 이메일+role의 활성 계정이 있는지 확인
    user = (
        db.query(User)
        .filter(
            User.email == body.email,
            User.role == target_role,
            User.is_active == True,
        )
        .first()
    )
    # ADMIN은 user 탭으로 재설정 가능 (로그인과 동일 정책)
    if not user and body.login_role == "user":
        user = (
            db.query(User)
            .filter(
                User.email == body.email,
                User.role == UserRole.ADMIN,
                User.is_active == True,
            )
            .first()
        )
    if not user:
        # 보안상 존재하지 않는 이메일이어도 같은 메시지 반환
        await _pad_password_reset_response(started_at)
        return _password_reset_request_response(body.email)
    if not user.hashed_password:
        # OAuth 계정은 비밀번호가 없으므로 재설정 레코드/이메일을 만들지 않는다.
        # 응답은 동일하게 유지해 계정 유형 노출을 피한다.
        await _pad_password_reset_response(started_at)
        return _password_reset_request_response(body.email)

    sr = _reset_signup_role(body.login_role)
    # 기존 미인증 비밀번호 재설정 레코드 삭제 (같은 role만)
    db.query(EmailVerification).filter(
        EmailVerification.email == body.email,
        EmailVerification.signup_role == sr,
        EmailVerification.verified == False,
    ).delete()
    db.commit()

    code = generate_verification_code()
    verification = EmailVerification(
        email=body.email,
        hashed_password="",  # 재설정이므로 기존 비밀번호 불필요
        code=code,
        signup_role=sr,
        expires_at=now_kst()
        + timedelta(minutes=settings.VERIFICATION_CODE_EXPIRE_MINUTES),
    )
    db.add(verification)
    db.commit()

    sent = await send_verification_email(body.email, code)
    if not sent:
        raise HTTPException(status_code=500, detail="인증 이메일 발송에 실패했습니다.")

    await _pad_password_reset_response(started_at)
    return _password_reset_request_response(body.email)


@router.post("/password-reset/confirm")
@limiter.limit("5/minute")
async def confirm_password_reset(
    request: Request, body: PasswordResetConfirm, db: Session = Depends(get_db)
):
    """비밀번호 재설정 2단계: 인증 코드 확인 + 해당 role 계정의 비밀번호만 변경."""
    target_role = _RESET_ROLE_MAP[body.login_role]
    sr = _reset_signup_role(body.login_role)
    record = (
        db.query(EmailVerification)
        .filter(
            EmailVerification.email == body.email,
            EmailVerification.signup_role == sr,
            EmailVerification.verified == False,
        )
        .order_by(EmailVerification.created_at.desc())
        .with_for_update()  # request_password_reset이 삭제 후 재생성하므로 단일 레코드 보장
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=400, detail="비밀번호 재설정 요청을 찾을 수 없습니다."
        )

    if now_kst() > record.expires_at:
        raise HTTPException(
            status_code=400, detail="인증 코드가 만료되었습니다. 다시 요청해주세요."
        )

    if (record.attempts or 0) >= 5:
        raise HTTPException(
            status_code=429,
            detail="인증 시도 횟수를 초과했습니다. 새 코드를 요청해주세요.",
            headers={"Retry-After": "0"},
        )

    if record.code != body.code.strip():
        record.attempts = (record.attempts or 0) + 1
        db.commit()
        raise HTTPException(status_code=400, detail="인증 코드가 일치하지 않습니다.")

    # 해당 이메일+role의 활성 계정만 비밀번호 변경
    user = (
        db.query(User)
        .filter(
            User.email == body.email,
            User.role == target_role,
            User.is_active == True,
        )
        .first()
    )
    # ADMIN은 user 탭으로 재설정 가능 (로그인과 동일 정책)
    if not user and body.login_role == "user":
        user = (
            db.query(User)
            .filter(
                User.email == body.email,
                User.role == UserRole.ADMIN,
                User.is_active == True,
            )
            .first()
        )
    if not user:
        raise HTTPException(status_code=404, detail="계정을 찾을 수 없습니다.")

    user.hashed_password = get_password_hash(body.new_password)
    db.delete(record)
    db.commit()

    return {"message": "비밀번호가 성공적으로 변경되었습니다."}


# ── 비밀번호 변경 (로그인 상태) ─────────────────────────────


@router.put("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """로그인한 사용자의 비밀번호를 변경합니다.

    같은 이메일로 여러 role 계정이 있어도 현재 로그인된 row 1건만 갱신합니다.
    (USER와 PROJECT_OWNER는 별개 계정으로 취급)
    """
    if not current_user.hashed_password:
        raise HTTPException(
            status_code=400, detail="OAuth 계정은 비밀번호 변경이 불가합니다."
        )

    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=400, detail="현재 비밀번호가 일치하지 않습니다."
        )

    current_user.hashed_password = get_password_hash(body.new_password)
    db.commit()
    return {"message": "비밀번호가 변경되었습니다."}


# ── 프로필 사진 ──────────────────────────────────────────────

AVATAR_DIR = Path("uploads/avatars")
AVATAR_DIR.mkdir(parents=True, exist_ok=True)
AVATAR_DIR_RESOLVED = AVATAR_DIR.resolve()
ALLOWED_AVATAR_TYPES = {"image/jpeg", "image/png", "image/webp"}
ALLOWED_AVATAR_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_AVATAR_SIZE = 2 * 1024 * 1024  # 2MB


def _safe_avatar_path(avatar_url: str) -> Path | None:
    """avatar_url을 안전한 로컬 경로로 변환. AVATAR_DIR 외부 경로는 None 반환."""
    resolved = Path(avatar_url.lstrip("/")).resolve()
    if not str(resolved).startswith(str(AVATAR_DIR_RESOLVED)):
        return None
    return resolved


@router.post("/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """프로필 사진 업로드 (최대 2MB, jpeg/png/webp)"""
    if file.content_type not in ALLOWED_AVATAR_TYPES:
        raise HTTPException(
            status_code=400, detail="jpg, png, webp 이미지만 업로드 가능합니다."
        )

    contents = await file.read()
    if len(contents) > MAX_AVATAR_SIZE:
        raise HTTPException(status_code=400, detail="파일 크기는 2MB 이하여야 합니다.")

    # 기존 아바타 삭제 (경로 순회 방지)
    if current_user.avatar_url:
        old_path = _safe_avatar_path(current_user.avatar_url)
        if old_path and old_path.exists():
            old_path.unlink(missing_ok=True)

    # 저장 (확장자 화이트리스트)
    ext = (
        file.filename.rsplit(".", 1)[-1].lower()
        if file.filename and "." in file.filename
        else ""
    )
    if ext not in ALLOWED_AVATAR_EXTENSIONS:
        ext = "png"
    filename = f"{current_user.id}_{int(time.time())}.{ext}"
    filepath = AVATAR_DIR / filename

    with open(filepath, "wb") as f:
        f.write(contents)

    avatar_url = f"/uploads/avatars/{filename}"
    current_user.avatar_url = avatar_url
    db.commit()

    return {"avatar_url": avatar_url}


@router.delete("/avatar")
async def delete_avatar(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """프로필 사진 삭제"""
    if current_user.avatar_url:
        old_path = _safe_avatar_path(current_user.avatar_url)
        if old_path and old_path.exists():
            old_path.unlink(missing_ok=True)

    current_user.avatar_url = None
    db.commit()
    return {"message": "프로필 사진이 삭제되었습니다."}


# ── 로그아웃 ────────────────────────────────────────────────


@router.post("/logout")
async def logout():
    """로그아웃 — httpOnly 쿠키 삭제."""
    response = JSONResponse(content={"message": "로그아웃 되었습니다."})
    _clear_auth_cookies(response)
    return response
