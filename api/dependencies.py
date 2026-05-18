from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from core.config import settings
from core.database import get_db
from models.user import User, UserRole

# Bearer 헤더 (선택적 — 쿠키 우선, fallback으로 사용)
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=False,
)


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    bearer_token: str = Depends(oauth2_scheme),
) -> User:
    """
    현재 로그인한 사용자를 식별합니다.
    httpOnly 쿠키 우선, 없으면 Authorization 헤더에서 토큰을 읽습니다.
    """
    # 1. 쿠키 우선, 없으면 Bearer 헤더
    token = request.cookies.get("access_token") or bearer_token

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="인증 정보가 유효하지 않습니다.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise credentials_exception

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        # refresh token으로 API 접근 차단
        if payload.get("type") != "access":
            raise credentials_exception
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="비활성화된 사용자입니다.")

    return user

def get_current_active_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    관리자 권한이 있는지 확인합니다.
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="이 작업에 대한 충분한 권한이 없습니다. (관리자 전용)"
        )
    return current_user


def get_vm_with_owner_check(
    db: Session,
    vmid: int,
    current_user: User,
    node: str = None,
):
    """
    DB에서 VM을 찾고 소유권을 확인하는 공통 헬퍼.
    node가 주어지면 해당 서버의 VM만 조회하여 다른 노드의 동일 vmid 충돌을 방지합니다.
    """
    from models.vm import Vm
    from models.server import Server

    query = db.query(Vm).filter(Vm.hypervisor_vmid == vmid)
    if node:
        query = query.join(Server).filter(Server.name == node)
    elif current_user.role != UserRole.ADMIN:
        # node 없이 vmid만으로 조회 시, 소유자 VM만 매칭 (동일 vmid 충돌 방지)
        query = query.filter(Vm.owner_id == current_user.id)
    vm_record = query.first()
    if not vm_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"VM {vmid}를 데이터베이스에서 찾을 수 없습니다.",
        )

    if current_user.role != UserRole.ADMIN and vm_record.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="해당 VM에 접근할 권한이 없습니다.",
        )

    return vm_record
