from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from core.config import settings

# .env의 DATABASE_URL에서 읽음 (SQLite / PostgreSQL 모두 지원)
SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL

# SQLite인 경우에만 check_same_thread 옵션 추가
connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,  # PostgreSQL 커넥션 끊김 자동 복구
}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
else:
    # 동기 라우트는 anyio 워커 스레드풀(기본 40개)에서 동시에 실행되고,
    # 노드/VM 상태 조회는 서버별로 스레드 병렬 호출한다. 기본 풀(5+10)로는
    # 커넥션이 고갈되므로 워커 동시성에 맞춰 풀을 키우고 stale 커넥션을 재활용한다.
    engine_kwargs.update(
        pool_size=20,        # 상시 유지 커넥션
        max_overflow=20,     # 피크 시 추가 허용 (총 40 ≈ 워커 스레드 수)
        pool_recycle=1800,   # 30분마다 커넥션 재생성 (DB 측 idle timeout 대비)
        pool_timeout=30,     # 커넥션 확보 대기 타임아웃(초)
    )

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args=connect_args,
    **engine_kwargs,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 모든 DB 모델이 상속받을 기본 Base 클래스
Base = declarative_base()


# 데이터베이스 세션을 생성하고 닫아주는 의존성 주입 함수
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
