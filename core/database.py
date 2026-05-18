from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from core.config import settings

# .env의 DATABASE_URL에서 읽음 (SQLite / PostgreSQL 모두 지원)
SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL

# SQLite인 경우에만 check_same_thread 옵션 추가
connect_args = {}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,  # PostgreSQL 커넥션 끊김 자동 복구
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
