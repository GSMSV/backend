"""
SQLite → PostgreSQL 데이터 마이그레이션 스크립트

사용법:
  1. .env의 DATABASE_URL을 PostgreSQL로 설정
  2. SQLite 파일(vm_console.db)을 같은 디렉토리에 복사
  3. python migrate_sqlite_to_pg.py

주의:
  - 양쪽 SECRET_KEY가 동일해야 암호화 필드 이식 가능
  - 기존 PostgreSQL 데이터는 모두 삭제됩니다 (테이블 TRUNCATE)
"""
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 환경변수 로딩
from core.config import settings
from core.database import Base

# 모든 모델 import (테이블 생성용)
from models.user import User
from models.vm import Vm
from models.server import Server
from models.notification import Notification
from models.faq_question import FaqQuestion
from models.email_verification import EmailVerification

SQLITE_URL = "sqlite:///./vm_console.db"
PG_URL = settings.DATABASE_URL

if not PG_URL.startswith("postgresql"):
    print(f"❌ DATABASE_URL이 PostgreSQL이 아닙니다: {PG_URL}")
    sys.exit(1)

print(f"📂 SQLite  : {SQLITE_URL}")
print(f"🐘 Postgres: {PG_URL}")
print()

# 엔진 생성
sqlite_engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})
pg_engine = create_engine(PG_URL)

# PostgreSQL에 테이블 생성
print("🔨 PostgreSQL 테이블 생성 중...")
Base.metadata.create_all(bind=pg_engine)

# 세션
SqliteSession = sessionmaker(bind=sqlite_engine)
PgSession = sessionmaker(bind=pg_engine)

# 마이그레이션할 모델 순서 (FK 관계 고려)
MODELS = [
    User,
    Server,
    Vm,
    Notification,
    FaqQuestion,
    EmailVerification,
]

sqlite_db = SqliteSession()
pg_db = PgSession()

try:
    # 기존 데이터 삭제 (역순)
    print("🧹 PostgreSQL 기존 데이터 삭제 중...")
    for model in reversed(MODELS):
        pg_db.query(model).delete()
    pg_db.commit()

    # 데이터 복사
    for model in MODELS:
        rows = sqlite_db.query(model).all()
        print(f"  {model.__tablename__}: {len(rows)}개 복사 중...")
        for row in rows:
            # __dict__에서 SQLAlchemy 내부 필드 제외
            data = {
                k: v for k, v in row.__dict__.items()
                if not k.startswith("_")
            }
            # encrypted property는 실제 컬럼명(_vm_password 등)과 다를 수 있음
            # SQLAlchemy 객체 직접 merge
            pg_db.merge(model(**data))
        pg_db.commit()
        print(f"  ✅ {model.__tablename__} 완료")

    # PostgreSQL 시퀀스 재설정 (auto-increment ID 충돌 방지)
    print()
    print("🔢 시퀀스 재설정 중...")
    with pg_engine.connect() as conn:
        for model in MODELS:
            table = model.__tablename__
            result = conn.execute(
                # noqa
                # 각 테이블의 id 컬럼 최대값 + 1로 시퀀스 설정
                __import__("sqlalchemy").text(
                    f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                    f"COALESCE((SELECT MAX(id) FROM {table}), 1))"
                )
            )
            conn.commit()
            print(f"  ✅ {table}")

    print()
    print("🎉 마이그레이션 완료!")

except Exception as e:
    pg_db.rollback()
    print(f"❌ 오류: {e}")
    raise
finally:
    sqlite_db.close()
    pg_db.close()
