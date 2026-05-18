from core.database import engine, Base
# 미리 생성해둔 모델들을 import 해야 SQLAlchemy가 테이블 구조를 인식합니다.

def init_db():
    print("데이터베이스 초기화를 시작합니다...")
    # Base.metadata.create_all은 연결된 DB(SQLite) 엔진 구동 시
    # 파이썬 클래스로 정의해둔 테이블들이 아직 DB에 없다면 생성해 줍니다.
    Base.metadata.create_all(bind=engine)
    print("테이블 생성이 완료되었습니다!")
    print("이제 프로젝트 디렉토리에 vm_console.db 파일이 생성되었을 겁니다.")

if __name__ == "__main__":
    init_db()
