# GSMSV Backend

광주소프트웨어마이스터고 VM 신청·관리 플랫폼의 백엔드.

## 스택

- FastAPI
- SQLAlchemy
- PostgreSQL / SQLite
- Pydantic Settings
- JWT 인증
- Proxmox API / Paramiko

## 디렉터리

- `api/routes/` API 라우트 모음
- `core/` 설정, DB, 보안, 공통 초기화
- `models/` SQLAlchemy 모델
- `schemas/` 요청·응답 스키마
- `services/` VM, 네트워크, 메일, 외부 서비스 로직
- `tests/` 테스트 코드
- `main.py` FastAPI 앱 진입점
- `start.ps1` / `start.bat` 로컬 실행 스크립트

## 프론트엔드 연동

이 백엔드는 [GSMSV/frontend](https://github.com/GSMSV/frontend) 와 함께 동작합니다.

프론트엔드는 `/api/*` 요청을 이 백엔드로 프록시하고, 백엔드는 로그인 시 `access_token`, `refresh_token` 을 httpOnly 쿠키로 내려줍니다. 따라서 로컬에서는 백엔드를 `http://localhost:8000`, 프론트엔드를 `http://localhost:3000` 기준으로 맞춰 두면 바로 연동할 수 있습니다.

기본 관련 환경 변수:

- `CORS_ORIGINS=["http://localhost:3000"]`
- `FRONTEND_URL=http://localhost:3000`
- `OAUTH_REDIRECT_URI=http://localhost:3000/api/v1/oauth/callback`

## 로컬 실행

### 1. 환경 변수 준비

`.env.example` 을 `.env` 로 복사한 뒤 필수 값을 채웁니다.

```powershell
Copy-Item .env.example .env
```

필수값이 비어 있으면 서버가 시작되지 않습니다.

- `SECRET_KEY`
- `GATEWAY_IP`
- `GATEWAY_USER`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `DATAGSM_API_KEY`

`SECRET_KEY` 예시:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### 2. 백엔드 실행

가장 간단한 방식:

```powershell
.\start.bat
```

또는

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

수동 실행:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

실행 후 주소:

- API: [http://localhost:8000](http://localhost:8000)
- Swagger: [http://localhost:8000/docs](http://localhost:8000/docs)

## 인증 흐름

1. 프론트 로그인 요청이 `/api/v1/auth/login` 으로 들어옵니다.
2. 백엔드가 사용자 검증 후 `access_token` 과 `refresh_token` 쿠키를 설정합니다.
3. 프론트는 `/api/v1/auth/me` 로 현재 사용자 정보를 조회합니다.
4. Access token 이 만료되면 `/api/v1/auth/refresh` 로 재발급합니다.
5. 로그아웃 시 인증 쿠키를 제거합니다.

OAuth 로그인 흐름은 `api/routes/oauth.py` 에서 처리하며, DataGSM OAuth 와 임시 코드 교환 방식으로 연결됩니다.

## 컨벤션

커밋 메시지:

- `type: 한국어 설명`
- 예: `feat: 로그인 응답 쿠키 처리 수정`
- 타입 예시: `feat`, `fix`, `update`, `add`, `docs`, `style`, `refactor`, `test`, `perf`, `merge`

브랜치 흐름:

- `develop` 에서 작업 브랜치 분기
- 작업 후 PR 을 통해 `develop` 으로 병합
- `main` 직접 push 금지

## 빌드

로컬 개발 서버:

```powershell
.\start.bat
```

도커 빌드:

```powershell
docker build -t gsmsv-backend .
```

테스트:

```powershell
.\.venv\Scripts\python -m pytest
```
