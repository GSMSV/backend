import sys
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    """
    애플리케이션 전역 설정 클래스
    .env 파일에서 환경변수를 자동으로 읽어와 타입 검증을 수행합니다.
    """
    PROJECT_NAME: str = "VM Control Platform"
    API_V1_STR: str = "/api/v1"
    
    # 데이터베이스 접속 URL (PostgreSQL 권장, SQLite 호환) — .env에서 설정
    DATABASE_URL: str = "sqlite:///./vm_console.db"

    # 보안 설정 (JWT) — .env에 반드시 설정 필요
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30              # Access Token 30분
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7    # Refresh Token 7일

    # CORS 허용 도메인 (쉼표 구분, .env에서 오버라이드 가능)
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # VM 프로비저닝
    MAX_VMS_PER_USER: int = 3
    TEMPLATE_VMID: int = 1000                       # Ubuntu 22.04 cloud-init 템플릿
    TEMPLATE_VMID_WINDOWS: int = 1001               # Windows Server 템플릿
    VM_DEFAULT_USER: str = "ubuntu"                  # cloud-init 기본 유저명 (Ubuntu)
    VM_DEFAULT_USER_WINDOWS: str = "Administrator"   # Windows 기본 유저명
    VM_ROOT_PASSWORD: str = ""                        # VM root 비밀번호 (.env에서 설정)

    # 이메일 인증 (SMTP)
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_NAME: str = "GSM SV"
    VERIFICATION_CODE_EXPIRE_MINUTES: int = 10

    # DataGSM OpenAPI
    DATAGSM_API_KEY: str = ""
    DATAGSM_API_URL: str = "https://openapi.data.hellogsm.kr"

    # DataGSM OAuth
    DATAGSM_CLIENT_ID: str = ""
    DATAGSM_CLIENT_SECRET: str = ""
    DATAGSM_OAUTH_URL: str = "https://oauth.data.hellogsm.kr"
    DATAGSM_USERINFO_URL: str = "https://oauth-userinfo.data.hellogsm.kr"
    OAUTH_REDIRECT_URI: str = "http://localhost:3000/api/v1/oauth/callback"
    FRONTEND_URL: str = "http://localhost:3000"
    OAUTH_STORE_MODE: str = "memory"               # memory | redis
    WEB_CONCURRENCY: int = 1

    # 서버리스 서비스
    SERVERLESS_SERVICE_URL: str = "http://serverless:3001"
    MAX_FUNCTIONS_PER_USER: int = 5

    # 프로젝트 오너 전용 설정
    PROJECT_NODE_NAME: str = "gsmgpu3"            # 프로젝트 VM 전용 노드

    # 내부 네트워크 (단일 서브넷)
    INTERNAL_SUBNET: str = "10.0.0"                  # /24 서브넷 프리픽스
    INTERNAL_IP_START: int = 100                     # 할당 시작 (.100)
    INTERNAL_IP_END: int = 254                       # 할당 끝 (.254)
    INTERNAL_GATEWAY: str = "10.0.0.1"
    INTERNAL_NETMASK: int = 24
    INTERNAL_DNS: str = "8.8.8.8"

    # ── 공용 게이트웨이(라우터) 설정 ─────────────────────────
    GATEWAY_PUBLIC_IP: str = ""                            # 외부 공인 IP (iptables -d 대상)
    GATEWAY_IP: str = ""
    GATEWAY_USER: str = ""
    GATEWAY_PASSWORD: str = ""

    # ── 서버 노드 설정 (NODE_{N}_{FIELD}) ────────────────────
    # ── 노드 공용 SSH 계정 (스니펫 업로드용) ──────────────────
    NODE_SSH_USER: str = ""
    NODE_SSH_PASSWORD: str = ""

    NODE_1_NAME: str = ""
    NODE_1_IP: str = ""
    NODE_1_PORT: int = 8006
    NODE_1_USER: str = "root@pam"
    NODE_1_PASSWORD: str = ""
    NODE_1_SSH_PORT: int = 22
    NODE_1_BASE_PORT: int = 21000

    NODE_2_NAME: str = ""
    NODE_2_IP: str = ""
    NODE_2_PORT: int = 8007
    NODE_2_USER: str = "root@pam"
    NODE_2_PASSWORD: str = ""
    NODE_2_SSH_PORT: int = 22
    NODE_2_BASE_PORT: int = 22000

    NODE_3_NAME: str = ""
    NODE_3_IP: str = ""
    NODE_3_PORT: int = 8008
    NODE_3_USER: str = "root@pam"
    NODE_3_PASSWORD: str = ""
    NODE_3_SSH_PORT: int = 22
    NODE_3_BASE_PORT: int = 23000

    def get_node_configs(self) -> list[dict]:
        """설정된 노드 목록을 반환 (NAME이 비어있으면 스킵)"""
        nodes = []
        for i in range(1, 4):
            name = getattr(self, f"NODE_{i}_NAME")
            ip = getattr(self, f"NODE_{i}_IP")
            if not name or not ip:
                continue
            nodes.append({
                "name": name,
                "ip_address": ip,
                "port": getattr(self, f"NODE_{i}_PORT"),
                "api_user": getattr(self, f"NODE_{i}_USER"),
                "api_password": getattr(self, f"NODE_{i}_PASSWORD"),
                "ssh_user": self.NODE_SSH_USER or None,
                "ssh_password": self.NODE_SSH_PASSWORD or None,
                "ssh_port": getattr(self, f"NODE_{i}_SSH_PORT"),
                "gateway_ip": self.GATEWAY_IP or None,
                "gateway_user": self.GATEWAY_USER or None,
                "gateway_password": self.GATEWAY_PASSWORD or None,
                "base_port": getattr(self, f"NODE_{i}_BASE_PORT"),
            })
        return nodes

    # .env 파일 로딩 설정 (pydantic v2 방식)
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"  # 모델에 없는 환경변수가 .env에 있어도 무시
    )

# 싱글톤 패턴으로 설정 인스턴스 생성
settings = Settings()

# 필수 환경변수 검증 — 누락 시 서버 시작 차단
if not settings.SECRET_KEY or settings.SECRET_KEY == "your-super-secret-key-change-this-in-production":
    print("❌ [FATAL] SECRET_KEY가 설정되지 않았습니다. .env 파일에 SECRET_KEY를 설정해주세요.")
    print("   예: SECRET_KEY=$(python -c \"import secrets; print(secrets.token_urlsafe(64))\")")
    sys.exit(1)

_REQUIRED_VARS = {
    "GATEWAY_IP": settings.GATEWAY_IP,
    "GATEWAY_USER": settings.GATEWAY_USER,
    "SMTP_USER": settings.SMTP_USER,
    "SMTP_PASSWORD": settings.SMTP_PASSWORD,
    "DATAGSM_API_KEY": settings.DATAGSM_API_KEY,
}
_missing = [k for k, v in _REQUIRED_VARS.items() if not v]
if _missing:
    print(f"❌ [FATAL] 다음 환경변수가 설정되지 않았습니다: {', '.join(_missing)}")
    print("   .env 파일의 필수 값을 모두 채운 뒤 다시 실행해주세요.")
    sys.exit(1)

if __name__ == "__main__":
    print("--- Loaded Configuration from .env ---")
    nodes = settings.get_node_configs()
    for n in nodes:
        print(f"  {n['name']}: {n['ip_address']}:{n['port']} (user={n['api_user']})")
    print(f"  GATEWAY: {settings.GATEWAY_IP or '(미설정)'}")
    print("--------------------------------------")
