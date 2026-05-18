from sqlalchemy import Boolean, Column, Integer, String, DateTime
from core.database import Base
from core.timezone import now_kst
from core.encryption import encrypt, decrypt

# ============================================================================
# 물리 서버(Proxmox Node) 정보를 저장하는 테이블
# ============================================================================
class Server(Base):
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True, index=True)
    # 서버 식별용 이름 (예: Node-1)
    name = Column(String, unique=True, index=True, nullable=False)
    # 서버 물리 IP
    ip_address = Column(String, nullable=False)
    # 서버 통신 포트 (예: 8006, 8007 등)
    port = Column(Integer, nullable=False)
    # Proxmox API 계정 정보 (예: gsmsv@pve)
    api_user = Column(String, nullable=False)
    _api_password = Column("api_password", String, nullable=False)

    # Proxmox 노드 SSH 계정 (스니펫 업로드용)
    ssh_user = Column(String, nullable=True)
    _ssh_password = Column("ssh_password", String, nullable=True)
    ssh_port = Column(Integer, default=22)

    # 이 서버에 새 VM을 자동 할당할지 여부
    is_active = Column(Boolean, default=True)

    # --- 포트 포워딩을 위한 라우터(Gateway) 정보 ---
    # 해당 노드의 트래픽이 나가는 상단 라우터의 IP (iptables 제어용)
    gateway_ip = Column(String, nullable=True)
    gateway_user = Column(String, nullable=True)
    _gateway_password = Column("gateway_password", String, nullable=True)

    # 해당 서버의 시작 포트 (예: 21000)
    base_port = Column(Integer, default=21000)

    # 마지막으로 남은 자원(RAM 등)을 체크해둔 시점 (오토 프로비저닝용 캐시)
    last_free_ram_mb = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), default=now_kst)
    updated_at = Column(DateTime(timezone=True), onupdate=now_kst)

    # ── 비밀번호 암호화 프로퍼티 ─────────────────────────────
    @property
    def api_password(self):
        return decrypt(self._api_password) if self._api_password else None

    @api_password.setter
    def api_password(self, value):
        self._api_password = encrypt(value) if value else None

    @property
    def ssh_password(self):
        return decrypt(self._ssh_password) if self._ssh_password else None

    @ssh_password.setter
    def ssh_password(self, value):
        self._ssh_password = encrypt(value) if value else None

    @property
    def gateway_password(self):
        return decrypt(self._gateway_password) if self._gateway_password else None

    @gateway_password.setter
    def gateway_password(self, value):
        self._gateway_password = encrypt(value) if value else None
