from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from core.database import Base
from core.timezone import now_kst
from core.encryption import encrypt, decrypt

# ============================================================================
# 각 물리 서버에 생성된 가상 머신(VM) 목록을 추적하는 테이블
# ============================================================================
class Vm(Base):
    __tablename__ = "vms"

    # 우리 플랫폼 내부에서 발급하는 고유 ID
    id = Column(Integer, primary_key=True, index=True)
    
    # Proxmox/Hypervisor 에서 실제 할당된 VMID (예: 100, 101)
    hypervisor_vmid = Column(Integer, nullable=False)
    
    # VM 이름 식별자 — Proxmox에 등록되는 전체 이름 (예: test1-myvm)
    name = Column(String, index=True, nullable=False)

    # 웹에서 표시되는 이름 (예: myvm) — 사용자 프리픽스 제외
    display_name = Column(String, nullable=True)
    
    # 생성된 VM이 실제로 위치한 물리 서버 ID (servers 테이블 참조)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False, index=True)

    # 신규: VM 소유자(사용자) ID 기록
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    # 할당된 자원
    allocated_ram_mb = Column(Integer, default=2048)
    allocated_cores = Column(Integer, default=2)
    
    # 내부 IP 주소 (iptables 포트포워딩 대상)
    internal_ip = Column(String, nullable=True)

    # VM 초기 비밀번호 (cloud-init으로 주입, Fernet 암호화 저장)
    _vm_password = Column("vm_password", String, nullable=True)
    
    # 생성 일자 등
    created_at = Column(DateTime(timezone=True), default=now_kst)

    # VM 만료 일자 (일반 유저만 적용, 생성 시 created_at + 30일)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    # 자동 스냅샷 활성화 여부
    auto_snapshot = Column(Boolean, default=False)
    
    # 서버 객체와의 역참조 관계 (ORM을 통해 vm.server 로 해당 서버 정보를 바로 꺼낼 수 있음)
    server = relationship("Server", backref="vms")
    # 소유자 객체와의 역참조 관계
    owner = relationship("User", backref="vms")

    # ── VM 비밀번호 암호화 프로퍼티 ──────────────────────────
    @property
    def vm_password(self):
        return decrypt(self._vm_password) if self._vm_password else None

    @vm_password.setter
    def vm_password(self, value):
        self._vm_password = encrypt(value) if value else None
