import ipaddress
from pydantic import BaseModel, field_validator, Field
from typing import Optional


class VmPortCreate(BaseModel):
    internal_port: int = Field(..., ge=1, le=65535)
    protocol: str = "tcp"
    source: Optional[str] = None
    description: Optional[str] = None

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        if v not in ("tcp", "udp"):
            raise ValueError("프로토콜은 tcp 또는 udp만 허용됩니다.")
        return v

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(
                "올바른 IP 또는 CIDR 형식이어야 합니다. (예: 192.168.1.0/24)"
            )
        return v


def _validate_ip_or_cidr(v: Optional[str]) -> Optional[str]:
    if not v:
        return v
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise ValueError("올바른 IP 또는 CIDR 형식이어야 합니다.")
    return v


def _validate_dport(v: Optional[str]) -> Optional[str]:
    if not v:
        return v
    parts = v.split(":")
    if len(parts) > 2:
        raise ValueError("포트 형식은 '80' 또는 '80:443'이어야 합니다.")
    for part in parts:
        if not part.isdigit() or not (1 <= int(part) <= 65535):
            raise ValueError("포트는 1~65535 범위의 정수여야 합니다.")
    return v


class FirewallRule(BaseModel):
    """방화벽 규칙 생성/수정 모델"""

    action: str = "ACCEPT"
    type: str = "in"
    proto: Optional[str] = "tcp"
    dport: Optional[str] = None
    dest: Optional[str] = None
    source: Optional[str] = None
    enable: int = 1
    comment: Optional[str] = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ("ACCEPT", "DROP", "REJECT"):
            raise ValueError("action은 ACCEPT, DROP, REJECT 중 하나여야 합니다.")
        return v

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in ("in", "out"):
            raise ValueError("type은 in 또는 out이어야 합니다.")
        return v

    @field_validator("proto")
    @classmethod
    def validate_proto(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ("tcp", "udp", "icmp"):
            raise ValueError("proto는 tcp, udp, icmp 중 하나여야 합니다.")
        return v

    @field_validator("dport")
    @classmethod
    def validate_dport(cls, v: Optional[str]) -> Optional[str]:
        return _validate_dport(v)

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: Optional[str]) -> Optional[str]:
        return _validate_ip_or_cidr(v)

    @field_validator("dest")
    @classmethod
    def validate_dest(cls, v: Optional[str]) -> Optional[str]:
        return _validate_ip_or_cidr(v)
