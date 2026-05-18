from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class VMTier(str, Enum):
    MICRO = "micro"
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    # 프로젝트 오너 전용 커스텀 티어
    PROJECT_CUSTOM = "project_custom"


class VMOs(str, Enum):
    UBUNTU2204 = "ubuntu2204"
    WINDOWS_SERVER = "windows-server"


class VMActionType(str, Enum):
    START = "start"
    STOP = "stop"
    SHUTDOWN = "shutdown"
    REBOOT = "reboot"


class VMAction(BaseModel):
    """VM/컨테이너 제어 액션 모델"""

    action: VMActionType


class VMResize(BaseModel):
    """VM 사양 변경 요청 모델 (핫플러그)"""

    cores: Optional[int] = None  # vCPU 수
    memory: Optional[int] = None  # RAM (MB 단위)


class SnapshotCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$")
    description: str = ""


class VMCreate(BaseModel):
    """VM 생성 요청 모델 — 사용자는 os, tier와 선택적으로 node_name만 입력"""

    tier: VMTier = VMTier.MICRO
    os: VMOs = VMOs.UBUNTU2204
    node_name: Optional[str] = None  # 미지정 시 Auto Provisioning
    name: Optional[str] = None  # 미지정 시 자동 생성
    # project_custom 전용 커스텀 스펙 (미입력 시 기본값 사용)
    custom_cores: Optional[int] = None  # vCPU 수 (1~8)
    custom_memory: Optional[int] = None  # RAM (MB 단위, 1024~32768)
    custom_disk: Optional[int] = None  # 디스크 (GB 단위, 30~70)
