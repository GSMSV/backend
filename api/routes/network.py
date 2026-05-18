from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from core.database import get_db
from models.user import User
from api.dependencies import get_current_user, get_vm_with_owner_check
from services.network_service import calculate_ports

router = APIRouter()


@router.get("/{node}/{vmid}/ports")
async def get_forwarded_ports(
    node: str,
    vmid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """특정 VM에 할당된 포트포워딩 정보 조회 (SSH, SVC1, SVC2)"""
    vm = get_vm_with_owner_check(db, vmid, current_user, node=node)
    ports = calculate_ports(vm.server.base_port, vmid)

    return {
        "vmid": vmid,
        "node": vm.server.name,
        "public_ip": vm.server.ip_address,
        "message": "VM에 할당된 공인 접속 포트 목록입니다.",
        "ports": [
            {"service": "SSH (22)", "public_port": ports["ssh"], "protocol": "tcp"},
            {"service": "HTTP (80)", "public_port": ports["svc1"], "protocol": "tcp"},
            {"service": "SVC (10000)", "public_port": ports["svc2"], "protocol": "tcp"},
        ],
    }
