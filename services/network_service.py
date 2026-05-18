import re
import random
import logging
import paramiko
from typing import Optional
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from models.server import Server
from core.config import settings

logger = logging.getLogger(__name__)

BACKUP_DIR = Path("backups/iptables")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# 포트 오프셋 정의
PORT_OFFSETS = {
    "ssh": 0,
    "svc1": 1000,
    "svc2": 2000
}

def calculate_ports(base_port: int, vmid: int):
    """정책에 따라 포트 번호를 계산합니다."""
    return {
        "ssh": base_port + PORT_OFFSETS["ssh"] + vmid,
        "svc1": base_port + PORT_OFFSETS["svc1"] + vmid,
        "svc2": base_port + PORT_OFFSETS["svc2"] + vmid,
    }

_IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def _validate_ip(ip: str) -> str:
    """IP 주소 형식 검증 (명령어 인젝션 방지)"""
    if not _IP_PATTERN.match(ip):
        raise ValueError(f"잘못된 IP 형식: {ip}")
    parts = ip.split(".")
    if not all(0 <= int(p) <= 255 for p in parts):
        raise ValueError(f"잘못된 IP 범위: {ip}")
    return ip

def manage_iptables(server: Server, vmid: int, vm_ip: str, action: str = "ADD"):
    """
    Router에 SSH로 접속하여 iptables DNAT 규칙을 추가하거나 삭제합니다.
    action: "ADD" (규칙 추가) or "DELETE" (규칙 삭제)
    """
    # SSH 명령어 인젝션 방지: IP 형식 검증
    _validate_ip(vm_ip)
    _validate_ip(settings.GATEWAY_PUBLIC_IP)

    if not server.gateway_ip or not server.gateway_user:
        logger.warning(f"서버 {server.name}의 Gateway 정보가 설정되지 않아 iptables 설정을 건너뜁니다.")
        return False

    ports = calculate_ports(server.base_port, vmid)
    
    # iptables 명령어 생성 (예시: DNAT 설정)
    # -i {인터페이스} 는 환경에 따라 다를 수 있으므로 여기선 생략하거나 기본값 사용
    commands = []
    
    # (공개포트, 내부포트, 프로토콜 목록)
    port_mapping = [
        (ports["ssh"], 22, ["tcp"]),
        (ports["svc1"], 80, ["tcp"]),
        (ports["svc2"], 10000, ["tcp", "udp"]),
    ]

    for public_port, internal_port, protocols in port_mapping:
        for proto in protocols:
            if action == "ADD":
                commands.append(f"sudo iptables -t nat -A PREROUTING -p {proto} -d {settings.GATEWAY_PUBLIC_IP} --dport {public_port} -j DNAT --to-destination {vm_ip}:{internal_port}")
                commands.append(f"sudo iptables -A FORWARD -p {proto} -d {vm_ip} --dport {internal_port} -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT")
            else:
                commands.append(f"sudo iptables -t nat -D PREROUTING -p {proto} -d {settings.GATEWAY_PUBLIC_IP} --dport {public_port} -j DNAT --to-destination {vm_ip}:{internal_port}")
                commands.append(f"sudo iptables -D FORWARD -p {proto} -d {vm_ip} --dport {internal_port} -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT")

    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        ssh.connect(
            hostname=server.gateway_ip,
            username=server.gateway_user,
            password=server.gateway_password or "",
            timeout=10
        )

        for cmd in commands:
            logger.info(f"Executing on {server.gateway_ip}: {cmd}")
            _, stdout_ch, stderr_ch = ssh.exec_command(cmd)
            exit_status = stdout_ch.channel.recv_exit_status()
            if exit_status != 0:
                err = stderr_ch.read().decode()
                logger.error(f"iptables command failed (exit {exit_status}): {err}")

        # iptables 백업 (변경 후 자동 저장)
        _backup_iptables(ssh, server.gateway_ip)

        return True
    except Exception as e:
        logger.error(f"Gateway SSH 접속 및 iptables 설정 실패: {e}")
        # 생성/삭제 핵심 로직을 멈추지는 않되 로그를 기록함
        return False
    finally:
        ssh.close()


def allocate_random_port(db: Session, start: int = 30000, end: int = 39999) -> int:
    """30000~39999 범위에서 DB에 없는 미사용 외부 포트를 랜덤으로 반환합니다."""
    from models.vm_port import VmPort
    for _ in range(100):
        port = random.randint(start, end)
        exists = db.query(VmPort).filter(VmPort.external_port == port).first()
        if not exists:
            return port
    raise RuntimeError("30000~39999 범위에서 할당 가능한 포트가 없습니다.")


_VALID_PROTOCOLS = {"tcp", "udp"}


def manage_custom_iptables(
    server: Server,
    vm_ip: str,
    internal_port: int,
    external_port: int,
    protocol: str,
    action: str = "ADD",
    source_ip: Optional[str] = None,
) -> bool:
    """커스텀 포트 포워딩 iptables 규칙을 추가하거나 삭제합니다."""
    if protocol not in _VALID_PROTOCOLS:
        raise ValueError(f"유효하지 않은 프로토콜: {protocol}. tcp 또는 udp만 허용됩니다.")
    _validate_ip(vm_ip)
    _validate_ip(settings.GATEWAY_PUBLIC_IP)

    if not server.gateway_ip or not server.gateway_user:
        logger.warning(f"서버 {server.name}의 Gateway 정보가 설정되지 않아 iptables 설정을 건너뜁니다.")
        return False

    flag = "-A" if action == "ADD" else "-D"
    if source_ip in ("0.0.0.0/0", "0.0.0.0"):
        source_ip = None
    src = f"-s {source_ip} " if source_ip else ""
    commands = [
        f"sudo iptables -t nat {flag} PREROUTING {src}-p {protocol} -d {settings.GATEWAY_PUBLIC_IP} --dport {external_port} -j DNAT --to-destination {vm_ip}:{internal_port}",
        f"sudo iptables {flag} FORWARD {src}-p {protocol} -d {vm_ip} --dport {internal_port} -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT",
    ]

    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        ssh.connect(
            hostname=server.gateway_ip,
            username=server.gateway_user,
            password=server.gateway_password or "",
            timeout=10,
        )
        for cmd in commands:
            logger.info(f"Executing on {server.gateway_ip}: {cmd}")
            _, stdout_ch, stderr_ch = ssh.exec_command(cmd)
            exit_status = stdout_ch.channel.recv_exit_status()
            if exit_status != 0:
                err = stderr_ch.read().decode()
                logger.error(f"iptables command failed (exit {exit_status}): {err}")
                return False
        _backup_iptables(ssh, server.gateway_ip)
        return True
    except Exception as e:
        logger.error(f"Gateway SSH 접속 및 커스텀 iptables 설정 실패: {e}")
        return False
    finally:
        ssh.close()


def _backup_iptables(ssh: paramiko.SSHClient, gateway_ip: str, **_kwargs):
    """Gateway에서 iptables 규칙을 읽어 백엔드 로컬에 .fw 파일로 저장합니다."""
    try:
        today = datetime.now().strftime("%Y%m%d")
        backup_file = BACKUP_DIR / f"iptables-{gateway_ip}-{today}.fw"

        stdin, stdout, stderr = ssh.exec_command("sudo iptables-save")
        output = stdout.read().decode()

        if output:
            backup_file.write_text(output)
            logger.info(f"[iptables-backup] 백업 완료: {backup_file}")

            # 30일 이상 된 백업 자동 정리
            for old_file in BACKUP_DIR.glob(f"iptables-{gateway_ip}-*.fw"):
                if old_file != backup_file:
                    age_days = (datetime.now() - datetime.fromtimestamp(old_file.stat().st_mtime)).days
                    if age_days > 30:
                        old_file.unlink()
                        logger.info(f"[iptables-backup] 오래된 백업 삭제: {old_file.name}")
        else:
            err = stderr.read().decode() if stderr else ""
            logger.warning(f"[iptables-backup] 백업 실패 ({gateway_ip}): 규칙을 가져올 수 없습니다. {err}")
    except Exception as e:
        logger.warning(f"[iptables-backup] 백업 실패 ({gateway_ip}): {e}")
