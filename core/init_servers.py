"""
앱 시작 시 .env의 노드 설정을 servers 테이블에 동기화 (upsert)
"""
import logging
from sqlalchemy.orm import Session
from core.config import settings
from core.database import SessionLocal
from models.server import Server

logger = logging.getLogger(__name__)


def sync_servers():
    """
    .env에 정의된 NODE_1~3 설정을 servers 테이블에 동기화한다.
    - 이미 존재하는 노드(name 기준): 설정값 업데이트
    - 새 노드: INSERT
    """
    node_configs = settings.get_node_configs()
    if not node_configs:
        logger.info("[init_servers] .env에 노드 설정이 없어 동기화를 건너뜁니다.")
        return

    db: Session = SessionLocal()
    try:
        for cfg in node_configs:
            server = db.query(Server).filter(Server.name == cfg["name"]).first()

            if server:
                # 기존 노드 업데이트
                changed = False
                for key, value in cfg.items():
                    if key == "name":
                        continue
                    if getattr(server, key) != value:
                        setattr(server, key, value)
                        changed = True
                if changed:
                    logger.info(f"[init_servers] '{cfg['name']}' 노드 설정 업데이트됨")
            else:
                # 새 노드 추가
                server = Server(
                    name=cfg["name"],
                    ip_address=cfg["ip_address"],
                    port=cfg["port"],
                    api_user=cfg["api_user"],
                    api_password=cfg["api_password"],
                    ssh_user=cfg.get("ssh_user"),
                    ssh_password=cfg.get("ssh_password"),
                    ssh_port=cfg.get("ssh_port", 22),
                    is_active=True,
                    gateway_ip=cfg["gateway_ip"],
                    gateway_user=cfg["gateway_user"],
                    gateway_password=cfg["gateway_password"],
                    base_port=cfg["base_port"],
                )
                db.add(server)
                logger.info(f"[init_servers] '{cfg['name']}' 노드 추가됨")

        db.commit()
        logger.info(f"[init_servers] 서버 동기화 완료 ({len(node_configs)}개 노드)")
    except Exception as e:
        db.rollback()
        logger.error(f"[init_servers] 서버 동기화 실패: {e}")
    finally:
        db.close()
