from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.sql import func
from core.database import Base


class VmPort(Base):
    __tablename__ = "vm_ports"

    id = Column(Integer, primary_key=True, index=True)
    vm_id = Column(Integer, ForeignKey("vms.id"), nullable=False, index=True)
    internal_port = Column(Integer, nullable=False)
    external_port = Column(Integer, nullable=False, unique=True)
    protocol = Column(String, default="tcp")
    action = Column(String, default="ACCEPT")
    source = Column(String, nullable=True)
    description = Column(String, nullable=True)
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
