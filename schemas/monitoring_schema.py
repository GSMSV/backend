from pydantic import BaseModel


class NodeStats(BaseModel):
    status: str
    cpu_usage_percent: float | None = None
    ram_total_gb: float | None = None
    ram_used_gb: float | None = None
    ram_free_gb: float | None = None
    uptime_seconds: int | None = None
    error: str | None = None


class NodeStatsResponse(BaseModel):
    stats: dict[str, NodeStats]
    message: str | None = None
