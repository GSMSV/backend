from schemas.vm_schema import VMTier

# VM 티어별 리소스 정의
TIER_SPECS = {
    VMTier.MICRO:  {"memory": 2048, "cores": 1, "disk": 30},
    VMTier.SMALL:  {"memory": 4096, "cores": 2, "disk": 40},
    VMTier.MEDIUM: {"memory": 6144, "cores": 2, "disk": 50},
    VMTier.LARGE:  {"memory": 8192, "cores": 4, "disk": 50},
    # 프로젝트 오너 전용 (최대 8 vCPU, 32GB RAM, 70GB SSD)
    VMTier.PROJECT_CUSTOM: {"memory": 32768, "cores": 8, "disk": 70},
}
