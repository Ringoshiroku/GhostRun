CONFIDENCE_MAP = {
    "high": 0.9,
    "medium": 0.6,
    "low": 0.3,
    "info": 0.1
}

def confidence_score(level: str) -> float:
    return CONFIDENCE_MAP.get(level, 0.1)
