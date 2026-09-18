BASE_SEVERITY = {
    "persistence": 5,
    "execution": 4,
    "network": 3,
    "static": 2
}

IMPACT_WEIGHT = {
    "system": 3,
    "user": 2,
    "temp": 0.5
}

def calculate_severity(ioc_type, impact, confidence):
    base = BASE_SEVERITY.get(ioc_type, 1)
    impact_weight = IMPACT_WEIGHT.get(impact, 1)

    return round(base * impact_weight * confidence, 2)
