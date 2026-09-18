from utils.rot13 import rot13

def decode_userassist(value_name: str) -> dict:
    decoded = rot13(value_name)

    classification = classify(decoded)

    return {
        "raw": value_name,
        "decoded": decoded,
        "category": classification["category"],
        "confidence": classification["confidence"],
        "explanation": classification["explanation"]
    }

def interpret_userassist(binary_before, binary_after):
    """
    Compare UserAssist binary before/after
    """
    if not binary_before or not binary_after:
        return {
            "type": "unknown",
            "confidence": "low",
            "explanation": "Insufficient UserAssist data for interpretation"
        }

    if (
        binary_before["run_count"] == binary_after["run_count"]
        and binary_before["last_execution_time"] == binary_after["last_execution_time"]
    ):
        return {
            "type": "statistics_update",
            "confidence": "info",
            "explanation": (
                "UserAssist statistics updated (focus time / UI interaction) "
                "with no evidence of new program execution"
            )
        }

    if binary_after["run_count"] > binary_before["run_count"]:
        return {
            "type": "execution",
            "confidence": "high",
            "explanation": "Increase in execution count observed in UserAssist"
        }

    return {
        "type": "ambiguous",
        "confidence": "low",
        "explanation": "UserAssist data changed but execution could not be confirmed"
    }


def classify(decoded: str) -> dict:
    if decoded.startswith("UEME_RUNPATH"):
        return {
            "category": "execution",
            "confidence": "high",
            "explanation": "Program execution via Explorer path"
        }

    if decoded.startswith("UEME_RUNPIDL"):
        return {
            "category": "execution",
            "confidence": "high",
            "explanation": "Explorer-based program execution"
        }

    if decoded.startswith("UEME_RUNCONTEXTMENU"):
        return {
            "category": "execution",
            "confidence": "medium",
            "explanation": "Program executed via context menu"
        }

    if decoded.startswith("UEME_CTL") or decoded.startswith("UEME_UI"):
        return {
            "category": "ui_activity",
            "confidence": "info",
            "explanation": "Explorer UI / session activity"
        }

    return {
        "category": "unknown",
        "confidence": "low",
        "explanation": "Unclassified UserAssist artifact"
    }
