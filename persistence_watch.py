_WATCHED_CLASSES = ["__EventFilter", "__EventConsumer", "__FilterToConsumerBinding"]


def _wmi_object_properties(wmi_obj):
    result = {}
    for key in wmi_obj.properties.keys():
        value = getattr(wmi_obj, key, None)
        if value is not None:
            result[key] = value
    return result


def _persistence_event_to_evidence(wmi_event, class_name):
    return {
        "wmi_class": class_name,
        "attck": "T1546.003",
        "properties": _wmi_object_properties(wmi_event),
    }
