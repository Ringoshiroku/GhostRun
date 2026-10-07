import warnings


class YaraScanError(Exception):
    """raised when a YARA rule file fails to compile, or a scan fails."""


_MIN_MATCH_LENGTH = 4
_MAX_INSTANCES_PER_IDENTIFIER = 20


def _is_unreadable(text):
    if "�" in text:
        return True
    return any(ord(c) < 32 and c not in "\t\n\r" for c in text)


def scan_file(file_path, rules_dir):
    import yara
    import os
    from pathlib import Path

    rule_files = sorted(
        set(Path(rules_dir).rglob("*.yar")) | set(Path(rules_dir).rglob("*.yara"))
    )
    if not rule_files:
        return []

    filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
    try:
        ruleset = yara.compile(filepaths=filepaths)
    except yara.Error:
        good_files = []
        errors = []
        for rule_file in rule_files:
            try:
                yara.compile(filepath=str(rule_file))
                good_files.append(rule_file)
            except yara.Error as exc:
                errors.append(f"{rule_file}: {exc}")
        if not good_files:
            raise YaraScanError("; ".join(errors))
        good_filepaths = {f"rule_{i}": str(f) for i, f in enumerate(good_files)}
        try:
            ruleset = yara.compile(filepaths=good_filepaths)
        except yara.Error as exc:
            raise YaraScanError(str(exc)) from exc

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            matches = ruleset.match(str(file_path))
    except yara.Error as exc:
        raise YaraScanError(str(exc)) from exc

    results = []
    for match in matches:
        if match.meta.get("hide"):
            continue

        by_identifier = {}
        for string_match in match.strings:
            for instance in string_match.instances:
                matched_data = instance.matched_data.decode("utf-8", errors="replace")
                if len(matched_data) < _MIN_MATCH_LENGTH:
                    continue
                if _is_unreadable(matched_data):
                    continue
                by_identifier.setdefault(string_match.identifier, []).append(
                    {
                        "identifier": string_match.identifier,
                        "offset": instance.offset,
                        "matched_data": matched_data,
                    }
                )

        flattened = []
        for identifier, instances in by_identifier.items():
            kept = instances[:_MAX_INSTANCES_PER_IDENTIFIER]
            flattened.extend(kept)
            suppressed = len(instances) - len(kept)
            if suppressed > 0:
                flattened.append(
                    {
                        "identifier": identifier,
                        "offset": None,
                        "matched_data": f"...{suppressed} more instance(s) suppressed",
                    }
                )

        if not flattened:
            continue

        results.append({"rule": match.rule, "tags": list(match.tags), "matches": flattened})

    return results
