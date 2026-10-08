import os
import shutil
import subprocess
import sys
import warnings


class YaraScanError(Exception):
    """raised when a YARA rule file fails to compile, or a scan fails."""


_MIN_MATCH_LENGTH = 4
_MAX_INSTANCES_PER_IDENTIFIER = 20
_DEFAULT_YARA_RULES_CACHE = os.path.expanduser("~/.ghostrun/rules/yara-rules")
_DEFAULT_YARA_RULES_URL = "https://github.com/Yara-Rules/rules"


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


def resolve_yara_rules_dir(configured_path=None, cache_dir=None, interactive=None):
    """
    finds a YARA rules directory to scan with.
    checks, in order: an explicit path, then a populated local cache
    dir, then, if interactive, offers to clone the default ruleset
    (Yara-Rules/rules, same one watson uses) via git.
    returns None and never raises if nothing is available or the user
    says no. monitoring still runs, just without YARA scanning.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_YARA_RULES_CACHE

    if configured_path and os.path.isdir(configured_path):
        return configured_path

    if os.path.isdir(cache_dir) and os.listdir(cache_dir):
        return cache_dir

    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        return None

    if not shutil.which("git"):
        return None

    answer = input(
        f"No YARA rules found. Fetch the community ruleset now via "
        f"'git clone {_DEFAULT_YARA_RULES_URL}'? [y/N] "
    ).strip().lower()
    if answer != "y":
        return None

    try:
        os.makedirs(os.path.dirname(cache_dir), exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--progress", _DEFAULT_YARA_RULES_URL, cache_dir],
            timeout=300,
        )
    except Exception:
        return None

    if result.returncode != 0:
        return None

    return cache_dir if os.path.isdir(cache_dir) and os.listdir(cache_dir) else None
