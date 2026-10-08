import os
import shutil
import subprocess
import sys
import warnings
from pathlib import Path


class YaraScanError(Exception):
    """raised when a YARA rule file fails to compile, or a scan fails."""


# community rules (e.g. utils/domain.yar's `/([\w\.-]+)/`) can be loose.
# they can match single characters or empty strings all over a binary.
# without bounds, one rule can produce millions of matches.
# a 1-3 character match tells an analyst nothing anyway.
_MIN_MATCH_LENGTH = 4
_MAX_INSTANCES_PER_IDENTIFIER = 20
_DEFAULT_YARA_RULES_CACHE = os.path.expanduser("~/.ghostrun/rules/yara-rules")
_DEFAULT_YARA_RULES_URL = "https://github.com/Yara-Rules/rules"


def _is_unreadable(text):
    # byte-pattern rules (crypto constants, magic numbers, GUIDs) match raw
    # binary data, not text.
    # decoding that as UTF-8 produces garbage characters.
    # so the match is dropped, same as a too-short match.
    if "�" in text:
        return True
    return any(ord(c) < 32 and c not in "\t\n\r" for c in text)


def _find_rule_files(rules_dir):
    return sorted(
        set(Path(rules_dir).rglob("*.yar")) | set(Path(rules_dir).rglob("*.yara"))
    )


def compile_rules(rules_dir):
    """
    compiles every .yar/.yara file under rules_dir into one yara.Rules
    object. returns None if rules_dir has no rule files.
    compiling a large ruleset takes seconds, so callers that scan many
    files (GhostRun scans every dropped file) should call this once and
    reuse the result via match_rules(), not recompile per file.
    a compiled yara.Rules object is safe to .match() from multiple
    threads at once.

    raises YaraScanError if every rule file is broken.
    raises ImportError if yara-python isn't installed (the import is
    deferred so this module stays importable without it).
    """
    import yara

    rule_files = _find_rule_files(rules_dir)
    if not rule_files:
        return None

    filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
    try:
        return yara.compile(filepaths=filepaths)
    except yara.Error:
        # one or more rule files may be broken (common in large rule sets).
        # test-compile each file on its own to find the broken ones,
        # then do one batch recompile of just the good files.
        # keeping each file as its own compiled Rules object costs too much
        # memory: on a large ruleset (500+ files) that reached multiple
        # gigabytes and could get the process OOM-killed, versus tens of
        # megabytes for one batch compile of the same rules.
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
            return yara.compile(filepaths=good_filepaths)
        except yara.Error as exc:
            raise YaraScanError(str(exc)) from exc


def match_rules(rules, file_path):
    """
    matches file_path against an already-compiled yara.Rules object
    (from compile_rules) and returns the filtered, capped match list.
    raises YaraScanError if the scan itself fails (e.g. the file is
    gone).
    """
    import yara

    try:
        # a rule with an unbounded pattern (e.g. the "domain"/"PoetRat_Python"
        # rules, whose matches get filtered out below anyway) can hit
        # libyara's own per-string match cap.
        # it raises a RuntimeWarning straight to stderr over whatever is on
        # screen, with no count to recover, so there's nothing useful to show.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            matches = rules.match(str(file_path))
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


def scan_file(file_path, rules_dir):
    """one-shot convenience: compiles rules_dir, then matches file_path.
    recompiles every call, so use this only for a single scan.
    for repeated scans, call compile_rules() once, then match_rules()
    per file."""
    rules = compile_rules(rules_dir)
    if rules is None:
        return []
    return match_rules(rules, file_path)


def _has_rule_files(rules_dir):
    # checks for an actual .yar/.yara file, not just "directory not
    # empty": a git clone killed by its timeout, or one that failed, can
    # leave a partial directory (e.g. just .git/) that would otherwise
    # look like a populated cache forever while giving zero rules.
    if not os.path.isdir(rules_dir):
        return False
    path = Path(rules_dir)
    return any(True for _ in path.rglob("*.yar")) or any(True for _ in path.rglob("*.yara"))


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

    if _has_rule_files(cache_dir):
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

    # only clean up a directory this call created itself on a failed
    # clone. a directory that already existed is left alone.
    cache_existed = os.path.exists(cache_dir)
    try:
        os.makedirs(os.path.dirname(cache_dir), exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--progress", _DEFAULT_YARA_RULES_URL, cache_dir],
            timeout=300,
        )
        cloned = result.returncode == 0
    except Exception:
        cloned = False

    if not cloned:
        # a killed or failed clone can leave a partial directory behind.
        # remove it so it isn't mistaken for a rules cache later.
        if not cache_existed:
            shutil.rmtree(cache_dir, ignore_errors=True)
        return None

    return cache_dir if _has_rule_files(cache_dir) else None


def load_yara_rules(configured_path=None, cache_dir=None, interactive=None):
    """
    resolves the rules directory (maybe prompting to clone it) and
    compiles it once, for reuse across every scan this run.
    returns None if YARA scanning isn't available. never raises.

    must run before the sample launches and before network capture
    starts: the prompt can't land mid-run, the compile can't compete
    with the sample for CPU, and a git clone's own HTTPS traffic can't
    end up in the capture.
    """
    try:
        import yara  # noqa: F401
    except ImportError:
        print("[GhostRun] YARA: yara-python not installed, dropped files won't be YARA-scanned")
        return None

    rules_dir = resolve_yara_rules_dir(
        configured_path=configured_path, cache_dir=cache_dir, interactive=interactive,
    )
    if rules_dir is None:
        print("[GhostRun] YARA: no rules directory available, dropped files won't be YARA-scanned")
        return None

    try:
        rules = compile_rules(rules_dir)
    except (YaraScanError, ImportError, OSError) as exc:
        print(f"[GhostRun] YARA: failed to compile rules in {rules_dir}: {exc}")
        return None

    if rules is None:
        print(f"[GhostRun] YARA: no .yar/.yara files under {rules_dir}, dropped files won't be YARA-scanned")
        return None

    print(f"[GhostRun] YARA: rules compiled from {rules_dir}")
    return rules
