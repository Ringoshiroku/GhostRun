import os
import yaml


_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detection_rules")


def load_rule_file(filename, required_fields=None, validate_entry=None):
    """
    loads a YAML rule file from detection_rules/.
    the path is resolved relative to this module's own location,
    not the caller's current working directory, since GhostRun
    is always run directly.

    never raises: a missing file, invalid YAML syntax, or a
    top level that isn't a list all degrade the whole file to
    an empty list. an entry that fails required_fields or
    validate_entry is skipped on its own, the rest of the file's
    valid entries still load.

    every degrade path prints a warning naming the file and the
    specific problem.

    when neither required_fields nor validate_entry is given,
    entries may be plain scalars (e.g. a flat list of hostname
    strings) and are returned as-is. with either one given, a
    non-mapping entry is skipped.
    """
    path = os.path.join(_RULES_DIR, filename)

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception as e:
        print(f"[GhostRun] WARNING: could not read rule file {filename}: {e}")
        return []

    try:
        parsed = yaml.safe_load(raw)
    except Exception as e:
        print(f"[GhostRun] WARNING: {filename} is not valid YAML: {e}")
        return []

    if parsed is None:
        return []

    if not isinstance(parsed, list):
        print(
            f"[GhostRun] WARNING: {filename} must contain a YAML list, "
            f"got {type(parsed).__name__}"
        )
        return []

    validated = []
    for i, entry in enumerate(parsed):
        if isinstance(entry, dict):
            if required_fields:
                missing = [f for f in required_fields if f not in entry]
                if missing:
                    print(
                        f"[GhostRun] WARNING: {filename} entry {i} is missing "
                        f"required field(s) {missing}, skipping it"
                    )
                    continue

            if validate_entry is not None:
                error = validate_entry(entry)
                if error:
                    print(f"[GhostRun] WARNING: {filename} entry {i}: {error}, skipping it")
                    continue

        elif required_fields or validate_entry is not None:
            # a non-dict entry can't satisfy either structural check,
            # so it's only ok when the caller didn't ask for either.
            # omitting both is how a caller says "this file's entries
            # are plain scalars, not mappings" (e.g. benign_domains.yml's
            # flat list of hostname strings).
            print(f"[GhostRun] WARNING: {filename} entry {i} is not a mapping, skipping it")
            continue

        validated.append(entry)

    return validated
