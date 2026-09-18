import os
from collections import defaultdict


# =========================================================
# SNAPSHOT (MULTI-ROOT)
# =========================================================

def snapshot_filesystem_multi(targets):
    """
    Take filesystem snapshot for multiple root directories.

    targets: dict
        {
          "TEMP": "C:\\Users\\...\\Temp",
          "APPDATA": "C:\\Users\\...\\AppData\\Roaming",
          ...
        }

    Returns:
        snapshot dict:
        {
          "ROOT_NAME": {
              "path": {
                  "size": int,
                  "mtime": int,
                  "ext": str
              }
          }
        }
    """
    snapshot = {}

    for root_name, root_path in targets.items():
        if not root_path or not os.path.exists(root_path):
            continue

        root_snapshot = {}

        for root, dirs, files in os.walk(root_path):
            for name in files:
                try:
                    full_path = os.path.join(root, name)
                    stat = os.stat(full_path)

                    root_snapshot[full_path] = {
                        "size": stat.st_size,
                        "mtime": int(stat.st_mtime),
                        "ext": os.path.splitext(name)[1].lower()
                    }
                except (FileNotFoundError, PermissionError):
                    continue

        snapshot[root_name] = root_snapshot

    return snapshot


# =========================================================
# DIFF (MULTI-ROOT)
# =========================================================

def diff_filesystem_multi(before, after, emit=None, root_pid=None):
    """
    Diff filesystem snapshots (multi-root) and emit forensic evidence.
    """
    #if root_pid not in MALWARE_PIDS:
    #    return True
        
    for root_name in after.keys():
        b = before.get(root_name, {})
        a = after.get(root_name, {})

        created = []
        deleted = []
        modified = []
        ext_changes = defaultdict(int)

        b_paths = set(b.keys())
        a_paths = set(a.keys())

        # Created
        for path in a_paths - b_paths:
            created.append(path)

        # Deleted
        for path in b_paths - a_paths:
            deleted.append(path)

        # Modified
        for path in b_paths & a_paths:
            if (
                b[path]["size"] != a[path]["size"]
                or b[path]["mtime"] != a[path]["mtime"]
            ):
                modified.append(path)

                if b[path]["ext"] != a[path]["ext"]:
                    ext_changes[(b[path]["ext"], a[path]["ext"])] += 1

        # --------------------------------------------------
        # Emit evidence
        # --------------------------------------------------
        if emit:
            if created:
                emit(
                    category="filesystem_behavior",
                    event="file_created",
                    confidence="medium",
                    data={
                        "pid": root_pid,
                        "root": root_name,
                        "count": len(created),
                        "examples": created[:5]
                    }
                )

            if deleted:
                emit(
                    category="filesystem_behavior",
                    event="file_deleted",
                    confidence="medium",
                    data={
                        "pid": root_pid,
                        "root": root_name,
                        "count": len(deleted),
                        "examples": deleted[:5]
                    }
                )

            if modified:
                emit(
                    category="filesystem_behavior",
                    event="file_modified",
                    confidence="medium",
                    data={
                        "pid": root_pid,
                        "root": root_name,
                        "count": len(modified),
                        "examples": modified[:5]
                    }
                )

            # Ransomware-style extension change
            for (old_ext, new_ext), count in ext_changes.items():
                if count >= 3 and new_ext not in ("", old_ext):
                    emit(
                        category="filesystem_behavior",
                        event="mass_extension_change",
                        confidence="high",
                        data={
                            "pid": root_pid,
                            "root": root_name,
                            "from_ext": old_ext,
                            "to_ext": new_ext,
                            "affected_files": count,
                            "note": (
                                "Pattern consistent with ransomware-style "
                                "file encryption behavior."
                            )
                        }
                    )

    return True
