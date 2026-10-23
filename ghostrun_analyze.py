r"""
One-command wrapper around ghostrun.py for an analyst who isn't running
the dev sync tooling: starts its own evidence receiver if one isn't
already listening, checks for elevation up front with a clear error
instead of a confusing mid-run failure, auto-picks the output filename,
runs ghostrun.py, then builds the markdown report automatically.

Only the sample path (and optionally --timeout/--port) are the
analyst's to set; everything else is auto-detected or a sensible
default. Must run from this same directory (where ghostrun.py,
receiver_http.py, and report/ live), elevated, on Windows -- the same
requirements ghostrun.py itself already has.

    python ghostrun_analyze.py path\to\sample.exe
    python ghostrun_analyze.py path\to\sample.exe --timeout 120
"""

import argparse
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

GHOSTRUN_DIR = Path(__file__).resolve().parent


def _is_elevated() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _is_receiver_running(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _next_run_number(ghostrun_dir: Path) -> int:
    numbers = []
    for p in ghostrun_dir.glob("run*.jsonl"):
        m = re.match(r"^run(\d+)\.jsonl$", p.name)
        if m:
            numbers.append(int(m.group(1)))
    return max(numbers, default=0) + 1


def _find_case_dir(ghostrun_dir: Path, case_prefix: str = "ghostrun-") -> "Path | None":
    # picks by the numeric suffix in the folder name, not filesystem
    # mtime: NTFS doesn't reliably bump a directory's own mtime just
    # because files were created inside it (same reasoning
    # flarevm-sync-run.ps1 already applies to this same lookup).
    cases_dir = ghostrun_dir / "cases"
    if not cases_dir.is_dir():
        return None
    candidates = []
    for p in cases_dir.iterdir():
        if not p.is_dir():
            continue
        m = re.match(rf"^{re.escape(case_prefix)}(\d+)$", p.name)
        if m:
            candidates.append((int(m.group(1)), p))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def main():
    if sys.platform != "win32":
        print("[ghostrun_analyze] this tool only runs on Windows.", file=sys.stderr)
        return 1

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", help="path to the sample to analyze")
    parser.add_argument("--timeout", type=int, default=60, help="seconds to run (default: 60)")
    parser.add_argument(
        "--port", type=int, default=9001, help="evidence receiver port (default: 9001)"
    )
    args = parser.parse_args()

    sample_path = Path(args.sample)
    if not sample_path.exists():
        print(f"[ghostrun_analyze] sample not found: {sample_path}", file=sys.stderr)
        return 1

    if not _is_elevated():
        print(
            "[ghostrun_analyze] this needs to run as Administrator. "
            "GhostRun's monitors fail partway through, with confusing "
            "permission errors, if it isn't.",
            file=sys.stderr,
        )
        return 1

    host = "127.0.0.1"
    receiver_proc = None
    if _is_receiver_running(host, args.port):
        print(f"[ghostrun_analyze] receiver already running on port {args.port}, reusing it.")
    else:
        print(f"[ghostrun_analyze] starting receiver on port {args.port}...")
        receiver_proc = subprocess.Popen(
            [sys.executable, "receiver_http.py", "--port", str(args.port)],
            cwd=GHOSTRUN_DIR,
        )
        # give it a moment to bind before ghostrun.py starts PUTting to it.
        for _ in range(20):
            if _is_receiver_running(host, args.port, timeout=0.2):
                break
            time.sleep(0.2)
        else:
            print("[ghostrun_analyze] receiver never came up, aborting.", file=sys.stderr)
            receiver_proc.terminate()
            return 1

    run_number = _next_run_number(GHOSTRUN_DIR)
    run_file = f"run{run_number}.jsonl"
    print(f"[ghostrun_analyze] running GhostRun -> {run_file} (timeout {args.timeout}s)...")

    try:
        result = subprocess.run(
            [
                sys.executable, "ghostrun.py",
                "-s", str(sample_path),
                "--host", host,
                "--port", str(args.port),
                "--timeout", str(args.timeout),
                "--file", run_file,
            ],
            cwd=GHOSTRUN_DIR,
        )
    finally:
        if receiver_proc is not None:
            receiver_proc.terminate()
            receiver_proc.wait(timeout=5)

    if result.returncode != 0:
        print(
            f"[ghostrun_analyze] ghostrun.py exited with code {result.returncode}; "
            f"building the report from whatever it produced anyway.",
            file=sys.stderr,
        )

    case_dir = _find_case_dir(GHOSTRUN_DIR)
    if case_dir is None:
        print("[ghostrun_analyze] no case directory found, skipping report build.", file=sys.stderr)
        return result.returncode

    print(f"[ghostrun_analyze] building report from {case_dir.name}...")
    report_result = subprocess.run(
        [sys.executable, "report_builder.py", str(case_dir), f"run{run_number}"],
        cwd=GHOSTRUN_DIR / "report",
    )
    if report_result.returncode != 0:
        print("[ghostrun_analyze] report_builder.py failed.", file=sys.stderr)
        return result.returncode

    report_file = GHOSTRUN_DIR / "report" / f"report_run{run_number}.md"
    print(f"[ghostrun_analyze] done. {run_file} / {report_file} are ready.")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
