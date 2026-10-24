# GhostRun

GhostRun is a behavioral analysis tool for Windows malware. You run it
inside an isolated sandbox VM that you provide and set up yourself.
GhostRun does not create or manage that isolation. It only runs inside
it. Point GhostRun at a sample and it launches the sample itself, then
watches what it actually does: processes it creates, files it drops,
registry keys it touches, and network connections it makes. When the
run finishes, GhostRun writes a plain-language report with the
evidence, an overall severity and confidence rating, and a list of
indicators of compromise you can reuse.

GhostRun's own analysis runs entirely offline. It does not call home
or need an internet connection to work, and no sample data leaves your
machine unless you set it up to send evidence to a separate host
yourself, see "Running across two machines" below. The sample itself
may still make real network connections if your VM allows it. GhostRun
does not block those connections. It only watches and reports on
them.

## Requirements

- Windows 10 or 11, run as Administrator. GhostRun uses Windows' own
  event tracing (ETW) and registry APIs, so it only runs on Windows.
- Python 3.10 or newer.
- An isolated, disposable VM you provide and control. GhostRun does
  not create or manage this VM. You set it up and run GhostRun inside
  it yourself. GhostRun launches and detonates the real sample, so
  never run it on your main machine.
- A few Python packages, installed with:

  ```
  pip install psutil wmi watchdog yara-python pyyaml
  ```

- Suricata is optional. GhostRun always reports which network
  connections the sample made, with or without Suricata installed. If
  Suricata is also installed and on your PATH, GhostRun captures a
  packet trace too and adds Suricata's own signature-based alerts to
  the report.

## Getting started

1. Copy the GhostRun folder into your analysis VM.
2. Open an elevated (Administrator) terminal in that folder.
3. Run:

   ```
   python ghostrun_analyze.py path\to\sample.exe
   ```

That's the whole command. GhostRun starts its own evidence receiver,
runs the sample for 60 seconds while it watches, and writes a report
when it's done. Run it again against a different sample whenever you
need to, each run gets its own case folder and its own report.

## Basic usage

```
python ghostrun_analyze.py path\to\sample.exe
python ghostrun_analyze.py path\to\sample.exe --timeout 120
```

| Option | Default | What it does |
|---|---|---|
| `sample` | (required) | path to the file to analyze |
| `--timeout` | `60` | how many seconds to let the sample run before stopping it |
| `--port` | `9001` | port the evidence receiver listens on |

A longer `--timeout` gives a sample more time to act, useful for
malware that waits before doing anything, or that calls home on a
delay.

## What a run produces

Each run writes two files:

- `run<N>.jsonl`: every piece of evidence GhostRun collected, one per
  line, in the order it happened.
- `report/report_run<N>.md`: the human-readable report built from that
  evidence. Open it in any markdown viewer or plain text editor.

The report includes:

- An executive summary with an overall severity and confidence rating.
- A timeline of what the sample did.
- Indicators of compromise: file hashes, registry keys, mutex names,
  and network indicators you can reuse in other tools or share with
  your team.

GhostRun also keeps the full case data (snapshots, raw evidence) in
`cases/ghostrun-<timestamp>/`, in case you need to dig deeper than the
report.

## Detection rules

GhostRun's own detection data (known malware mutex names, persistence
registry keys, known-benign domains, and more) lives in
`detection_rules/*.yml`. Edit these files directly to add your own
signatures, no code changes needed. See `detection_rules/README.md`
for what each file covers.

## Running across two machines

By default GhostRun starts its own evidence receiver locally, on the
same machine as the sample. If you'd rather keep the receiver on a
separate host (so your case data survives even if you revert or
destroy the VM afterward), run `receiver_http.py` there first, then
point `ghostrun.py` at it directly:

```
# on the receiver host
python receiver_http.py --port 9001

# inside the analysis VM
python ghostrun.py -s path\to\sample.exe --host <receiver-ip> --port 9001 --timeout 60 --file run1.jsonl
```

This is the lower-level command `ghostrun_analyze.py` already runs for
you. Use it directly only if you need the separate-host setup above.
