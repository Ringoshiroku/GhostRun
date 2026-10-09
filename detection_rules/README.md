# GhostRun detection rules

Each file here holds one category of GhostRun's own detection data, as
plain YAML. Edit these directly, no code changes needed: a syntax error
disables that file; a malformed entry is skipped on its own; either way
a warning is printed and GhostRun keeps running.

- `mutex_signatures.yml`: known malware family mutex-name patterns (e.g. DarkComet, QuasarRAT, Remcos)
- `network_service_signatures.yml`: known legitimate services (Discord, Telegram, etc.), recognized by domain/IP, used to label C2/exfil-capable traffic
- `benign_domains.yml`: hostnames suppressed as known-benign noise (Windows Update, NTP, OCSP)
- `registry_persistence_keys.yml`: registry locations checked for persistence, each tagged with its MITRE ATT&CK technique
