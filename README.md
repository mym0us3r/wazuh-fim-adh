# wazuh-fim-adh

**File Integrity Monitoring with Wazuh: The Advanced Defender's Handbook**

Detection engineering content for Wazuh 4.14.8 covering FIM fundamentals, anomaly detection rules, and a two-stage AI-assisted pipeline for automated malware triage. Developed as part of the [Wazuh Ambassador Program](https://wazuh.com/community/ambassador-program/).

Reference lab: Wazuh Server 4.14.8 (WZ-SRV), Windows 11 endpoint (LABDESK, agent 4.14.8).

---

## What this repository contains

```
rules/
  fim_ai_rules.xml          # Rules 109000-109020 — FIM AI Pipeline (Stage 1 and Stage 2)
  fim_anomaly_rules.xml     # Rules 100300-100304 — Anomaly correlation (mass create/modify/delete)

decoders/
  fim_ai_decoder.xml        # JSON_Decoder for Stage 1 (fim_ai_endpoint) and Stage 2 (fim_ai_intel)

active-response/
  fim_ai_scan.py            # Source for the Windows endpoint AR executable
  fim_ai_scan.spec          # PyInstaller spec (--runtime-tmpdir required — see Lab Findings)
  fim_intel_query.py        # Server-side intelligence query: VT, OTX, URLScan, Claude

config/
  ossec_server.conf         # Server ossec.conf — AR commands, localfile blocks, FIM AI section
  ossec_agent_windows.conf  # Agent ossec.conf — explicit C:\Users\<user>\ paths, ignore rules

docs/
  wazuh-fim-documentacao-completa-pt-br.docx   # Full handbook (PT-BR, 60 pages)
```

The compiled `fim_ai_scan.exe` is distributed separately in `fim-ai-pipeline-binaries.zip` (password-protected) because the YARA ruleset and unsigned executables trigger AV false positives on download.

---

## FIM AI Pipeline

Two-stage pipeline that runs automatically after FIM detects a file change.

**Stage 1 — Endpoint scan (fim_ai_scan.exe)**

Triggered by rule 109020 (FIM event in monitored lab paths). Runs on the endpoint via Wazuh Active Response.

- Calculates MD5, SHA1, SHA256
- Scans with YARA 4.5.5 against the Valhalla demo ruleset (1298 rules)
- Scans with Windows Defender via PowerShell
- Writes structured JSON to `active-responses.log`

Output decoded by `fim_ai_endpoint` decoder. Fields indexed as `data.*` in Wazuh Indexer.

**Stage 2 — Intelligence query (fim_intel_query.py)**

Triggered by rules 109001 (YARA match) or 109002 (Defender match). Runs on the server via Wazuh Active Response.

- Queries VirusTotal (SHA256 hash)
- Queries AlienVault OTX (SHA256 hash)
- Queries URLScan.io (SHA256 hash)
- Calls Claude Sonnet 4.6 via Anthropic API with structured file metadata — never file content
- Calculates confidence score (0-100) with source weights
- Writes `RESULT` line to `active-responses.log`

Output decoded by `fim_ai_intel` decoder. Fields indexed as `data.*` in Wazuh Indexer.

**Rule chain**

| Rule | Level | Trigger |
|------|-------|---------|
| 109020 | 5 | FIM event in monitored lab paths — AR trigger |
| 109001 | 5 | YARA match on endpoint |
| 109002 | 5 | Defender threat on endpoint |
| 109003 | 3 | Scan complete, no threat |
| 109011 | 5 | Intelligence result: low confidence (score 0-30) |
| 109012 | 12 | Intelligence result: medium confidence (score 31-69) — analyst review |
| 109013 | 12 | Conflict: YARA positive + VT 0/72 |
| 109014 | 15 | High confidence (score >= 70) — host isolation trigger |
| 109015 | 15 | High confidence + YARA rule confirmed |

**Confidence score weights**

- YARA match: 35 points
- Defender detection: 25 points
- VirusTotal malicious ratio (scaled): 0-30 points
- OTX pulses: 5-10 points

Conflict rule: when YARA reports match but VT returns 0/72, score is capped at 69 regardless of other signals. Automatic isolation (rule 109014) never fires on conflicting signals.

**Validated lab result (02/10/2026, test10.txt)**

```
19:25:23 - Rule 109020  FIM detects C:\Users\kr\Downloads\test10.txt
19:25:27 - EventID 4688  fim_ai_scan.exe spawned (Sysmon)
19:25:29 - Rule 109001  YARA match: FIM_AI_Lab_Test
19:25:39 - Rule 109012  score=35, zone=medium, conflict=False
```

Total latency FIM to verdict: 16 seconds.

---

## FIM Anomaly Detection Rules

Threshold-based rules for detecting mass file operations. No external dependencies.

| Rule | Level | Trigger |
|------|-------|---------|
| 100300 | 10 | 3+ files created in 10 minutes (same agent) |
| 100301 | 12 | Same MD5 hash created in 3+ directories in 10 minutes |
| 100302 | 10 | 3+ files modified in 10 minutes |
| 100303 | 10 | 3+ files deleted in 10 minutes |
| 100304 | 14 | 5+ mixed FIM events in 10 minutes — active malware pattern |

Rule 100304 uses `<if_matched_group>syscheck_file</if_matched_group>` to cover rules 550, 553, and 554 in a single correlation. `<if_matched_sid>` with comma-separated SIDs does not work in Wazuh 4.14.x correlation rules.

Thresholds are calibrated for lab use. Production deployments should baseline normal file activity per environment before enabling threshold alerts.

---

## Requirements

- Wazuh Server 4.14.8
- Wazuh Agent 4.14.8 on monitored endpoints
- Windows endpoint: Python 3.10+, PyInstaller 6.x (for building `fim_ai_scan.exe`)
- YARA 4.5.5 (`yara64.exe` on Windows, installable via `winget install VirusTotal.YARA`)
- API keys for VirusTotal, AlienVault OTX, URLScan.io, and Anthropic (stored in `/var/ossec/etc/fim-ai/keys.env`)

---

## Deploy

**Server**

```bash
# Rules and decoders
cp rules/fim_ai_rules.xml /var/ossec/etc/rules/
cp rules/fim_anomaly_rules.xml /var/ossec/etc/rules/
cp decoders/fim_ai_decoder.xml /var/ossec/etc/decoders/

# Server-side AR script
cp active-response/fim_intel_query.py /var/ossec/active-response/bin/
chmod 750 /var/ossec/active-response/bin/fim_intel_query.py
chown root:wazuh /var/ossec/active-response/bin/fim_intel_query.py

# API keys (fill in keys.env.example and rename)
mkdir -p /var/ossec/etc/fim-ai
cp config/keys.env.example /var/ossec/etc/fim-ai/keys.env
# Edit /var/ossec/etc/fim-ai/keys.env with your API keys

# Validate and restart
/var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -i error
systemctl restart wazuh-manager
```

**Windows endpoint (PowerShell — elevated)**

```powershell
# Create runtime tmpdir (required — see Lab Finding 1)
New-Item -ItemType Directory -Force "C:\Program Files (x86)\ossec-agent\active-response\fim_ai_tmp"

# Deploy fim_ai_scan.exe (from binaries zip)
Copy-Item fim_ai_scan.exe "C:\Program Files (x86)\ossec-agent\active-response\bin\fim_ai_scan.exe" -Force

# Deploy YARA
New-Item -ItemType Directory -Force "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules"
Copy-Item yara64.exe "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe" -Force
Copy-Item yara_rules.yar "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar" -Force

# Apply agent config
Copy-Item config\ossec_agent_windows.conf "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
Restart-Service -Name WazuhSvc
```

**Whodata on Windows (workgroup environments)**

Windows Defender resets audit SACLs on shell folders (Downloads, Desktop, Documents). Before enabling `whodata` on user paths, set the audit policy:

```powershell
auditpol /set /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}" /success:enable
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable
```

In domain environments, apply via GPO: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Object Access > File System and Handle Manipulation.

---

## Building fim_ai_scan.exe

The binary is distributed pre-compiled. To rebuild from source (PowerShell without elevation, outside monitored paths):

```powershell
New-Item -ItemType Directory -Force C:\build\fim_ai
Set-Location C:\build\fim_ai
pyinstaller --onefile --name fim_ai_scan --runtime-tmpdir "C:\Program Files (x86)\ossec-agent\active-response\fim_ai_tmp" fim_ai_scan.py
```

The `--runtime-tmpdir` flag is mandatory. Without it, PyInstaller extracts the Python runtime to `C:\Windows\Temp` on each execution. If `C:\Windows\Temp` is monitored by syscheck (as in this pipeline), each extraction generates a FIM 554 alert, which triggers another AR execution, creating a self-feeding loop. See Lab Finding 1 in the handbook for the full incident timeline.

Build environment: PyInstaller 6.22.3, Python 3.13.3, Windows 11 (10.0.26200).

---

## Lab Findings

Six technical findings documented during deployment that apply to any Wazuh Active Response Python deployment on Windows.

1. **PyInstaller `--onefile` + `C:\Windows\Temp` loop** — `--runtime-tmpdir` must point outside all monitored syscheck paths.
2. **PowerShell SYSTEM profile loop** — `run_defender()` rewrites `StartupProfileData-NonInteractive` in `C:\Windows\System32\config\systemprofile\...\PowerShell`. Add `<ignore>` for that path in the agent `ossec.conf`.
3. **Windows AR requires `.exe`** — Wazuh execd on Windows does not reliably pass stdin to `.bat` or `.ps1` child processes. Compile to `.exe` with PyInstaller.
4. **`field name="file"` not `syscheck.path`** — Custom FIM rules must use `<field name="file">` for path matching. `syscheck.path` does not match in the rules engine. Documented in the [Wazuh FIM fields correspondence table](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html).
5. **AR saturation from high-frequency paths** — Rule 109020 uses `<if_group>syscheck_file</if_group>` + `<field name="file">` pcre2 to restrict AR scope to lab paths, avoiding saturation from noise sources (download managers, session files, Trend Micro, etc.).
6. **Logcollector loses tracking after manager restart** — After `systemctl restart wazuh-manager`, the logcollector may not resume reading `active-responses.log`. Verify with `grep -a "active-responses" /var/ossec/logs/ossec.log | tail -5`.

---

## References

- [Wazuh FIM documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Wazuh Active Response — custom scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
- [Creating custom FIM rules](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html)
- [Wazuh 4.14.8 release notes](https://documentation.wazuh.com/current/release-notes/release-4-14-8.html)
- [Valhalla YARA Rule Set](https://valhalla.nextron-systems.com/) (Nextron Systems, CC-BY-NC)
- [DIRTY-FRAG Detection with Wazuh 4.14.4](https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4)
- [COPY-FAIL Detection with Wazuh 4.14.4](https://github.com/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4)

---

Kislley Rodrigues — Wazuh Ambassador Program
