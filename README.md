# WAZUH FIM - File Integrity Monitoring
## The Advanced Defender’s Handbook

> **Advanced File Integrity Monitoring - Anomaly correlation, AI-assisted triage, and Active Response pipeline**

> *Windows 11 (LABDESK) / Wazuh 4.14.8*

[![rules](https://img.shields.io/badge/wazuh_rules-21-brightgreen)](https://github.com/mym0us3r/wazuh-fim-adh) [![stages](https://img.shields.io/badge/pipeline_stages-2-blue)](https://github.com/mym0us3r/wazuh-fim-adh) [![status](https://img.shields.io/badge/status-production--validated-success)](https://github.com/mym0us3r/wazuh-fim-adh) [![mitre](https://img.shields.io/badge/MITRE-T1204.002%20%7C%20T1486%20%7C%20T1565.001-red)](https://attack.mitre.org/techniques/T1204/002/) [![wazuh](https://img.shields.io/badge/Wazuh-4.14.8-0080FF)](https://documentation.wazuh.com/current/release-notes/release-4-14-8.html) [![ambassador](https://img.shields.io/badge/Wazuh-Ambassador-0080FF)](https://wazuh.com/ambassadors-program/)

---

## What is this?

Detection engineering content for Wazuh 4.14.8 covering three capabilities built on top of the native FIM engine:

**1. Anomaly correlation rules** — threshold-based detection for mass file operations (ransomware staging, anti-forensics, bulk dropper delivery) using `<if_matched_group>` chain rules. No external dependencies.

**2. FIM + AI Pipeline** — two-stage Active Response that automatically runs YARA, Windows Defender, VirusTotal, AlienVault OTX, URLScan.io, and Claude Sonnet 4.6 on every detected file change in monitored paths. Total latency FIM to verdict: 16 seconds.

**3. Windows endpoint hardening** — production-validated `ossec.conf` for Windows with explicit `C:\Users\<user>` paths, `whodata` on system directories, and `realtime` on user paths. Includes fixes for five deployment pitfalls not documented in the official handbook.

Developed as part of the [Wazuh Ambassador Program](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

Reference lab: **WZ-SRV** (Wazuh Server 4.14.8, Ubuntu 24.04 LTS, 4GB RAM) + **LABDESK** (Windows 11 26200, Wazuh Agent 4.14.8).

---

## Why Advanced FIM?

Traditional FIM — hash comparison on a scheduled scan — has three blind spots.

```
Scheduled scan approach:
  read file from disk → compute hash → compare → alert on change
  problem: anything that happens between scans is invisible

Realtime FIM without AR:
  file created at 14:32:07 → alert fired
  analyst reviews at 14:45:00 → file already executed or deleted
  problem: detection without context is noise

Native FIM + AI Pipeline (this repo):
  file created at 19:25:23 → FIM detects (rule 109020)
  19:25:29 → fim_ai_scan.exe: YARA match FIM_AI_Lab_Test
  19:25:39 → fim_intel_query.py: VT 0/0, score=35, zone=medium
  total elapsed: 16 seconds → analyst receives enriched alert with verdict
```

---

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 1 — Endpoint (fim_ai_scan.exe)                               │
│                                                                     │
│  FIM detects file  ──►  rule 109020  ──►  wazuh-execd              │
│                                               │                     │
│                              fim_ai_scan.exe ◄┘                    │
│                                   │                                 │
│                    ┌──────────────┴──────────────┐                  │
│                    │                             │                  │
│               YARA 4.5.5                Windows Defender            │
│             1298 rules (Valhalla)       Start-MpScan                │
│                    │                             │                  │
│                    └──────────────┬──────────────┘                  │
│                                   │                                 │
│                    MD5 + SHA1 + SHA256  (all computed)              │
│                                   │                                 │
│                    JSON ──► active-responses.log                    │
│                                   │                                 │
│        decoder: fim_ai_endpoint   │   rules: 109000-109003          │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  STAGE 2 — Server (fim_intel_query.py)                              │
│                                                                     │
│  rule 109001 (YARA match) ──► wazuh-execd ──► fim_intel_query.py   │
│  rule 109002 (AV match)   ──►                                       │
│                                   │                                 │
│                    ┌──────────────┼──────────────┐                  │
│                    │              │              │                  │
│              VirusTotal      AlienVault OTX   URLScan.io            │
│              (SHA256 hash)   (SHA256 hash)    (SHA256 hash)         │
│                    │              │              │                  │
│                    └──────────────┬──────────────┘                  │
│                                   │                                 │
│              Claude Sonnet 4.6 ◄──┘  (structured metadata only)    │
│              Anthropic API                                          │
│                                   │                                 │
│              confidence score 0-100 → verdict_zone                 │
│              malware_family · mitre_techniques · recommended_action │
│                                   │                                 │
│              RESULT ──► active-responses.log                        │
│                                   │                                 │
│        decoder: fim_ai_intel      │   rules: 109010-109015          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Rule Catalog

### FIM AI Pipeline (fim_ai_rules.xml)

| Rule | Level | Trigger | Action |
|------|-------|---------|--------|
| 109020 | 5 | FIM event in monitored lab path | Fires AR → fim_ai_scan.exe |
| 109000 | 0 | Endpoint scan result received | Grouping |
| 109001 | 5 | YARA match on endpoint | Fires AR → fim_intel_query.py |
| 109002 | 5 | Defender threat on endpoint | Fires AR → fim_intel_query.py |
| 109003 | 3 | Scan complete — no threat | Log for baseline |
| 109010 | 0 | Intelligence result received | Grouping |
| 109011 | 5 | score 0-30 — low confidence | Log for baseline |
| 109012 | 12 | score 31-69 — medium confidence | Analyst review required |
| 109013 | 12 | YARA positive + VT 0/72 | Conflict — manual validation |
| 109014 | 15 | score ≥ 70 — high confidence | Host isolation trigger |
| 109015 | 15 | High confidence + YARA confirmed | Isolation + YARA evidence |

> **Conflict rule**: when YARA reports match but VT returns 0/72, score is capped at 69 regardless of other signals. Automatic isolation (rule 109014) never fires on conflicting signals.

**Confidence score weights**

| Source | Points |
|--------|--------|
| YARA match | 35 |
| Windows Defender detection | 25 |
| VirusTotal malicious ratio (scaled 0-30) | 0–30 |
| OTX pulses | 5–10 |
| Maximum | 100 |

### FIM Anomaly Correlation (fim_anomaly_rules.xml)

| Rule | Level | Trigger | MITRE |
|------|-------|---------|-------|
| 100300 | 10 | 3+ files created in 10 min (same agent) | T1105 |
| 100301 | 12 | Same MD5 in 3+ directories in 10 min | T1565.001 |
| 100302 | 10 | 3+ files modified in 10 min | T1565.001 |
| 100303 | 10 | 3+ files deleted in 10 min | T1485 |
| 100304 | 14 | 5+ mixed FIM events in 10 min | T1485 + T1486 |

> **Engineering note**: Rule 100304 uses `<if_matched_group>syscheck_file</if_matched_group>` to cover rules 550, 553, and 554 in a single correlation. `<if_matched_sid>` with comma-separated SIDs does not work in Wazuh 4.14.x correlation rules.

---

## Repository Structure

```
wazuh-fim-adh/
│
├── rules/
│   ├── fim_ai_rules.xml              # Rules 109000-109020 — FIM AI Pipeline
│   └── fim_anomaly_rules.xml         # Rules 100300-100304 — Anomaly correlation
│
├── decoders/
│   └── fim_ai_decoder.xml            # JSON_Decoder — Stage 1 (fim_ai_endpoint)
│                                     #               Stage 2 (fim_ai_intel)
│
├── active-response/
│   ├── fim_ai_scan.py                # Source — Windows endpoint AR
│   ├── fim_ai_scan.spec              # PyInstaller spec (--runtime-tmpdir required)
│   └── fim_intel_query.py            # Server AR — VT, OTX, URLScan, Claude
│
├── config/
│   ├── ossec_server.conf             # Server ossec.conf — AR, localfile, FIM AI
│   └── ossec_agent_windows.conf      # Agent ossec.conf — explicit paths + ignores
│
├── docs/
│   ├── pipeline_diagram.svg          # FIM + AI Pipeline flow
│   ├── threshold_diagram.svg         # Confidence score zones
│   ├── rule_109020_discover.png      # Discover — 109020 FIM trigger
│   ├── rule_109001_discover.png      # Discover — 109001 YARA match
│   ├── rule_109012_discover.png      # Discover — 109012 medium confidence
│   └── wazuh-fim-documentacao-completa-pt-br.docx   # Full handbook (PT-BR, 60 pages)
│
└── binaries/                         # Distributed separately (password-protected ZIP)
    ├── fim_ai_scan.exe               # PyInstaller-compiled AR (Windows x64)
    ├── yara64.exe                    # YARA 4.5.5 (Windows x64)
    └── yara_rules.yar               # Valhalla demo ruleset — 1298 rules, CC-BY-NC
```

> The compiled binaries and YARA ruleset are distributed in `fim-ai-pipeline-binaries.zip` (password-protected) because unsigned executables and YARA rule content trigger AV false positives on download. SHA-256 hashes in `SHA256SUMS`.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Wazuh Server | 4.14.8 — WZ-SRV, Ubuntu 24.04 LTS, 3.9 GB RAM |
| Windows Agent | 4.14.8 — LABDESK, Windows 11 Pro (build 26200), user `kr` |
| YARA | 4.5.5 — `winget install VirusTotal.YARA` |
| Ruleset | Valhalla demo — 1298 rules, 1.2 MB (`yara_rules.yar`) |
| AR build | PyInstaller 6.22.3, Python 3.13.3 |
| Intelligence | VirusTotal, AlienVault OTX, URLScan.io, Anthropic (Claude Sonnet 4.6) |

---

## Requirements

- Wazuh Server 4.14.8 and Wazuh Agent 4.14.8
- Windows endpoint: Python 3.10+, PyInstaller 6.x (build only)
- YARA 4.5.5 for Windows
- API keys for VirusTotal, AlienVault OTX, URLScan.io, and Anthropic — stored in `/var/ossec/etc/fim-ai/keys.env`

---

## Deployment

### Step 1 — Server: rules, decoders, AR script

```bash
cp rules/fim_ai_rules.xml /var/ossec/etc/rules/
cp rules/fim_anomaly_rules.xml /var/ossec/etc/rules/
cp decoders/fim_ai_decoder.xml /var/ossec/etc/decoders/
cp active-response/fim_intel_query.py /var/ossec/active-response/bin/
chmod 750 /var/ossec/active-response/bin/fim_intel_query.py
chown root:wazuh /var/ossec/active-response/bin/fim_intel_query.py
```

### Step 2 — Server: API keys

```bash
mkdir -p /var/ossec/etc/fim-ai
cp config/keys.env.example /var/ossec/etc/fim-ai/keys.env
# Fill in VT_API_KEY, OTX_API_KEY, URLSCAN_API_KEY, ANTHROPIC_API_KEY
chmod 640 /var/ossec/etc/fim-ai/keys.env
chown root:wazuh /var/ossec/etc/fim-ai/keys.env
```

### Step 3 — Server: validate and restart

```bash
/var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -i error
systemctl restart wazuh-manager
```

Expected: exit 0, zero errors.

### Step 4 — Windows endpoint (PowerShell — elevated)

```powershell
# Create PyInstaller runtime tmpdir (required — see Lab Finding 1)
New-Item -ItemType Directory -Force "C:\Program Files (x86)\ossec-agent\active-response\fim_ai_tmp"

# Deploy binaries (from fim-ai-pipeline-binaries.zip)
Copy-Item fim_ai_scan.exe "C:\Program Files (x86)\ossec-agent\active-response\bin\fim_ai_scan.exe" -Force
New-Item -ItemType Directory -Force "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules"
Copy-Item yara64.exe "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe" -Force
Copy-Item yara_rules.yar "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar" -Force

# Apply agent config
Copy-Item config\ossec_agent_windows.conf "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
Restart-Service -Name WazuhSvc
```

### Step 5 — Windows: audit policy (required for whodata)

```powershell
# File System and Handle Manipulation — must be Success
auditpol /set /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}" /success:enable
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable
auditpol /get /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}","{0CCE921D-69AE-11D9-BED3-505054503030}"
```

Expected: `Sistema de arquivos: Êxito` / `Manipulação de Identificador: Êxito`

> In domain environments apply via GPO: **Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Object Access > File System** and **Handle Manipulation**.

---

## Building fim_ai_scan.exe

The binary is distributed pre-compiled. To rebuild from source — PowerShell **without elevation**, outside monitored paths:

```powershell
New-Item -ItemType Directory -Force C:\build\fim_ai
Set-Location C:\build\fim_ai
pyinstaller --onefile --name fim_ai_scan `
  --runtime-tmpdir "C:\Program Files (x86)\ossec-agent\active-response\fim_ai_tmp" `
  fim_ai_scan.py
```

> `--runtime-tmpdir` is mandatory. Without it, PyInstaller extracts the Python runtime to `C:\Windows\Temp` on each execution. If `C:\Windows\Temp` is monitored by syscheck, each extraction triggers a FIM 554 alert, which fires the AR, which extracts again — a self-feeding loop generating 43-124 alerts/minute. See **Lab Finding 1** for the full incident timeline with evidence.

Build environment: PyInstaller 6.22.3, Python 3.13.3, Windows 11 (10.0.26200).

Verify the `--runtime-tmpdir` is embedded in the binary:

```bash
strings -a fim_ai_scan.exe | grep -i 'runtime-tmpdir'
```

---

## Validation

### Quick test — Stage 1 (no malware required)

Add the lab YARA rule to the ruleset and create the test file:

```powershell
# Append lab YARA rule
$rule = @"

rule FIM_AI_Lab_Test {
    meta:
        description = "FIM AI Pipeline lab validation"
        author = "Kislley Rodrigues"
        date = "2026-10-02"
    strings:
        `$s1 = "FIM_AI_YARA_TRIGGER_LAB"
    condition:
        `$s1
}
"@
Add-Content "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar" $rule -Encoding ASCII

# Verify YARA detects before triggering the pipeline
"FIM_AI_YARA_TRIGGER_LAB" | Out-File "C:\Users\<user>\Downloads\lab_test.txt" -Encoding ASCII -NoNewline
& "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe" -w `
  "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar" `
  "C:\Users\<user>\Downloads\lab_test.txt"
```

Expected YARA output: `FIM_AI_Lab_Test C:\Users\<user>\Downloads\lab_test.txt`

### Verify Stage 1 result on endpoint

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" `
  -Pattern "lab_test" | Select-Object -Last 3
```

### Verify Stage 2 on server

```bash
tail -5 /var/ossec/logs/fim-ai-results.log
grep -a "wazuh-fim-ai-intel.*lab_test" /var/ossec/logs/active-responses.log | tail -1
```

### Verify alerts in Wazuh Discover

```
agent.name:LABDESK AND rule.id:(109020 OR 109001 OR 109012)
```

---

## Production Validation Evidence

### Stage 1 — Rule 109020 (FIM trigger in monitored path)

FIM detects `test10.txt` in `C:\Users\kr\Downloads` via realtime monitoring:

[![Rule 109020 — Discover](https://raw.githubusercontent.com/mym0us3r/wazuh-fim-adh/main/docs/rule_109020_discover.png)](https://raw.githubusercontent.com/mym0us3r/wazuh-fim-adh/main/docs/rule_109020_discover.png)

---

### Stage 1 — Rule 109001 (YARA match confirmed)

`fim_ai_scan.exe` matched rule `FIM_AI_Lab_Test`. Stage 2 triggered:

[![Rule 109001 — Discover](https://raw.githubusercontent.com/mym0us3r/wazuh-fim-adh/main/docs/rule_109001_discover.png)](https://raw.githubusercontent.com/mym0us3r/wazuh-fim-adh/main/docs/rule_109001_discover.png)

---

### Stage 2 — Rule 109012 (medium confidence — analyst review)

`fim_intel_query.py` completed: VT 0/0 (unknown hash), score=35 (YARA only), zone=medium:

[![Rule 109012 — Discover](https://raw.githubusercontent.com/mym0us3r/wazuh-fim-adh/main/docs/rule_109012_discover.png)](https://raw.githubusercontent.com/mym0us3r/wazuh-fim-adh/main/docs/rule_109012_discover.png)

---

### End-to-end timeline (test10.txt, LABDESK, 02/10/2026)

| Timestamp | Rule | Description |
|-----------|------|-------------|
| 19:25:23 | 109020 | FIM detects `C:\Users\kr\Downloads\test10.txt` — realtime |
| 19:25:27 | 67027 | EventID 4688 — `fim_ai_scan.exe` spawned by `wazuh-agent.exe` |
| 19:25:27 | 67027 | EventID 4688 — `yara64.exe` spawned by `fim_ai_scan.exe` |
| 19:25:29 | 109001 | YARA match: `FIM_AI_Lab_Test` — Stage 2 triggered |
| 19:25:39 | 109012 | score=35, zone=medium, conflict=False — analyst review |

**Total latency FIM to verdict: 16 seconds.**

---

### Stage 2 — WannaCry hash validation (SHA256: ed01ebfbc...)

Manual injection with WannaCry SHA256 to validate full Stage 2 stack with real threat intelligence:

```
Processing: c:\users\kr\downloads\wannacry.exe | SHA256: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
Done: score=90 zone=high conflict=False
```

Active Response RESULT line — rule 109015 (HIGH CONFIDENCE + YARA confirmed):

```json
{
  "source": "fim-ai-intel",
  "agent": "LABDESK",
  "file_path": "c:\\users\\kr\\downloads\\wannacry.exe",
  "vt_malicious": 67,
  "vt_total": 75,
  "vt_family": "ransomware.wannacry/wannacryptor",
  "confidence_score": 90,
  "verdict_zone": "high",
  "conflict": false,
  "malware_family": "WannaCry ransomware (Ransom:Win32/WannaCrypt)",
  "mitre_techniques": ["T1566", "T1204.002", "T1486", "T1490", "T1082", "T1057", "T1070.004"],
  "recommended_action": "Immediately isolate the host from the network..."
}
```

---

## Lab Findings

Six technical findings documented during deployment on Windows. All are reproducible and apply to any Wazuh Active Response Python deployment on Windows.

### Finding 1 — PyInstaller `--onefile` loop via `C:\Windows\Temp`

A `--onefile` PyInstaller executable extracts its Python runtime to a `_MEIxxxxxx` subdirectory in the OS temp directory (`C:\Windows\Temp` for the SYSTEM account) on every execution. If `C:\Windows\Temp` is monitored by syscheck, each extraction generates a FIM 554 alert, which triggers another AR execution, which extracts again.

**Evidence**: 3335 alerts from `c:\windows\temp\_mei*` paths in three hours. Rate reached 43-124 alerts/minute before the AR was disabled on the server.

**Fix**: `--runtime-tmpdir` pointing to an unmonitored path inside the agent installation directory.

### Finding 2 — PowerShell SYSTEM profile loop

`run_defender()` calls `powershell.exe` as SYSTEM. PowerShell rewrites `StartupProfileData-NonInteractive` in `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell` on each invocation. If `C:\Windows\System32` is monitored with `whodata`, each rewrite generates a FIM 550 alert, triggering the AR, which calls PowerShell again — a 1:1 gain loop cycling every ~4.5 seconds.

**Fix**: add `<ignore>` for that path in the agent `ossec.conf`.

```xml
<!-- FIM AI Pipeline: path written by the active response itself (PowerShell as SYSTEM) -->
<ignore>C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell</ignore>
```

### Finding 3 — Windows Active Response requires a compiled `.exe`

Wazuh `wazuh-execd` on Windows does not reliably pass stdin to `.bat` or `.ps1` child processes. The JSON alert payload written to stdin is not received by the script, which exits silently with error 1317 (`ERROR_INVALID_HANDLE`).

**Fix**: compile the Python script to `.exe` with PyInstaller. The execd spawns the `.exe` directly and the stdin pipe is inherited correctly.

### Finding 4 — `field name="file"` not `syscheck.path` in custom FIM rules

Custom rules that match on the file path must use `<field name="file">`. The field `syscheck.path` is visible in `alerts.json` but does not resolve in the rules engine for child rule matching.

**Reference**: [Wazuh FIM fields correspondence table](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html).

### Finding 5 — AR scope saturation from high-frequency paths

With AR configured for rules 554/550 across all monitored paths, high-frequency sources (Chrome `.crdownload`, Trend Micro `tasks.json` at ~60s, Sublime Text autosave) generate continuous AR executions — each costing YARA compilation of 1298 rules + Defender scan. The pipeline becomes unable to process events from actual malware-landing paths.

**Fix**: rule 109020 using `<if_group>syscheck_file</if_group>` + `<field name="file" type="pcre2">` restricts AR to specific lab paths. The AR block in `ossec.conf` points to 109020 instead of 554/550.

### Finding 6 — Logcollector loses tracking after manager restart

After `systemctl restart wazuh-manager`, the logcollector may stop reading `active-responses.log`. Stage 2 results are written to the file but not indexed or decoded.

**Diagnosis**:
```bash
grep -a "active-responses" /var/ossec/logs/ossec.log | tail -5
```
If the last `(1950): Analyzing file` entry predates the current Stage 2 results, restart the manager again to force re-indexing.

---

## Whodata on Windows — `auditpol` requirement

Windows Defender and the Windows kernel reset audit SACLs on shell folders (Downloads, Desktop, Documents) independently of Wazuh configuration. When the SACL is reset, Wazuh logs `(6021): The SACL of '<path>' has been modified and it is not valid for the real-time Whodata mode` and disables whodata for that path.

The root cause is that `Windows Defender` manages the SACL of special shell folders for its own audit rules and overwrites entries applied by the Wazuh agent. The `windows_audit_interval=60` parameter in `ossec.conf` only reapplies the SACL if the underlying audit policy is already set to **Success**. With the default `Sem Auditoria` (No Auditing), the SACL cannot be maintained.

```powershell
# Verify current state
auditpol /get /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}","{0CCE921D-69AE-11D9-BED3-505054503030}"
# Must show: Êxito (Success) for both subcategories
```

Special shell folders (Downloads, Desktop, Documents) remain unstable for `whodata` even after applying the policy on workgroup machines with Tamper Protection enabled. Use `realtime="yes"` on user paths and reserve `whodata="yes"` for stable system paths (System32, drivers, wbem, WindowsPowerShell).

---

## Comparison: FIM monitoring modes (Windows)

| Mode | User required | SACL dependency | `user` field | `process` field |
|------|---------------|-----------------|--------------|-----------------|
| `realtime` | No | No | Empty | Empty |
| `whodata` | Audit policy set to Success | Yes — resets on shell folders | Populated | Populated |
| Scheduled scan | No | No | Empty | Empty |

---

## References

- [Wazuh FIM documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Creating custom FIM rules](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html)
- [Wazuh Active Response — custom scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
- [Wazuh syscheck configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)
- [Wazuh 4.14.8 release notes](https://documentation.wazuh.com/current/release-notes/release-4-14-8.html)
- [PyInstaller — `--runtime-tmpdir`](https://pyinstaller.org/en/stable/usage.html)
- [PyInstaller — How the One-File Program Works](https://pyinstaller.org/en/stable/operating-mode.html)
- [Valhalla YARA Rule Set](https://valhalla.nextron-systems.com/) (Nextron Systems, CC-BY-NC 4.0)
- [MITRE ATT&CK T1204.002 — Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [DIRTY-FRAG Detection with Wazuh 4.14.4](https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4)
- [COPY-FAIL Detection with Wazuh 4.14.4](https://github.com/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4)

---

## Author

**Kislley Rodrigues (m0us3r)** Wazuh Ambassador | Detection Engineering | Blue Team

---

## Acknowledgments

- **Wazuh Team** for the open SIEM/XDR platform and Ambassador Program
- **Nextron Systems** for the Valhalla YARA Rule Set (demo tier, CC-BY-NC 4.0)

---

*Detection rules, decoders, Active Response pipeline, and agent configuration validated on Wazuh 4.14.8, Windows 11 Pro (build 26200), PyInstaller 6.22.3, YARA 4.5.5, and Valhalla demo ruleset (1298 rules, obtained 01/10/2026).*

---

## Wazuh

This project was developed as part of the [Wazuh Ambassador Program](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

Wazuh is a free, open source security platform that provides unified XDR and SIEM protection.
Learn more at [wazuh.com](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).
