# Wazuh FIM in Depth - The Advanced Defender's Handbook

**English** | [Português (BR)](README.pt-BR.md)

> **Detection engineering on top of Wazuh 4.14.8 File Integrity Monitoring · Windows and Linux · anomaly correlation + AI-assisted investigation**

![custom_rules](https://img.shields.io/badge/custom_rules-6-brightgreen)
![findings](https://img.shields.io/badge/validated_findings-15-blue)
![refuted](https://img.shields.io/badge/refuted_hypothesis-1-lightgrey)
![status](https://img.shields.io/badge/status-lab--validated-success)
![wazuh](https://img.shields.io/badge/wazuh-4.14.8-005571)
![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![mitre](https://img.shields.io/badge/MITRE-T1565-red)
![mitre](https://img.shields.io/badge/MITRE-T1485-red)
![mitre](https://img.shields.io/badge/MITRE-T1486-red)
![mitre](https://img.shields.io/badge/MITRE-T1105-red)

---

## What is this project?

The Wazuh FIM module answers three questions with precision: **what changed, when it changed and, with whodata, who changed it**. In production, most coverage problems come from somewhere else: the operating system's audit subsystem underneath FIM, the internal behavior of `wazuh-analysisd` when it correlates events, and silent failures that `ossec.conf` does not reveal.

This repository documents a lab project that went from the problem to the solution, with evidence at every step. It delivers three capabilities built on the native FIM engine:

**1. Anomaly correlation rules.** Threshold-based detection of mass file operations (ransomware staging, anti-forensics, bulk dropper delivery), using `<if_matched_group>` and `<if_matched_sid>`. Six custom rules, no external dependencies.

**2. FIM Alert Investigation.** AI-assisted investigation panel integrated with the [WAZUH-Process-Tree-Viewer](https://github.com/mym0us3r/WAZUH-Process-Tree-Viewer). The analyst selects a FIM alert and triggers Claude Sonnet 4.6 with the full context (±60 s, same agent). The result is a structured verdict with `risk_score`, MITRE techniques with confidence, IOCs and recommended actions.

**3. Hardened endpoint configuration.** A validated `ossec.conf` for Windows and Linux, with explicit per-user paths, `whodata` on system directories and `realtime` on user paths, plus the technical findings that the official material does not cover.

All of it is consolidated in the **Handbook** (53 pages, PT-BR), in [`docs/`](docs/). An EN-US edition is on the [ROADMAP](ROADMAP.md).

> Developed as part of the [Wazuh Ambassador Program](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

---

## Reference Environment

| Component | Platform | Role |
|---|---|---|
| WZ-SRV | Ubuntu 24.04 LTS, 3.9 GB RAM, Wazuh 4.14.8 | Manager, Indexer, Dashboard and WPTV (Flask) |
| LABDESK | Windows 11 Pro (build 26200), agent 4.14.8 | Windows agent: file system and Registry FIM |
| labnix | Ubuntu 24.04.5, kernel 6.17.0, agent 4.14.8 | Current Linux agent: realtime, whodata and auditd |
| pentlab | Kali Linux (kernel 6.x), agent 4.14.5 | Linux agent for the initial validations on 4.14.7 |
| Intelligence | Claude Sonnet 4.6, VirusTotal, AlienVault OTX, AbuseIPDB | Analysis and enrichment for FIM Alert Investigation |

Part of the correlation scenarios ran on 4.14.7 and the current pipeline runs on 4.14.8. Volume and latency figures reflect a 3.9 GB RAM server and are not a production sizing.

---

## Why advanced FIM?

```
Scheduled scan:
  read file -> compute hash -> compare -> alert on change
  problem: everything that happens between scans is invisible

Realtime FIM without context:
  file created at 14:32:07 -> alert fired
  analyst reviews at 14:45 -> file already executed or deleted
  problem: detection without context is noise

FIM Alert Investigation (this repository):
  file created -> FIM detects (rule 554, displayed as 100310)
  analyst selects the alert -> triggers Claude Sonnet 4.6
  ±60 s context: file, registry and process events correlated
  verdict: risk_score, MITRE ATT&CK, IOCs, recommended actions
```

---

## The Project Story

The project went through four stages. Each one produced findings that changed the next.

**Stage 1 - Detect behavior, not just change.** A single file-creation alert says little. The question became "how many, in how much time, on the same agent". Rules 100300 to 100304, based on volume, came out of it.

**Stage 2 - The correlation engine has its own rules.** Two rules using `<if_matched_sid>` on the same SID share the accumulator and interfere with each other (findings AC-3, AC-5 and AC-6). The fix was the **proxy rule 100310**, a child of 554, which re-emits each creation to two independent groups (`fim_creation` and `fim_new_entry`) and isolates the counters of 100300 and 100301.

**Stage 3 - Every mechanism has a side effect.** The child rule 100310 started suppressing the parent rule 554 in `wazuh-alerts-*`: only 100310 reaches the index. With 100310 at level 0, the alert disappears entirely and the event shows up only in `wazuh-archives-*`, with no `rule` field. 100310 runs at level 5 and the investigation panel now treats it as a file rule (finding AC-7).

**Stage 4 - From alert to verdict.** With stable detection, FIM Alert Investigation closes the loop: ±60 s context, threat intelligence enrichment and LLM analysis. FIM-to-verdict latency measured on labnix: **16 seconds**.

### A refuted hypothesis, documented on purpose

During Linux validation, a window of missing realtime events on labnix led to the hypothesis that the inotify reader of `wazuh-syscheckd` was stalled, which would justify an issue in the Wazuh repository. Reproducing before reporting showed the opposite:

- The manager's `archives.json` records **41 events** from labnix in the window, **36 of them in `realtime` mode**.
- The `strace` of `syscheckd` shows `read()` on the `anon_inode:inotify` descriptor. The original observation had filtered the wrong syscall: the daemon waits with `pselect6`, which the old filter did not capture.
- The 21 `added` events without an associated rule are consistent with creations hidden by proxy rule 100310 while it ran at level 0 (effect of finding AC-7), not with lost events.

**Verdict: DOES NOT HOLD.** Not an upstream issue. Finding AP-1 stays in the Handbook as a refuted hypothesis, with the method and the flaws that produced it. The practical takeaway: to confirm that realtime delivers events, check `syscheck.mode` in `archives.json` (or in `wazuh-archives-*`) and never query the live `fim.db` (it returns `database is locked`).

---

## Architecture

```
Agent (syscheckd)
  scheduled | realtime (inotify) | whodata (auditd / SACL)
        |
        v
Manager: analysisd
  rule 554 (added) -> child 100310 -> groups fim_creation, fim_new_entry
  rule 550 (modified) | 553 (deleted) | syscheck_file
        |
        v
Correlation rules 100300-100304  ->  wazuh-alerts-*
        |
        v
FIM Alert Investigation (WPTV, Forensics tab)
  GET  /api/fim/alerts   -> FIM alert list
  GET  /api/fim/context  -> ±60 s context (file, registry, process)
  POST /api/fim/analyze  -> Claude Sonnet 4.6 -> structured verdict
```

```
Nginx:
  /wptv/     -> Flask :5000 (WPTV - process tree)
  /fim/      -> Flask :5000 (FIM Alert Investigation)
  /api/fim/  -> Flask :5000 (FIM panel API)
```

The LLM receives the event context, never the file content.

---

## Anomaly Correlation Rules

File: `/var/ossec/etc/rules/fim_anomaly_rules.xml` (permissions `660 wazuh:wazuh`).

| Rule | Level | Correlation | Trigger | MITRE |
|---|---|---|---|---|
| 100310 | 5 | `if_sid 554` | Proxy: re-emits each creation to `fim_creation` and `fim_new_entry` | - |
| 100300 | 10 | `if_matched_group fim_creation` | 3+ files created in 10 min (same agent) | T1565, T1565.001, T1074 |
| 100301 | 12 | `if_matched_group fim_new_entry` | Same MD5 (`md5_after`) in 3+ directories in 10 min | T1105, T1570 |
| 100302 | 10 | `if_matched_sid 550` | 3+ files modified in 10 min | T1565, T1565.001 |
| 100303 | 10 | `if_matched_sid 553` | 3+ files deleted in 10 min | T1485, T1070, T1561 |
| 100304 | 14 | `if_matched_group syscheck_file` | 5+ mixed events in 10 min | T1485, T1486, T1565 |

> **Technical note 1:** `<if_sid>` defines a child rule (fires on the same event). `<if_matched_sid>` defines temporal correlation (independent counter, `frequency` events within the `timeframe`). 100310 uses the first mechanism so that 100300 and 100301 can use the second on distinct groups.

> **Technical note 2:** `<if_matched_sid>` with comma-separated SIDs does not work in correlation rules on Wazuh 4.14.x. Rule 100304 uses `<if_matched_group>syscheck_file</if_matched_group>` to cover 550, 553 and 554 in a single correlation.

> **Calibration warning:** `frequency="3"`, `timeframe="600"` and `ignore="30"` were calibrated for the lab. In production, tune them against a baseline of normal activity per agent group.

### Validation matrix

| Rule | Scenario | LABDESK (Windows) | pentlab (Linux) |
|---|---|---|---|
| 100310 | Isolation proxy (level 5) | CONFIRMED | - (validated on labnix) |
| 100300 | 3+ creations in 10 min | CONFIRMED | CONFIRMED |
| 100301 | Same hash, distinct directories | NOT CONFIRMED | CONFIRMED |
| 100302 | 3+ modifications in 10 min | CONFIRMED | CONFIRMED |
| 100303 | 3+ deletions in 10 min | CONFIRMED | CONFIRMED |
| 100304 | 5+ mixed events (level 14) | CONFIRMED | CONFIRMED |

For rule 100301 on Windows, `same_field` over `syscheck` fields was not confirmed in the tests of 2026-09-16. Windows endpoints keep creation coverage through 100300 and escalation coverage through 100304.

---

## Technical Findings

Fifteen validated findings and one refuted hypothesis, all backed by lab evidence. The detail (behavior, impact, mitigation) is in chapter 10 of the Handbook.

| ID | Finding | Type | Status |
|---|---|---|---|
| AC-1 | `same_field` must use `md5_after` | Correlation | RESOLVED |
| AC-2 | `if_matched_sid` with multiple SIDs is unreliable | Correlation | RESOLVED |
| AC-3 | Counter interference between 100300 and 100301 | Correlation | RESOLVED |
| AC-4 | `wazuh-logtest` does not process syscheck events | Validation | EXPECTED |
| AC-5 | Counter interference confirmed on Linux | Correlation | RESOLVED |
| AC-6 | Child-parent interference on 100300 | Correlation | RESOLVED |
| AC-7 | 100310 level and suppression of 554 | Correlation | RESOLVED |
| AO-1 | `field name="file"`, not `syscheck.path` | Rules | RESOLVED |
| AO-2 | Syscheck saturation by noise sources | Endpoint | RESOLVED |
| AO-3 | `auditpol` required for whodata on Windows workgroup | Endpoint | RESOLVED |
| AO-4 | nginx `client_max_body_size` for analysis payloads | Integration | RESOLVED |
| AO-5 | AbuseIPDB is only queried via auditd `connect` | Integration | RESOLVED |
| AO-6 | VirusTotal does not detect custom payloads | Integration | EXPECTED |
| AO-7 | `windows_audit_interval` does not restore the SACL after a manager restart | Windows | MITIGATED |
| AO-8 | Path with `/*` expands the glob into individual files | Endpoint | RESOLVED |
| AP-1 | Inotify reader stall hypothesis (refuted) | Linux daemon | DOES NOT HOLD |

Two findings deserve immediate attention in any deployment, because they degrade coverage without logging an error:

- **AO-7 (Windows):** after a manager restart, the whodata SACL is not reapplied by `windows_audit_interval`. On LABDESK the gap was about 25 minutes without whodata coverage, until a manual `Restart-Service WazuhSvc`. Mitigation: restart the agent after the manager restart.
- **AO-8 (Linux):** `<directories>` with `/*` registers watches on individual files and leaves new files without realtime coverage. Use the directory without the wildcard. According to the [official documentation](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html), realtime works with directories, not with individual files.

---

## Repository Structure

```
wazuh-fim-adh/
│
├── rules/
│   └── fim_anomaly_rules.xml         # Rules 100310 + 100300-100304
│
├── decoders/
│   └── fim_ai_decoder.xml            # JSON_Decoder Stage 1 (fim_ai_endpoint)
│                                     #               Stage 2 (fim_ai_intel)
│
├── config/
│   ├── ossec_server.conf             # Server ossec.conf
│   ├── ossec_agent_windows.conf      # Windows agent: paths + ignores
│   └── ossec_agent_linux.conf        # Linux agent: whodata + realtime
│
├── wptv-fim/                         # WAZUH-Process-Tree-Viewer extension
│   ├── logic_fim.py                  # FIM investigation logic
│   ├── server.py                     # /api/fim/* routes
│   └── public/
│       └── fim.html                  # FIM Alert Investigation panel
│
├── docs/
│   ├── wazuh-fim-advanced-defenders-handbook-pt-br.docx   # Full Handbook (53 pages)
│   └── ev_*.png                      # Wazuh Discover and panel evidence
│
├── README.md                         # English
├── README.pt-BR.md                   # Português (BR)
└── ROADMAP.md
```

---

## Requirements

- Wazuh Server 4.14.8 and agents 4.14.8
- Python 3.10+ on the server (for `logic_fim.py`)
- API keys: VirusTotal, AlienVault OTX, AbuseIPDB and Anthropic, stored in `/etc/wazuh-process-tree/wptv.env`
- WAZUH-Process-Tree-Viewer installed (`/usr/share/wazuh-dashboard/plugins/process_tree_api/`)
- Filebeat with the archives module enabled (`archives.enabled: true` in `filebeat.yml`)
- `logall_json: yes` in the server `ossec.conf`, required for process context in the panel

---

## Deployment

### Step 1 - Correlation rules

```bash
cp rules/fim_anomaly_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/fim_anomaly_rules.xml
chmod 660 /var/ossec/etc/rules/fim_anomaly_rules.xml

# Validate the syntax before restarting
/var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5

systemctl restart wazuh-manager
```

### Step 2 - Agent configuration

Apply `config/ossec_agent_linux.conf` or `config/ossec_agent_windows.conf` to the agent `ossec.conf` and replace the manager address placeholders. Points of attention:

- `whodata` on system directories and `realtime` on user paths.
- Directories without `/*` (finding AO-8).
- Windows in a workgroup: enable object access auditing with `auditpol` (finding AO-3).

```cmd
auditpol /set /subcategory:"File System" /success:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable
```

### Step 3 - FIM Alert Investigation

```bash
DEST=/usr/share/wazuh-dashboard/plugins/process_tree_api

# Backup
cp $DEST/server.py $DEST/server.py.bak-$(date +%Y%m%d)

# Deploy
cp wptv-fim/logic_fim.py      $DEST/logic_fim.py
cp wptv-fim/server.py         $DEST/server.py
cp wptv-fim/public/fim.html   $DEST/public/fim.html

# Permissions
chown wazuh-dashboard:wazuh-dashboard \
  $DEST/logic_fim.py $DEST/server.py $DEST/public/fim.html
chmod 755 $DEST/logic_fim.py $DEST/server.py
chmod 644 $DEST/public/fim.html

# wptv.env - add the Anthropic key and the archives index
echo "WPTV_ANTHROPIC_API_KEY=<your_key>" >> /etc/wazuh-process-tree/wptv.env
echo "WPTV_ARCHIVE_INDEX=wazuh-archives-*" >> /etc/wazuh-process-tree/wptv.env

# Restart
systemctl restart wazuh-process-tree
```

### Step 4 - Nginx (`/etc/nginx/sites-enabled/wptv`)

```nginx
server {
    listen 443 ssl;
    server_name YOUR-WAZUH-SERVER-IP;   # Server IP or FQDN

    # Restrict HTTPS access to your IP
    allow YOUR-ADMIN-IP;
    deny all;

    ssl_certificate     /etc/wazuh-dashboard/certs/wazuh-dashboard.pem;
    ssl_certificate_key /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem;

    # FIM/WPTV analysis payloads can exceed the 1MB default
    client_max_body_size 10m;

    location / {
        proxy_pass              https://127.0.0.1:5601;
        proxy_ssl_verify        off;
        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_read_timeout      120s;
    }

    location /wptv/ {
        proxy_pass              https://127.0.0.1:5000/;
        proxy_ssl_verify        off;
        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_read_timeout      120s;
    }

    location /fim/ {
        proxy_pass              https://127.0.0.1:5000;
        proxy_ssl_verify        off;
        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_read_timeout      120s;
    }

    location /api/fim/ {
        proxy_pass              https://127.0.0.1:5000;
        proxy_ssl_verify        off;
        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_read_timeout      120s;
    }
}
```

> `client_max_body_size 10m` is mandatory (finding AO-4): the `POST /api/fim/analyze` payload exceeds the default 1MB limit. Without it, nginx returns an HTML HTTP 413 before forwarding to Flask and the frontend fails with `Unexpected token '<'`.

---

## Validation

### Confirm that realtime delivers events

The alert may be hidden by the proxy rule (AC-7). The source of truth is `archives.json`, which requires `logall_json: yes`. On the manager:

```bash
grep '"syscheck"' /var/ossec/logs/archives/archives.json \
  | jq -c '{timestamp, agent:.agent.name, rule:.rule.id, mode:.syscheck.mode, event:.syscheck.event, path:.syscheck.path}'
```

The `mode` field is `realtime`, `whodata` or `scheduled`. An `added` event with `rule: null` indicates a creation hidden by the proxy at level 0 (finding AC-7), not a lost event.

### Create, modify and delete test

```bash
# On the Linux agent
echo "test" > /home/kr/Downloads/fim_test.txt        # 554 (displayed as 100310)
echo "more" >> /home/kr/Downloads/fim_test.txt       # 550
rm -f /home/kr/Downloads/fim_test.txt                # 553
```

To trigger the correlation thresholds, repeat the operation 3 times (or 5 times for 100304) within 10 minutes.

---

## Validation Evidence

All images are real captures from Wazuh Discover and from the FIM Alert Investigation panel. The Handbook has the complete set, with captions.

### Rule 100310 - proxy for 554 (level 5)

Validated on LABDESK (2026-10-10 at 02:14:29 and 02:13:56) and on labnix (02:30:14 and 02:31:41 with the old description, 02:35:52 with the new one).

![Rule 100310 - LABDESK](docs/ev_regra_100310_labdesk.png)

![Rule 100310 - labnix, updated description](docs/ev_regra_100310_labnix_descricao.png)

### File creation - 554 and 100300 (labnix)

16 hits for 554 (`p100301v3.txt` created on 2026-10-09 at 20:51:17, realtime mode) and 22 hits for 100300 in 24 hours.

![Rule 554 - labnix, 16 hits](docs/ev_regra_554_labnix_16_hits.png)

![Rule 100300 - labnix](docs/ev_regra_100300_labnix.png)

### Same hash in distinct directories - 100301 (pentlab)

![Rule 100301 - pentlab](docs/ev_regra_100301_pentlab.png)

### File modification - 550 and 100302 (labnix)

25 hits for 550 (`elif.zip` and `file.zip` modified on 2026-10-09 at 23:51) and 100302 on `beacon_test.sh`.

![Rule 550 - labnix, 25 hits](docs/ev_regra_550_labnix_25_hits.png)

![Rule 100302 - labnix](docs/ev_regra_100302_labnix.png)

### File deletion - 553 and 100303 (labnix)

34 hits for 553 between 23:08 and 23:15 on 2026-10-09, with 100303 at 23:08:33 and 23:15:16.

![Rule 553 - labnix, 34 hits](docs/ev_regra_553_labnix_34_hits.png)

![Rule 100303 - labnix](docs/ev_regra_100303_labnix.png)

### Escalation - 100304 (LABDESK)

![Rule 100304 - LABDESK](docs/ev_regra_100304_labdesk.png)

### FIM Alert Investigation - post-exploitation simulation on Windows

The `up.ps1` script ran three phases on LABDESK: staging, reconnaissance (11 commands) and lateral copy. Result: 44 FIM alerts, rule 100302 fired, FIM + process tree correlation (EventID 4688) confirmed.

![14-event context in the ±60 s window](docs/ev_fim_investigation_context_14_eventos.png)

![Focal alert 100302](docs/ev_fim_investigation_focal_alert_100302.png)

![LLM verdict - risk_score 87, CRITICAL, 11 MITRE techniques](docs/ev_fim_investigation_veredito_risk_87.png)

![IOCs and recommended actions](docs/ev_fim_investigation_iocs_recomendacoes.png)

### Validated output on Linux (labnix, 2026-10-06)

```
Focal alert: PROC_CONTEXT.txt added in /home/kr/Downloads/
±60 s context: 8 process events with key: lpe_quartet_root_netlink_route

LLM verdict:
  risk_score: 50 | risk_level: MEDIUM
  T1068 Exploitation for Privilege Escalation - 52% confidence
  IOC: /usr/bin/vmtoolsd triggering the LPE audit key
  Action: audit vmtoolsd integrity and correlate the audit key
          across the full SIEM timeline
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Rules |
|---|---|---|
| Data Manipulation | T1565 | 100300, 100302, 100304 |
| Stored Data Manipulation | T1565.001 | 100300, 100302 |
| Data Staged | T1074 | 100300 |
| Ingress Tool Transfer | T1105 | 100301 |
| Lateral Tool Transfer | T1570 | 100301 |
| Data Destruction | T1485 | 100303, 100304 |
| Indicator Removal | T1070 | 100303 |
| Disk Wipe | T1561 | 100303 |
| Data Encrypted for Impact | T1486 | 100304 |

Chapter 9 of the Handbook also covers compliance mapping (PCI DSS 4.0, NIST 800-53 Rev 5, HIPAA, GDPR and SOC 2).

---

## Handbook Contents

The Handbook is written in PT-BR. Chapters:

| Chapter | Content |
|---|---|
| 1. Sumário Executivo | Results, structure and reference environment |
| 2. Fundamentos do FIM | Architecture, the three modes, parameters, network paths and delta sync |
| 3. FIM em Windows | SACL, `auditpol`, GPO, `windows_audit_interval`, rename and Registry |
| 4. FIM em Linux | auditd, persistent rules, audit-keys CDB, eBPF provider, inotify and troubleshooting |
| 5. Regras de Detecção de Anomalia | Six rules, the 100310 proxy pattern and per-platform evidence |
| 6. FIM Alert Investigation | Architecture, threat intelligence, LLM verdict and validations |
| 7. Regras Complementares | Agent lifecycle (504, 505, 506), inotify overflow (560) and Registry |
| 8. Perspectiva do Adversário | Evasion, timestomping and ransomware event pattern |
| 9. Compliance e MITRE ATT&CK | PCI DSS, NIST, HIPAA, GDPR, TSC and techniques |
| 10. Achados Técnicos | 15 validated findings and 1 refuted hypothesis |
| 11. Configurações de Referência | What is new in 4.14.8, hardened `ossec.conf`, server state |

---

## Validation Limits

- The formal controlled-threshold test of rules 100300 to 100304, with documented scenarios on LABDESK and labnix, is an open step (see [ROADMAP.md](ROADMAP.md)). Current evidence comes from simulation scripts and real indexed alerts.
- Rule 100301 was not confirmed on Windows.
- The correlation parameters are lab values and require a baseline in production.
- The 60 s `syscheck frequency` is a lab value used to speed up validation.

---

## References

- [Wazuh FIM documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Custom FIM rules](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html)
- [Syscheck configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)
- [Release notes 4.14.8](https://documentation.wazuh.com/current/release-notes/release-4-14-8.html)
- [MITRE ATT&CK - T1565 Data Manipulation](https://attack.mitre.org/techniques/T1565/)
- [MITRE ATT&CK - T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [MITRE ATT&CK - T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK - T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [WAZUH-Process-Tree-Viewer](https://github.com/mym0us3r/WAZUH-Process-Tree-Viewer)
- [DIRTY-FRAG Detection with Wazuh 4.14.4](https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4)
- [COPY-FAIL Detection with Wazuh 4.14.4](https://github.com/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4)

---

## Author

**Kislley Rodrigues (m0us3r)**
Wazuh Ambassador | Detection Engineering | Blue Team

---

## Acknowledgments

- **Wazuh Team** for the open source SIEM/XDR platform and the Ambassador Program

---

*Detection rules, decoders, FIM Alert Investigation panel and agent configurations validated on Wazuh 4.14.8, Windows 11 Pro build 26200, Ubuntu 24.04.5 kernel 6.17.0 and Claude Sonnet 4.6.*

---

## Update 2026-10-11

| Change | Detail |
|---|---|
| Hypothesis AP-1 refuted | The suspected stall of the `syscheckd` inotify reader on labnix was not confirmed: realtime delivers events (41 events in the window, 36 in realtime mode). Not an upstream issue. |
| Handbook revised | 53 pages, 15 validated findings and 1 refuted hypothesis, with 9 new Wazuh Discover screenshots and a caption on every figure. |
| Verification rule | Confirm realtime through `syscheck.mode` in `archives.json`, use `strace -y` including `pselect6`, and do not query the live `fim.db`. |

---

## Wazuh

This project was developed as part of the [Wazuh Ambassador Program](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

Wazuh is a free, open source security platform that provides unified XDR and SIEM protection.
Learn more at [wazuh.com](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).
