"""
logic_fim.py
FIM Alert Investigation - Backend Logic
Kislley Rodrigues (m0us3r) - Wazuh Ambassador Program
Reference Version: Wazuh 4.14.8

Extension of WAZUH-Process-Tree-Viewer (WPTV) for FIM-focused investigation.
Uses the same OpenSearch connection pattern as logic.py (WPTV_INDEXER_* env vars).
Falls back to /var/ossec/logs/alerts/alerts.json when indexer is not available.

Rule groups monitored:
  Group A - File events:  550, 553, 554, 517, 100310 (proxy/554-child)
  Group B - Registry:     594, 597, 598, 750, 751, 752
  Group C - Anomaly:      100300, 100301, 100302, 100303, 100304
"""

import os
import json
import gzip
import logging
import json as _json
from datetime import datetime, timezone, timedelta

import dateutil.parser

logger = logging.getLogger('wptv.fim')


_TLS_WARNED = False


def _tls_verify(ca):
    """Return the `verify` value for requests to the Wazuh Indexer.

    Uses the CA bundle from WPTV_INDEXER_CA_CERT when set. When it is not set,
    certificate verification is disabled (lab default for a local Indexer with a
    self-signed certificate) and a warning is logged once. Set
    WPTV_INDEXER_CA_CERT in production.
    """
    global _TLS_WARNED
    if ca:
        return ca
    if not _TLS_WARNED:
        logger.warning('WPTV_INDEXER_CA_CERT is not set: TLS certificate '
                       'verification for the Wazuh Indexer is disabled')
        _TLS_WARNED = True
    return False

# ── Rule catalog ──────────────────────────────────────────────────────────────

FIM_FILE_RULES = {'550', '553', '554', '517', '100310'}
# NOTE: 100310 is the counter-isolation proxy for rule 554 (syscheck_new_entry).
# When 100310 fires (if_sid 554, level 5), analysisd suppresses the parent 554 alert.
# Adding 100310 here ensures file-creation events are visible in the FIM panel.
# 100310 carries the same syscheck.* fields as 554 and is treated as equivalent.
# LAB VALIDATED: Wazuh 4.14.8, WZ-SRV, 2026-10-10 (Kislley Rodrigues)

FIM_REGISTRY_RULES = {'594', '597', '598', '750', '751', '752'}

FIM_ANOMALY_RULES = {
    '100300', '100301', '100302', '100303', '100304',
}

ALL_FIM_RULES = FIM_FILE_RULES | FIM_REGISTRY_RULES | FIM_ANOMALY_RULES

# ── Context window for correlation ────────────────────────────────────────────
CONTEXT_WINDOW_SECONDS = 60


class FIMInvestigationLogic:
    """
    FIM Alert Investigation logic.

    Data source priority:
      1. OpenSearch wazuh-alerts-* (when WPTV_INDEXER_URL is set)
      2. /var/ossec/logs/alerts/alerts.json + rotated files (fallback)

    For investigation context (±60s window), also queries wazuh-archives-*
    when WPTV_ARCHIVE_INDEX is set, to include auditd / non-FIM events.
    """

    def __init__(self):
        self.alerts_path = '/var/ossec/logs/alerts/alerts.json'

    # ── Time resolution ───────────────────────────────────────────────────────

    def _resolve_range(self, hours_back=None, start=None, end=None):
        now_utc = datetime.now(timezone.utc)
        if start and end:
            s = dateutil.parser.isoparse(start)
            e = dateutil.parser.isoparse(end)
            if s.tzinfo is None:
                s = s.replace(tzinfo=timezone.utc)
            if e.tzinfo is None:
                e = e.replace(tzinfo=timezone.utc)
            return s, e
        hours = float(hours_back) if hours_back is not None else 24.0
        return now_utc - timedelta(hours=hours), now_utc

    # ── OpenSearch connection (same env vars as WPTV) ─────────────────────────

    def _os_request(self, index, query):
        import requests as _req
        url  = os.getenv('WPTV_INDEXER_URL', '').rstrip('/')
        user = os.getenv('WPTV_INDEXER_USER', '')
        pwd  = os.getenv('WPTV_INDEXER_PASSWORD', '')
        ca   = os.getenv('WPTV_INDEXER_CA_CERT', '')

        if not url:
            raise EnvironmentError('WPTV_INDEXER_URL not set')

        resp = _req.post(
            f'{url}/{index}/_search',
            json=query,
            auth=(user, pwd) if user else None,
            verify=_tls_verify(ca),
            timeout=30,
        )
        resp.raise_for_status()
        return [h['_source'] for h in resp.json().get('hits', {}).get('hits', [])]

    # ── Threat intel enrichment (server-side, no AR) ─────────────────────────

    def _enrich_intel(self, sha256=None, md5=None, ips=None):
        """
        Query VirusTotal, AlienVault OTX, and AbuseIPDB for the given
        indicators. All sources are optional - skipped silently when the
        corresponding API key is not set in wptv.env.

        Returns:
          {
            'virustotal':  {malicious, suspicious, total, name, type} | None,
            'otx':         {pulse_count} | None,
            'abuseipdb':   [{ip, abuse_score, total_reports, country, isp}, ...],
          }
        """
        import requests as _req

        result = {'virustotal': None, 'otx': None, 'abuseipdb': []}

        # VirusTotal - file hash lookup
        vt_key = os.getenv('WPTV_VT_API_KEY', '').strip()
        if vt_key and sha256:
            try:
                resp = _req.get(
                    f'https://www.virustotal.com/api/v3/files/{sha256}',
                    headers={'x-apikey': vt_key},
                    timeout=15,
                )
                if resp.status_code == 200:
                    attrs  = resp.json().get('data', {}).get('attributes', {})
                    stats  = attrs.get('last_analysis_stats', {})
                    result['virustotal'] = {
                        'malicious':  stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'total':      sum(stats.values()),
                        'name':       attrs.get('meaningful_name', ''),
                        'type':       attrs.get('type_description', ''),
                    }
                elif resp.status_code == 404:
                    result['virustotal'] = {'not_found': True}
                else:
                    logger.warning('[fim/intel] VT returned %s', resp.status_code)
            except Exception as exc:
                logger.warning('[fim/intel] VT error: %s', exc)

        # AlienVault OTX - file hash lookup
        otx_key = os.getenv('WPTV_OTX_API_KEY', '').strip()
        if otx_key and sha256:
            try:
                resp = _req.get(
                    f'https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general',
                    headers={'X-OTX-API-KEY': otx_key},
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result['otx'] = {
                        'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    }
                else:
                    logger.warning('[fim/intel] OTX returned %s', resp.status_code)
            except Exception as exc:
                logger.warning('[fim/intel] OTX error: %s', exc)

        # AbuseIPDB - IP reputation
        abuse_key = os.getenv('WPTV_ABUSEIPDB_API_KEY', '').strip()
        if abuse_key and ips:
            for ip in ips[:5]:  # cap at 5 IPs per investigation
                try:
                    resp = _req.get(
                        'https://api.abuseipdb.com/api/v2/check',
                        headers={'Key': abuse_key, 'Accept': 'application/json'},
                        params={'ipAddress': ip, 'maxAgeInDays': 90},
                        timeout=15,
                    )
                    if resp.status_code == 200:
                        d = resp.json().get('data', {})
                        result['abuseipdb'].append({
                            'ip':           ip,
                            'abuse_score':  d.get('abuseConfidenceScore', 0),
                            'total_reports': d.get('totalReports', 0),
                            'country':      d.get('countryCode', ''),
                            'isp':          d.get('isp', ''),
                        })
                    else:
                        logger.warning('[fim/intel] AbuseIPDB returned %s for %s',
                                       resp.status_code, ip)
                except Exception as exc:
                    logger.warning('[fim/intel] AbuseIPDB error for %s: %s', ip, exc)

        return result

    # ── File fallback: iterate log paths ─────────────────────────────────────

    def _iter_log_paths(self, start_dt, end_dt):
        base   = os.path.dirname(self.alerts_path)
        paths  = []
        seen   = set()
        cursor = start_dt
        while cursor.date() <= end_dt.date():
            year  = cursor.strftime('%Y')
            month = cursor.strftime('%b')
            day   = cursor.strftime('%d')
            day_dir = os.path.join(base, year, month)
            for ext in ('.json.gz', '.json'):
                cand = os.path.join(day_dir, f'ossec-alerts-{day}{ext}')
                if os.path.exists(cand) and cand not in seen:
                    paths.append(cand)
                    seen.add(cand)
            cursor += timedelta(days=1)
        if os.path.exists(self.alerts_path) and self.alerts_path not in seen:
            paths.append(self.alerts_path)
        return paths

    def _open_log(self, path):
        if path.endswith('.gz'):
            return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
        return open(path, 'r', encoding='utf-8', errors='replace')

    def _scan_files(self, start_dt, end_dt, rule_ids=None, agent_id=None):
        results = []
        rule_set = set(rule_ids) if rule_ids else None
        for path in self._iter_log_paths(start_dt, end_dt):
            try:
                with self._open_log(path) as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            alert = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        ts_raw = alert.get('timestamp', '')
                        try:
                            ts = dateutil.parser.isoparse(ts_raw)
                            if ts.tzinfo is None:
                                ts = ts.replace(tzinfo=timezone.utc)
                        except Exception:
                            continue
                        if not (start_dt <= ts <= end_dt):
                            continue
                        rid = str(alert.get('rule', {}).get('id', ''))
                        if rule_set and rid not in rule_set:
                            continue
                        if agent_id and alert.get('agent', {}).get('id') != agent_id:
                            continue
                        results.append(alert)
            except OSError as e:
                logger.warning('Cannot read %s: %s', path, e)
        return results

    # ── Alert list ────────────────────────────────────────────────────────────

    def fetch_fim_alerts(self, agent_id=None, hours_back=24, start=None, end=None,
                         rule_ids=None, host=None, ip=None):
        """
        Fetch FIM alerts for the given agent and time window.
        Returns list of raw alert dicts sorted by timestamp ascending.
        """
        start_dt, end_dt = self._resolve_range(hours_back, start, end)
        target_rules = list(rule_ids or ALL_FIM_RULES)

        if os.getenv('WPTV_INDEXER_URL'):
            try:
                must = [
                    {'range': {'timestamp': {
                        'gte': start_dt.isoformat(),
                        'lte': end_dt.isoformat(),
                    }}},
                    {'terms': {'rule.id': target_rules}},
                ]
                if agent_id:
                    must.append({'term': {'agent.id': agent_id}})
                elif host:
                    must.append({'match_phrase': {'agent.name': host}})
                elif ip:
                    must.append({'term': {'agent.ip': ip}})

                index = os.getenv('WPTV_INDEXER_INDEX', 'wazuh-alerts-*')
                alerts = self._os_request(index, {
                    'size': 10000,
                    'sort': [{'timestamp': {'order': 'asc'}}],
                    'query': {'bool': {'must': must}},
                    '_source': True,
                })
                logger.info('FIM alerts from indexer: %d (agent=%s window=%s)',
                            len(alerts), agent_id or host or ip,
                            f'{start_dt.isoformat()} -> {end_dt.isoformat()}')
                return alerts
            except Exception as e:
                logger.warning('Indexer unavailable (%s) - falling back to file scan', e)

        alerts = self._scan_files(start_dt, end_dt,
                                  rule_ids=target_rules, agent_id=agent_id)
        logger.info('FIM alerts from file scan: %d', len(alerts))
        return alerts

    # ── Investigation context ─────────────────────────────────────────────────

    def fetch_investigation_context(self, alert_id, agent_id, timestamp_iso):
        """
        Build investigation context for a single FIM alert.

        Returns:
          {
            'focal_alert':    <the alert that was clicked>,
            'file_events':    <FIM file events ±60s same agent>,
            'registry':       <registry events ±60s same agent>,
            'process_events': <4688 events ±60s same agent (from archives)>,
            'anomaly':        <anomaly correlation hits ±60s same agent>,
          }
        """
        try:
            ts = dateutil.parser.isoparse(timestamp_iso)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        win_start = ts - timedelta(seconds=CONTEXT_WINDOW_SECONDS)
        win_end   = ts + timedelta(seconds=CONTEXT_WINDOW_SECONDS)

        # FIM file + registry + anomaly from alerts index
        all_alerts = self.fetch_fim_alerts(
            agent_id=agent_id,
            start=win_start.isoformat(),
            end=win_end.isoformat(),
        )

        focal        = None
        file_events  = []
        registry     = []
        anomaly      = []

        for a in all_alerts:
            rid = str(a.get('rule', {}).get('id', ''))
            if a.get('id') == alert_id or (
                    not focal and rid in FIM_FILE_RULES and
                    a.get('timestamp') == timestamp_iso):
                focal = a
            elif rid in FIM_FILE_RULES:
                file_events.append(a)
            elif rid in FIM_REGISTRY_RULES:
                registry.append(a)
            elif rid in FIM_ANOMALY_RULES:
                anomaly.append(a)

        # Process events from archives (4688 / auditd) - optional enrichment
        process_events = self._fetch_process_context(
            agent_id, win_start, win_end)

        # Threat intel enrichment (VT, OTX, AbuseIPDB) - server-side, no AR
        sha256 = None
        md5    = None
        ips    = []
        if focal:
            sc     = focal.get('syscheck', {})
            sha256 = sc.get('sha256_after') or sc.get('sha256_before')
            md5    = sc.get('md5_after') or sc.get('md5_before')
            # Collect IPs from process events (auditd remote addr, win network)
            for ev in process_events:
                data = ev.get('data', {})
                aud  = data.get('audit', {})
                for field in ('addr', 'daddr', 'saddr'):
                    v = aud.get(field, '')
                    if v and v not in ips and not v.startswith('127.') \
                            and v != '0.0.0.0':
                        ips.append(v)

        threat_intel = self._enrich_intel(sha256=sha256, md5=md5, ips=ips or None)

        return {
            'focal_alert':    focal,
            'file_events':    file_events,
            'registry':       registry,
            'anomaly':        anomaly,
            'process_events': process_events,
            'threat_intel':   threat_intel,
            'window': {
                'start': win_start.isoformat(),
                'end':   win_end.isoformat(),
            },
        }

    def _fetch_process_context(self, agent_id, start_dt, end_dt):
        """
        Fetch process creation events (EID 4688 / auditd execve) from
        wazuh-archives-* or archives.json fallback.
        Returns list of raw alert dicts, empty list if unavailable.
        """
        arc_index = os.getenv('WPTV_ARCHIVE_INDEX', '').strip()

        if arc_index and os.getenv('WPTV_INDEXER_URL'):
            try:
                must = [
                    {'range': {'timestamp': {
                        'gte': start_dt.isoformat(),
                        'lte': end_dt.isoformat(),
                    }}},
                    {'bool': {'should': [
                        {'term':  {'data.win.system.eventID': '4688'}},
                        {'term':  {'data.audit.type': 'SYSCALL'}},
                    ], 'minimum_should_match': 1}},
                ]
                if agent_id:
                    must.append({'term': {'agent.id': agent_id}})

                events = self._os_request(arc_index, {
                    'size': 500,
                    'sort': [{'timestamp': {'order': 'asc'}}],
                    'query': {'bool': {'must': must}},
                    '_source': True,
                })
                logger.info('Process context from archives: %d events', len(events))
                return events
            except Exception as e:
                logger.warning('Archives index unavailable: %s', e)

        # Fallback: scan archives.json
        arc_base = '/var/ossec/logs/archives'
        arc_live = os.path.join(arc_base, 'archives.json')
        results  = []
        if os.path.exists(arc_live):
            try:
                with open(arc_live, 'r', encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        ts_raw = ev.get('timestamp', '')
                        try:
                            ts = dateutil.parser.isoparse(ts_raw)
                            if ts.tzinfo is None:
                                ts = ts.replace(tzinfo=timezone.utc)
                            if not (start_dt <= ts <= end_dt):
                                continue
                        except Exception:
                            continue
                        if agent_id and ev.get('agent', {}).get('id') != agent_id:
                            continue
                        eid = (ev.get('data', {}).get('win', {})
                               .get('system', {}).get('eventID', ''))
                        syscall = ev.get('data', {}).get('syscall', '')
                        if eid == '4688' or syscall == 'execve':
                            results.append(ev)
            except OSError as e:
                logger.warning('Cannot read archives.json: %s', e)
        return results

    # ── LLM Analysis ──────────────────────────────────────────────────────────

    def analyze_fim_context(self, context):
        """
        Call Claude Sonnet 4.6 with the FIM investigation context.
        Returns structured JSON verdict for the analyst.

        Requires WPTV_ANTHROPIC_API_KEY in wptv.env.
        """
        import anthropic as _anthropic

        api_key = os.getenv('WPTV_ANTHROPIC_API_KEY', '')
        if not api_key:
            raise EnvironmentError(
                'WPTV_ANTHROPIC_API_KEY not set in wptv.env')

        # ── Build narrative for LLM ────────────────────────────────────────
        lines = []

        focal = context.get('focal_alert')
        if focal:
            syscheck = focal.get('syscheck', {})
            rule     = focal.get('rule', {})
            agent    = focal.get('agent', {})
            audit    = syscheck.get('audit', {})
            lines.append('=== FOCAL FIM ALERT ===')
            lines.append(
                f"timestamp={focal.get('timestamp')} "
                f"agent={agent.get('name','')} "
                f"rule={rule.get('id','')} ({rule.get('description','')})"
            )
            if syscheck.get('path'):
                lines.append(f"  path={syscheck['path']}")
            if syscheck.get('event'):
                lines.append(f"  event={syscheck['event']} "
                             f"mode={syscheck.get('mode','')}")
            if audit.get('user', {}).get('name'):
                lines.append(f"  user={audit['user']['name']}")
            if audit.get('process', {}).get('name'):
                lines.append(f"  process={audit['process']['name']}")
            for field in ('sha256_after', 'md5_after'):
                if syscheck.get(field):
                    lines.append(f"  {field}={syscheck[field]}")
            mitre = rule.get('mitre', {})
            if isinstance(mitre, dict) and mitre.get('id'):
                lines.append(f"  mitre={','.join(mitre['id'])}")

        # File events in window
        file_evs = context.get('file_events', [])
        if file_evs:
            lines.append(f'\n=== FILE EVENTS IN ±{CONTEXT_WINDOW_SECONDS}s WINDOW '
                         f'({len(file_evs)} events) ===')
            for ev in file_evs[:20]:
                sc = ev.get('syscheck', {})
                r  = ev.get('rule', {})
                lines.append(
                    f"  {ev.get('timestamp','')} "
                    f"rule={r.get('id','')} "
                    f"event={sc.get('event','')} "
                    f"path={sc.get('path','')}"
                )

        # Registry events (Windows persistence signals)
        reg_evs = context.get('registry', [])
        if reg_evs:
            lines.append(f'\n=== REGISTRY EVENTS IN ±{CONTEXT_WINDOW_SECONDS}s '
                         f'({len(reg_evs)} events) ===')
            for ev in reg_evs[:20]:
                sc = ev.get('syscheck', {})
                r  = ev.get('rule', {})
                lines.append(
                    f"  {ev.get('timestamp','')} "
                    f"rule={r.get('id','')} ({r.get('description','')})"
                    f"  key={sc.get('path','')}"
                )

        # Process events (4688 / auditd execve)
        proc_evs = context.get('process_events', [])
        if proc_evs:
            lines.append(f'\n=== PROCESS EVENTS IN ±{CONTEXT_WINDOW_SECONDS}s '
                         f'({len(proc_evs)} events) ===')
            for ev in proc_evs[:20]:
                data   = ev.get('data', {})
                win    = data.get('win', {})
                evdata = win.get('eventdata', {})
                aud    = data.get('audit', {})

                # Windows EventID 4688
                if evdata.get('newProcessName'):
                    lines.append(
                        f"  {ev.get('timestamp','')} "
                        f"exe={evdata.get('newProcessName','')} "
                        f"parent={evdata.get('parentProcessName','')} "
                        f"user={evdata.get('subjectUserName','')} "
                        f"cmd={evdata.get('commandLine','')[:80]}"
                    )
                # Linux auditd SYSCALL
                elif aud.get('exe'):
                    lines.append(
                        f"  {ev.get('timestamp','')} "
                        f"exe={aud.get('exe','')} "
                        f"cmd={aud.get('command','')} "
                        f"pid={aud.get('pid','')} ppid={aud.get('ppid','')} "
                        f"uid={aud.get('uid','')} auid={aud.get('auid','')} "
                        f"key={aud.get('key','')}"
                    )

        # Threat intel enrichment results
        intel = context.get('threat_intel', {})
        if intel:
            has_intel = (
                intel.get('virustotal') or
                intel.get('otx') or
                intel.get('abuseipdb')
            )
            if has_intel:
                lines.append('\n=== THREAT INTELLIGENCE ===')
                vt = intel.get('virustotal') or {}
                if vt and not vt.get('not_found'):
                    lines.append(
                        f"  VirusTotal: malicious={vt.get('malicious', 0)} "
                        f"suspicious={vt.get('suspicious', 0)} "
                        f"total={vt.get('total', 0)} "
                        f"name={vt.get('name', '')} "
                        f"type={vt.get('type', '')}"
                    )
                elif vt.get('not_found'):
                    lines.append('  VirusTotal: hash not found (first submission or private)')
                otx = intel.get('otx') or {}
                if otx:
                    lines.append(
                        f"  AlienVault OTX: pulse_count={otx.get('pulse_count', 0)}"
                    )
                for ip_intel in intel.get('abuseipdb', []):
                    lines.append(
                        f"  AbuseIPDB: ip={ip_intel.get('ip', '')} "
                        f"score={ip_intel.get('abuse_score', 0)} "
                        f"reports={ip_intel.get('total_reports', 0)} "
                        f"country={ip_intel.get('country', '')} "
                        f"isp={ip_intel.get('isp', '')}"
                    )

        # Anomaly correlation
        anom_evs = context.get('anomaly', [])
        if anom_evs:
            lines.append(f'\n=== ANOMALY CORRELATION ({len(anom_evs)} events) ===')
            for ev in anom_evs[:5]:
                r = ev.get('rule', {})
                lines.append(
                    f"  rule={r.get('id','')} lvl={r.get('level','')} "
                    f"{r.get('description','')}"
                )

        context_text = '\n'.join(lines)

        # ── System prompt ─────────────────────────────────────────────────────
        system_prompt = (
            "You are an expert SOC analyst and threat hunter specialising in "
            "File Integrity Monitoring (FIM), malware analysis, DFIR, and "
            "MITRE ATT&CK mapping. You analyse FIM events extracted from "
            "Wazuh (SIEM/XDR) telemetry alongside correlated process, "
            "registry, anomaly, and external threat intelligence data "
            "(VirusTotal, AlienVault OTX, AbuseIPDB).\n\n"
            "Analyse the FIM investigation context below and return ONLY a "
            "valid JSON object - no prose, no markdown fences, nothing "
            "outside the JSON:\n\n"
            "{\n"
            '  "risk_score": <integer 0-100>,\n'
            '  "risk_level": <"LOW"|"MEDIUM"|"HIGH"|"CRITICAL">,\n'
            '  "verdict_en": <one-sentence verdict in English>,\n'
            '  "verdict_pt": <same verdict in Brazilian Portuguese>,\n'
            '  "summary_en": [<sentence in English>, ...],\n'
            '  "summary_pt": [<sentence in Brazilian Portuguese>, ...],\n'
            '  "techniques": [{"id": "<T####.###>", "name": "<name>", '
            '"confidence": <integer 0-100>}],\n'
            '  "ioc": [{"type": "<hash|path|domain|ip|registry>", '
            '"value": "<value>", "note": "<note>"}],\n'
            '  "recommendations_en": [<action in English>, ...],\n'
            '  "recommendations_pt": [<action in Brazilian Portuguese>, ...]\n'
            "}\n\n"
            "Rules:\n"
            "- risk_score: 0-100 reflecting overall threat severity\n"
            "- verdict_en: single sentence, direct, actionable\n"
            "- summary_en: 2-4 sentences covering what happened and why it matters\n"
            "- techniques: only MITRE ATT&CK techniques genuinely observed; "
            "confidence 0-100\n"
            "- ioc: file hashes, suspicious paths, registry keys, domains or IPs "
            "observed in the context that are worth tracking\n"
            "- recommendations_en: 2-3 actionable steps for the analyst\n"
            "- If registry Run/RunOnce/Services keys appear alongside a new file: "
            "always flag T1547.001\n"
            "- If VirusTotal malicious>0 or OTX pulse_count>0: always flag T1204.002\n"
            "- If AbuseIPDB score>50 for any IP in context: note it in ioc and "
            "increase risk_score accordingly\n"
            "- Never invent events not present in the context\n"
            "- CRITICAL: Windows file paths use backslashes. In JSON strings, "
            "backslash MUST be escaped as \\\\ (double backslash). "
            "Example: C:\\\\Users\\\\kr\\\\AppData is correct; C:\\Users\\kr\\AppData is NOT valid JSON."
        )

        client = _anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model='claude-sonnet-4-6',
            max_tokens=4096,
            system=system_prompt,
            messages=[{'role': 'user', 'content': context_text}],
        )

        raw = msg.content[0].text.strip()
        if raw.startswith('```'):
            raw = '\n'.join(raw.split('\n')[1:])
            raw = raw.rsplit('```', 1)[0].strip()

        try:
            result = _json.loads(raw)
        except _json.JSONDecodeError as je:
            logger.error('[fim/analyze] JSONDecodeError at char %d: %s', je.pos, je.msg)
            logger.error('[fim/analyze] raw output (%d chars, %d tokens used): %.500s...',
                         len(raw), msg.usage.output_tokens, raw)
            raise ValueError(
                f'AI returned malformed JSON (pos {je.pos}): {je.msg}. '
                f'Output was {msg.usage.output_tokens} tokens '
                f'(limit {msg.usage.output_tokens + (4096 - msg.usage.output_tokens)} tokens).'
            ) from je
        result['model']  = 'claude-sonnet-4-6'
        result['tokens'] = {
            'input':  msg.usage.input_tokens,
            'output': msg.usage.output_tokens,
        }
        logger.info('[fim/analyze] risk=%s techniques=%d ioc=%d',
                    result.get('risk_score'),
                    len(result.get('techniques', [])),
                    len(result.get('ioc', [])))
        return result
