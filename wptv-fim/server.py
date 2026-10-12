from flask import Flask, request, jsonify, send_from_directory
from logic import ProcessTreeLogic
from logic_fim import FIMInvestigationLogic
import logging
import logging.handlers
import os

app = Flask(__name__, static_folder='public', static_url_path='')

# ── Logging setup ─────────────────────────────────────────────────────────────
# Writes to /var/log/wazuh-process-tree/wptv.log (rotated at 5MB, keeps 5 files).
# Falls back to stderr if the directory is not writable.
LOG_DIR  = '/var/log/wazuh-process-tree'
LOG_FILE = os.path.join(LOG_DIR, 'wptv.log')

# Force INFO level on the root logger before adding handlers.
# gunicorn pre-initialises the root logger at WARNING, so basicConfig()
# becomes a no-op and INFO messages never reach any handler we add later.
# Setting the level here, before anything else, guarantees our file handler
# actually receives INFO records.
_root = logging.getLogger()
_root.setLevel(logging.DEBUG)

_fmt = logging.Formatter(
    '%(asctime)s %(levelname)-8s %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')

# Stderr handler so gunicorn/journalctl still see everything
_sh = logging.StreamHandler()
_sh.setLevel(logging.DEBUG)
_sh.setFormatter(_fmt)
_root.addHandler(_sh)

# Rotating file handler
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    _fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8')
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(_fmt)
    _root.addHandler(_fh)
except OSError as _e:
    logging.warning("Cannot write to %s (%s) - file logging disabled", LOG_FILE, _e)

logger = logging.getLogger('wptv')
logger.info("WPTV starting - log: %s", LOG_FILE)

logic     = ProcessTreeLogic()
logic_fim = FIMInvestigationLogic()

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/api/process-tree', methods=['GET'])
def get_process_tree():
    try:
        agent_id = request.args.get('agent_id') or None
        host     = request.args.get('host') or None
        ip       = request.args.get('ip') or None
        search   = request.args.get('filter', "")
        event_id_filter = request.args.get('event_id', "") or None
        time_range = request.args.get('range', "24")
        start    = request.args.get('start')
        end      = request.args.get('end')

        if not agent_id and not host and not ip:
            return jsonify({"nodes": [], "edges": [], "stats": {"total": 0},
                            "error": "agent_id, host or ip is required"}), 400

        identity = agent_id or host or ip
        logger.info("process-tree request: identity=%s range=%s start=%s end=%s filter=%s event_id=%s",
                    identity, time_range, start, end, search or '(none)', event_id_filter or '(none)')

        events, sysmon_enrichment = logic.fetch_events_and_enrichment(
            agent_id=agent_id, hours_back=time_range, start=start, end=end, host=host, ip=ip)

        logger.info("events fetched: %d 4688 events, %d sysmon events",
                    len(events), sum(len(v) for v in sysmon_enrichment.values()) if sysmon_enrichment else 0)

        result = logic.build_tree(events, search, sysmon_enrichment=sysmon_enrichment,
                                  event_id_filter=event_id_filter)
        node_count = len(result.get('nodes', []))
        edge_count = len(result.get('edges', []))
        logger.info("tree built: %d nodes, %d edges", node_count, edge_count)
        return jsonify(result)
    except Exception as e:
        logger.exception("process-tree ERROR: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/process-tree/expand', methods=['GET'])
def expand_process_node():
    try:
        agent_id = request.args.get('agent_id') or None
        host = request.args.get('host') or None
        ip = request.args.get('ip') or None
        pid = request.args.get('pid')
        time_range = request.args.get('range', "24")
        start = request.args.get('start')
        end = request.args.get('end')

        if not pid or (not agent_id and not host and not ip):
            return jsonify({"error": "pid and one of agent_id/host/ip are required"}), 400

        identity = agent_id or host or ip
        logger.info("expand request: pid=%s identity=%s range=%s", pid, identity, time_range)
        events, sysmon_enrichment = logic.fetch_events_and_enrichment(agent_id=agent_id, hours_back=time_range, start=start, end=end, host=host, ip=ip)
        result = logic.expand_node(pid, hours_back=time_range, start=start, end=end,
                                    agent_id=agent_id, host=host, ip=ip,
                                    events=events, sysmon_enrichment=sysmon_enrichment)
        if result is None:
            result = {'nodes': [], 'edges': [], 'stats': {'total': 0}}
        logger.info("expand done: pid=%s new_nodes=%d", pid, len(result.get('nodes', [])))
        return jsonify(result)
    except Exception as e:
        logger.exception("expand ERROR: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments', methods=['GET'])
def get_comments():
    try:
        agent_id = request.args.get('agent_id') or None
        host = request.args.get('host') or None
        ip = request.args.get('ip') or None
        pid = request.args.get('pid')
        if not pid:
            return jsonify({"error": "pid is required"}), 400
        comments = logic.get_comments(pid, agent_id=agent_id, host=host, ip=ip)
        return jsonify({"comments": comments})
    except Exception as e:
        logger.error("get-comments ERROR: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments', methods=['POST'])
def post_comment():
    try:
        body = request.get_json(force=True, silent=True) or {}
        pid = body.get('pid')
        text = body.get('text')
        author = body.get('author')
        agent_id = body.get('agent_id') or None
        host = body.get('host') or None
        ip = body.get('ip') or None
        if not pid or not text:
            return jsonify({"error": "pid and text are required"}), 400
        comments = logic.add_comment(pid, text, author, agent_id=agent_id, host=host, ip=ip)
        return jsonify({"comments": comments})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("post-comment ERROR: %s", e)
        return jsonify({"error": str(e)}), 500

# ── AI Analysis ──────────────────────────────────────────────────────────────
@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    AI-powered analysis of the current WPTV process tree.
    Calls Claude Sonnet 4.6 and returns structured threat analysis.
    Requires WPTV_ANTHROPIC_API_KEY set in /etc/wazuh-process-tree/wptv.env.
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
        result  = logic.analyze_tree(payload)
        logger.info('[/api/analyze] risk_score=%s tokens_in=%s tokens_out=%s',
                    result.get('risk_score', '?'),
                    result.get('tokens', {}).get('input', '?'),
                    result.get('tokens', {}).get('output', '?'))
        return jsonify(result)
    except Exception as e:
        logger.exception('[/api/analyze] ERROR: %s', e)
        return jsonify({'error': str(e)}), 500




# ── FIM Alert Investigation routes ─────────────────────────────────────────
@app.route('/fim', strict_slashes=False)
def fim_index():
    """Serve the FIM Alert Investigation frontend."""
    return send_from_directory('public', 'fim.html')


@app.route('/api/fim/alerts', methods=['GET'])
def fim_alerts():
    """
    List FIM alerts for an agent within a time window.

    Query params:
      agent_id   - Wazuh agent ID (required unless host or ip provided)
      host       - agent hostname (alternative to agent_id)
      ip         - agent IP (alternative to agent_id)
      range      - hours back from now (default: 24)
      start      - ISO 8601 start datetime (overrides range)
      end        - ISO 8601 end datetime (overrides range)
      rules      - comma-separated rule IDs to filter (optional, default: all FIM rules)
    """
    try:
        agent_id   = request.args.get('agent_id') or None
        host       = request.args.get('host') or None
        ip         = request.args.get('ip') or None
        time_range = request.args.get('range', '24')
        start      = request.args.get('start') or None
        end        = request.args.get('end') or None
        rules_raw  = request.args.get('rules', '') or ''

        if not agent_id and not host and not ip:
            return jsonify({'error': 'agent_id, host or ip is required'}), 400

        rule_ids = set(r.strip() for r in rules_raw.split(',') if r.strip()) or None
        identity = agent_id or host or ip
        logger.info('fim/alerts request: identity=%s range=%s start=%s end=%s',
                    identity, time_range, start, end)

        alerts = logic_fim.fetch_fim_alerts(
            agent_id=agent_id, host=host, ip=ip,
            hours_back=time_range, start=start, end=end,
            rule_ids=rule_ids,
        )

        # Return summarised list - full document on investigation context
        summary = []
        for a in alerts:
            rule     = a.get('rule', {})
            syscheck = a.get('syscheck', {})
            agent    = a.get('agent', {})
            summary.append({
                'id':          a.get('id', ''),
                'timestamp':   a.get('timestamp', ''),
                'agent_id':    agent.get('id', ''),
                'agent_name':  agent.get('name', ''),
                'rule_id':     rule.get('id', ''),
                'rule_level':  rule.get('level', 0),
                'description': rule.get('description', ''),
                'path':        syscheck.get('path', ''),
                'event':       syscheck.get('event', ''),
                'mode':        syscheck.get('mode', ''),
                'mitre':       rule.get('mitre', {}).get('id', []),
                'groups':      rule.get('groups', []),
            })

        logger.info('fim/alerts response: %d alerts for %s', len(summary), identity)
        return jsonify({'alerts': summary, 'total': len(summary)})

    except Exception as e:
        logger.exception('fim/alerts ERROR: %s', e)
        return jsonify({'error': str(e)}), 500


@app.route('/api/fim/context', methods=['GET'])
def fim_context():
    """
    Fetch full investigation context for a single FIM alert.

    Returns the focal alert plus correlated events ±60s:
      file_events, registry, fim_ai, process_events, anomaly

    Query params:
      alert_id   - Wazuh alert ID (the id field in alerts.json)
      agent_id   - Wazuh agent ID
      timestamp  - ISO 8601 timestamp of the focal alert
    """
    try:
        alert_id  = request.args.get('alert_id') or ''
        agent_id  = request.args.get('agent_id') or None
        timestamp = request.args.get('timestamp') or ''

        if not agent_id or not timestamp:
            return jsonify({'error': 'agent_id and timestamp are required'}), 400

        logger.info('fim/context request: alert_id=%s agent_id=%s ts=%s',
                    alert_id, agent_id, timestamp)

        context = logic_fim.fetch_investigation_context(
            alert_id=alert_id,
            agent_id=agent_id,
            timestamp_iso=timestamp,
        )

        logger.info('fim/context: file=%d registry=%d fim_ai=%d process=%d anomaly=%d',
                    len(context.get('file_events', [])),
                    len(context.get('registry', [])),
                    len(context.get('fim_ai', [])),
                    len(context.get('process_events', [])),
                    len(context.get('anomaly', [])))

        return jsonify(context)

    except Exception as e:
        logger.exception('fim/context ERROR: %s', e)
        return jsonify({'error': str(e)}), 500


@app.route('/api/fim/analyze', methods=['POST'])
def fim_analyze():
    """
    AI-powered FIM investigation analysis using Claude Sonnet 4.6.

    Accepts the full context object returned by /api/fim/context
    and returns a structured verdict for the analyst.

    Requires WPTV_ANTHROPIC_API_KEY in wptv.env.

    Request body: JSON context object from /api/fim/context
    Response:
      {
        "risk_score":        <0-100>,
        "risk_level":        <"LOW"|"MEDIUM"|"HIGH"|"CRITICAL">,
        "verdict_en":        <one-sentence verdict>,
        "verdict_pt":        <same in Brazilian Portuguese>,
        "summary_en":        [...],
        "summary_pt":        [...],
        "techniques":        [{"id": "T####", "name": "...", "confidence": 0-100}],
        "ioc":               [{"type": "...", "value": "...", "note": "..."}],
        "recommendations_en": [...],
        "recommendations_pt": [...],
        "model":             "claude-sonnet-4-6",
        "tokens":            {"input": N, "output": N}
      }
    """
    try:
        context = request.get_json(force=True, silent=True) or {}
        if not context:
            return jsonify({'error': 'Request body is required'}), 400

        logger.info('fim/analyze request: focal=%s agent=%s',
                    (context.get('focal_alert') or {}).get('id', '?'),
                    ((context.get('focal_alert') or {}).get('agent') or {}).get('name', '?'))

        result = logic_fim.analyze_fim_context(context)

        logger.info('fim/analyze: risk=%s level=%s techniques=%d ioc=%d tokens_in=%s tokens_out=%s',
                    result.get('risk_score', '?'),
                    result.get('risk_level', '?'),
                    len(result.get('techniques', [])),
                    len(result.get('ioc', [])),
                    result.get('tokens', {}).get('input', '?'),
                    result.get('tokens', {}).get('output', '?'))

        return jsonify(result)

    except EnvironmentError as e:
        logger.error('fim/analyze config error: %s', e)
        return jsonify({'error': str(e)}), 503
    except Exception as e:
        logger.exception('fim/analyze ERROR: %s', e)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Development-only entrypoint. In production this app is served by
    # gunicorn (see wazuh-process-tree.service) - app.run() here is a plain
    # Werkzeug dev server (no process management, not hardened) and should
    # never be exposed directly. Use it only for local testing.
    app.run(host='127.0.0.1', port=5000, threaded=True, debug=False)
