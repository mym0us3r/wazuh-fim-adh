## Security

WPTV and FIM Alert Investigation are analyst tools for a lab or an administrator network. Review the points below before deploying them.

**Access control.** The Flask service listens on `127.0.0.1:5000` only and has no authentication of its own. Nginx routes `/wptv/`, `/fim/` and `/api/fim/` directly to it, so these paths do not go through the Wazuh Dashboard login. The `allow YOUR-ADMIN-IP; deny all;` rule in `wptv-fim/wptv.nginx.conf` is the only access control for them. Keep it restricted to administrator addresses.

**Indexer access.** The service reads from the Wazuh Indexer with the read-only user `wptv_svc` (role `wptv_role`, indices `wazuh-alerts-*` and `wazuh-archives-*`). See [Step 3](#step-3---wazuh-indexer-credentials-service-user-wptv_svc).

**Secrets.** The Indexer password and the API keys live in `/etc/wazuh-process-tree/wptv.env` (mode `600`, owner `wazuh-dashboard`). The repository ships only `wptv-fim/wptv.env.example` with placeholders. `.gitignore` excludes `wptv.env`, `*.env` (except `*.env.example`), `*.pem` and `*.key`.

**TLS.** `proxy_ssl_verify off` applies only to the loopback hops between nginx and the local services. Set `WPTV_INDEXER_CA_CERT` in `wptv.env`: without it, certificate verification of the Indexer connection is disabled and a warning is written to the log.

**Data sent to third parties.** All features below are optional and stay off while their key is unset in `wptv.env`.

| Feature | Destination | Data sent |
|---|---|---|
| AI ANALYZE (WPTV) | Anthropic API | Host, IP and agent ID, process names, user, first 200 characters of the command line, file paths, parent-child relations |
| Investigate with AI (FIM Alert Investigation) | Anthropic API | Rule IDs and descriptions, file and registry paths, event types, user and process names, hashes, process events in the ±60 s window, threat intelligence results |
| Threat intelligence enrichment | VirusTotal and AlienVault OTX; AbuseIPDB | SHA256 of the file (VirusTotal, OTX); IP addresses found in the event context (AbuseIPDB) |

Do not enable these features where paths, hostnames or command lines cannot leave the organization. Each analysis request also consumes Anthropic API quota, which is one more reason to keep the nginx restriction in place.

To report a vulnerability, see [SECURITY.md](SECURITY.md).
