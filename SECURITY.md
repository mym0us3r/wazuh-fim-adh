# Security Policy

## Scope

This policy covers the content of this repository: the FIM detection rules, the Sysmon research rules, the agent and manager configurations, and the WPTV / FIM Alert Investigation code in `wptv-fim/`. The reference environment is Wazuh 4.14.8.

## Reporting a vulnerability

Do not open a public issue for a vulnerability.

Use GitHub private vulnerability reporting: open the **Security** tab of this repository and select **Report a vulnerability**.

Include:

- the affected file and commit
- the steps to reproduce
- the impact you observed

Do not include real credentials, API keys, hostnames or customer data in a report. Reports are handled by the maintainer on a best-effort basis.

## What to report

- Bypass of the nginx access restriction in `wptv-fim/wptv.nginx.conf`
- Injection issues (command, path, template, XSS) in `server.py`, `logic.py`, `logic_fim.py`, `index.html` or `fim.html`
- Secrets, keys or sensitive data committed to the repository or present in its history
- Unsafe defaults in the configuration files or in the deployment steps of the README

## Out of scope

- Findings about the behavior of upstream Wazuh (the AO and AP findings in the README). Report those to the Wazuh project.
- Detection thresholds. The values for `frequency`, `timeframe` and `ignore` are lab values and must be tuned for each environment.

## Security model

How the service is exposed, which credentials it uses and which data leaves the environment when the optional AI and threat intelligence features are enabled is described in the **Security** section of the README.
