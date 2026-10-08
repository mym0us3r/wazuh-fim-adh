# wazuh-fim-adh

> **Wazuh FIM em Profundidade: O Handbook do Defensor Avançado**

[![fim_ai_rules](https://img.shields.io/badge/fim_ai_rules-9-brightgreen)](https://github.com/mym0us3r/wazuh-fim-adh)
[![anomaly_rules](https://img.shields.io/badge/anomaly_rules-5-blue)](https://github.com/mym0us3r/wazuh-fim-adh)
[![status](https://img.shields.io/badge/status-production--validated-success)](https://github.com/mym0us3r/wazuh-fim-adh)
[![wazuh](https://img.shields.io/badge/wazuh-4.14.8-005571)](https://documentation.wazuh.com/current/release-notes/release-4-14-8.html)
[![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)](https://github.com/mym0us3r/wazuh-fim-adh)
[![mitre](https://img.shields.io/badge/MITRE-T1204.002-red)](https://attack.mitre.org/techniques/T1204/002/)
[![mitre](https://img.shields.io/badge/MITRE-T1485-red)](https://attack.mitre.org/techniques/T1485/)
[![mitre](https://img.shields.io/badge/MITRE-T1486-red)](https://attack.mitre.org/techniques/T1486/)

Conteúdo de Detection Engineering para Wazuh 4.14.8 cobrindo três capacidades construídas sobre o motor nativo de FIM:

**1. Regras de correlação de anomalia** - detecção baseada em threshold para operações massivas de arquivo (preparação de ransomware, anti-forense, entrega em massa de droppers) usando regras de correlação com `<if_matched_group>`. Sem dependências externas.

**2. FIM Alert Investigation** - painel de investigação assistida por IA integrado ao WAZUH-Process-Tree-Viewer. Quando um alerta FIM chega, o analista abre o painel, seleciona o alerta e aciona o Claude Sonnet 4.6 com contexto completo: evento focal, eventos de arquivo/registro/processo nos ±60s no mesmo agente, e resultados do pipeline FIM AI. O LLM raciocina sobre comportamento e entrega veredito, técnicas MITRE com confiança e ações recomendadas.

**3. Configuração hardened de endpoints** - `ossec.conf` validado em produção para Windows e Linux com paths explícitos por usuário, `whodata` em diretórios de sistema e `realtime` em paths do usuário. Inclui correções para seis pontos de falha não documentados no handbook oficial.

Desenvolvido como parte do [Programa Wazuh Ambassador](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

Ambiente de referência: **WZ-SRV** (Wazuh Server 4.14.8, Ubuntu 24.04 LTS, 3.9 GB RAM) + **LABDESK** (Windows 11 26200, agente 4.14.8) + **labnix** (Ubuntu 24.04.5, kernel 6.17.0, agente 4.14.8).

---

## Por que FIM avançado?

```
Abordagem com scan agendado:
  lê arquivo → calcula hash → compara → alerta na mudança
  problema: tudo que acontece entre scans é invisível

FIM em tempo real sem contexto:
  arquivo criado às 14:32:07 → alerta disparado
  analista revisa às 14:45 → arquivo já executado ou deletado
  problema: detecção sem contexto é ruído

FIM Alert Investigation (este repositório):
  arquivo criado 19:25:23 → FIM detecta (regra 554)
  19:25:29 → YARA match: FIM_AI_Lab_Test
  19:25:39 → Claude Sonnet 4.6: VT 0/0, score=35, zone=medium
  latência total FIM-to-verdict: 16 segundos
  analista recebe alerta enriquecido com veredito e contexto comportamental
```

---

## FIM Alert Investigation

Extensão do [WAZUH-Process-Tree-Viewer](https://github.com/mym0us3r/WAZUH-Process-Tree-Viewer) para investigação focada em FIM.

```
Nginx:
  /wptv/              → Flask :5000 (WPTV - árvore de processos)
  /fim-investigation/ → Flask :5000 (FIM Alert Investigation)
```

### Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│  PAINEL FIM ALERT INVESTIGATION                             │
│                                                             │
│  Agent ID + Preset de tempo (10min a 24h / Custom 90d)      │
│                      │                                      │
│              GET /api/fim/alerts                            │
│                      │                                      │
│         wazuh-alerts-*                                      │
│         Regras: 550/553/554/517 (arquivo)                   │
│                 594-752 (registro)                          │
│                 70000-70015 (FIM AI)                        │
│                 100300-100304 (anomalia)                    │
│                      │                                      │
│  Analista seleciona alerta → GET /api/fim/context           │
│                      │                                      │
│         Contexto ±60s (mesmo agente):                       │
│         - Eventos de arquivo (FIM)                          │
│         - Eventos de registro (Windows)                     │
│         - Processos (auditd SYSCALL / EventID 4688)         │
│           via wazuh-archives-*                              │
│         - Resultados do pipeline FIM AI                     │
│         - Alertas de anomalia                               │
│                      │                                      │
│  Analista clica "Investigate with AI"                       │
│              POST /api/fim/analyze                          │
│                      │                                      │
│         Claude Sonnet 4.6 (Anthropic API)                   │
│         Entrada: contexto completo - nunca o conteúdo       │
│         do arquivo                                          │
│                      │                                      │
│         Saída: risk_score, risk_level, veredito EN/PT-BR,   │
│         MITRE ATT&CK com confiança, IOC, ações recomendadas │
└─────────────────────────────────────────────────────────────┘
```

### Grupos de regras monitorados

| Grupo | Regras | Descrição |
|-------|--------|-----------|
| A - Arquivo | 550, 553, 554, 517 | Modificado, excluído, adicionado, auditoria |
| B - Registro | 594, 597, 598, 750, 751, 752 | Chaves e valores de registro Windows |
| C - FIM AI | 70000, 70001, 70002, 70010-70015 | Pipeline FIM AI (YARA, Defender, confiança média/alta) |
| D - Anomalia | 100300-100304 | Correlação de volume (ransomware, anti-forense) |

### Saída validada

```
Agente: labnix (008) | Ubuntu 24.04.5 | 06/10/2026

Alerta focal: PROC_CONTEXT.txt adicionado em /home/kr/Downloads/
Contexto ±60s: 8 eventos de processo com key: lpe_quartet_root_netlink_route

Veredito LLM:
  risk_score: 50 | risk_level: MEDIUM
  T1068 Exploitation for Privilege Escalation — 52% de confiança
  IOC: /usr/bin/vmtoolsd disparando audit key de LPE
  Ação: auditar integridade do vmtoolsd, correlacionar audit key
        lpe_quartet_root_netlink_route na linha do tempo completa do SIEM
```

---

## Regras de Correlação de Anomalia (fim_anomaly_rules.xml)

| Regra | Nível | Gatilho | MITRE |
|-------|-------|---------|-------|
| 100300 | 10 | 3+ arquivos criados em 10 min (mesmo agente) | T1105 |
| 100301 | 12 | Mesmo MD5 em 3+ diretórios em 10 min | T1565.001 |
| 100302 | 10 | 3+ arquivos modificados em 10 min | T1565.001 |
| 100303 | 10 | 3+ arquivos excluídos em 10 min | T1485 |
| 100304 | 14 | 5+ eventos FIM mistos em 10 min | T1485 + T1486 |

> **Nota técnica:** A regra 100304 usa `<if_matched_group>syscheck_file</if_matched_group>` para cobrir as regras 550, 553 e 554 em uma única correlação. `<if_matched_sid>` com SIDs separados por vírgula não funciona em regras de correlação no Wazuh 4.14.x.

---

## Estrutura do repositório

```
wazuh-fim-adh/
│
├── rules/
│   ├── fim_ai_rules.xml              # Regras 70000-70015 — pipeline FIM AI
│   └── fim_anomaly_rules.xml         # Regras 100300-100304 — correlação de anomalia
│
├── decoders/
│   └── fim_ai_decoder.xml            # JSON_Decoder Stage 1 (fim_ai_endpoint)
│                                     #               Stage 2 (fim_ai_intel)
│
├── config/
│   ├── ossec_server.conf             # ossec.conf do servidor — localfile, FIM AI
│   ├── ossec_agent_windows.conf      # ossec.conf do agente Windows — paths + ignores
│   └── ossec_agent_linux.conf        # ossec.conf do agente Linux — whodata + realtime
│
├── wptv-fim/
│   ├── logic_fim.py                  # Lógica de investigação FIM (extensão do WPTV)
│   ├── server.py                     # Servidor WPTV estendido com rotas /api/fim/*
│   └── public/fim.html               # Painel FIM Alert Investigation
│
├── docs/
│   ├── fim_alert_investigation_panel.png
│   ├── fim_ai_verdict_example.png
│   └── wazuh-fim-documentacao-completa-pt-br.docx   # Handbook completo (PT-BR, 62 páginas)
│
└── ROADMAP.md
```

---

## Ambiente de lab

| Componente | Detalhe |
|-----------|---------|
| Wazuh Server | 4.14.8 — WZ-SRV, Ubuntu 24.04 LTS, 3.9 GB RAM |
| Agente Windows | 4.14.8 — LABDESK, Windows 11 Pro build 26200, usuário `kr` |
| Agente Linux | 4.14.8 — labnix, Ubuntu 24.04.5, kernel 6.17.0, usuário `kr` |
| YARA | 4.5.5 — `winget install VirusTotal.YARA` (Windows) / `apt install yara` (Linux) |
| Windows Defender | integrado via PowerShell — scan sob demanda pelo pipeline |
| Ruleset YARA | Valhalla demo — CC-BY-NC 4.0 |
| Inteligência | VirusTotal, AlienVault OTX, URLScan.io, Anthropic (Claude Sonnet 4.6) |
| WPTV | [WAZUH-Process-Tree-Viewer](https://github.com/mym0us3r/WAZUH-Process-Tree-Viewer) |

---

## Requisitos

- Wazuh Server 4.14.8 e agentes 4.14.8
- Python 3.10+ no servidor (para `logic_fim.py`)
- Chaves de API: VirusTotal, AlienVault OTX, URLScan.io, Anthropic — armazenadas em `/etc/wazuh-process-tree/wptv.env`
- WAZUH-Process-Tree-Viewer instalado (`/usr/share/wazuh-dashboard/plugins/process_tree_api/`)
- Filebeat com módulo archives habilitado (`archives.enabled: true` em `filebeat.yml`)
- `logall_json: yes` no `ossec.conf` do servidor para contexto de processo no painel

---

## Deploy do FIM Alert Investigation

```bash
DEST=/usr/share/wazuh-dashboard/plugins/process_tree_api

# Backup
cp $DEST/server.py $DEST/server.py.bak-$(date +%Y%m%d)

# Deploy
cp wptv-fim/logic_fim.py  $DEST/logic_fim.py
cp wptv-fim/server.py     $DEST/server.py
cp wptv-fim/public/fim.html $DEST/public/fim.html

# Permissões
chown wazuh-dashboard:wazuh-dashboard \
  $DEST/logic_fim.py $DEST/server.py $DEST/public/fim.html
chmod 755 $DEST/logic_fim.py $DEST/server.py
chmod 644 $DEST/public/fim.html

# wptv.env — adicionar chave Anthropic e archives
echo "WPTV_ANTHROPIC_API_KEY=<sua_chave>" >> /etc/wazuh-process-tree/wptv.env
echo "WPTV_ARCHIVE_INDEX=wazuh-archives-*" >> /etc/wazuh-process-tree/wptv.env

# Nginx — adicionar location /fim-investigation/
# (mesmo padrão do /wptv/ no arquivo de site existente)

# Reiniciar
systemctl restart wazuh-process-tree
```

### Nginx — adicionar ao site existente

```nginx
location /fim-investigation/ {
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
```

---

## Achados Técnicos do Lab

Seis achados documentados durante a implantação. Todos reproduzíveis e relevantes para qualquer deploy Wazuh em ambiente Windows e Linux.

1. **Loop PyInstaller `--onefile` via `C:\Windows\Temp`** — `--runtime-tmpdir` obrigatório para executáveis Python compilados no Windows. Sem ele: 3335 alertas em três horas, 43-124 alertas/minuto.
2. **Loop via perfil PowerShell da conta SYSTEM** — scripts de scan regravavam `StartupProfileData-NonInteractive`. Adicionar `<ignore>` específico no `ossec.conf` do agente resolve.
3. **Executável de scan Windows requer `.exe`** — `.bat` e `.ps1` não recebem stdin do execd de forma confiável no Windows (erro 1317). PyInstaller resolve.
4. **`field name="file"` e não `syscheck.path`** — campo correto para matching de path em regras FIM customizadas. Erro silencioso: analysisd não reporta falha.
5. **Saturação do syscheck por fontes de ruído** — Chrome `.crdownload`, Trend Micro, Sublime Text. Filtrar via `<ignore>` com `type="sregex"` no `ossec.conf` do agente.
6. **auditpol obrigatório para whodata em workgroup Windows** — sem política de auditoria em Êxito, o SACL é invalidado silenciosamente pelo Windows Defender. O Wazuh emite erro 6021.

---

## Referências

- [Documentação Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Regras FIM customizadas](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html)
- [Configuração syscheck](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)
- [Release notes 4.14.8](https://documentation.wazuh.com/current/release-notes/release-4-14-8.html)
- [PyInstaller — `--runtime-tmpdir`](https://pyinstaller.org/en/stable/usage.html)
- [PyInstaller — How the One-File Program Works](https://pyinstaller.org/en/stable/operating-mode.html)
- [Valhalla YARA Rule Set](https://valhalla.nextron-systems.com/) (Nextron Systems, CC-BY-NC 4.0)
- [MITRE ATT&CK T1204.002 — Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [WAZUH-Process-Tree-Viewer](https://github.com/mym0us3r/WAZUH-Process-Tree-Viewer)
- [DIRTY-FRAG Detection with Wazuh 4.14.4](https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4)
- [COPY-FAIL Detection with Wazuh 4.14.4](https://github.com/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4)

---

## Autor

**Kislley Rodrigues** — Wazuh Ambassador | Detection Engineering | Blue Team

---

## Agradecimentos

- **Equipe Wazuh** pela plataforma SIEM/XDR open source e pelo Programa Ambassador
- **Nextron Systems** pelo Valhalla YARA Rule Set (tier demo, CC-BY-NC 4.0)

---

*Regras de detecção, decoders, painel FIM Alert Investigation e configurações de agente validados no Wazuh 4.14.8, Windows 11 Pro build 26200, Ubuntu 24.04.5 kernel 6.17.0, PyInstaller 6.22.3, YARA 4.5.5, Windows Defender e Claude Sonnet 4.6.*

---

## Wazuh

Este projeto foi desenvolvido como parte do [Programa Wazuh Ambassador](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

O Wazuh é uma plataforma de segurança gratuita e open source que oferece proteção unificada de XDR e SIEM.
Saiba mais em [wazuh.com](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).
