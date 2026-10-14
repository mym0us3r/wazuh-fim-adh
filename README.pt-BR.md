# Wazuh FIM em Profundidade - O Handbook do Defensor Avançado

[English](README.md) | **Português (BR)**

> **Detection engineering sobre o File Integrity Monitoring do Wazuh 4.14.8 · Windows e Linux · correlação de anomalia + investigação assistida por IA**

![custom_rules](https://img.shields.io/badge/regras_customizadas-6-brightgreen)
![findings](https://img.shields.io/badge/achados_validados-15-blue)
![refuted](https://img.shields.io/badge/hip%C3%B3tese_refutada-1-lightgrey)
![sysmon_rules](https://img.shields.io/badge/regras_sysmon_pesquisa-5-orange)
![status](https://img.shields.io/badge/status-validado_em_laborat%C3%B3rio-success)
![wazuh](https://img.shields.io/badge/wazuh-4.14.8-005571)
![platform](https://img.shields.io/badge/plataforma-Windows%20%7C%20Linux-lightgrey)
![mitre](https://img.shields.io/badge/MITRE-T1565-red)
![mitre](https://img.shields.io/badge/MITRE-T1485-red)
![mitre](https://img.shields.io/badge/MITRE-T1486-red)
![mitre](https://img.shields.io/badge/MITRE-T1105-red)

---

## O que é este projeto?

O módulo FIM do Wazuh responde com precisão a três perguntas: **o que mudou, quando mudou e, com whodata, quem mudou**. Em produção, a maioria dos problemas de cobertura nasce em outro lugar: no subsistema de auditoria do sistema operacional por baixo do FIM, no comportamento interno do `wazuh-analysisd` ao correlacionar eventos e em falhas silenciosas que o `ossec.conf` não revela.

### Por que esta pesquisa existe

As mesmas dúvidas sobre FIM aparecem de forma recorrente na comunidade Wazuh, no Slack, em fóruns, no LinkedIn e em outras plataformas, especialmente entre usuários que estão implementando o FIM em produção pela primeira vez. O padrão costuma ser bastante semelhante: eventos de criação e modificação são recebidos normalmente, mas os eventos de exclusão não chegam, ou o comportamento é exatamente o oposto.

Diante desse cenário, é comum presumir que a solução esteja em uma única linha ausente no `ossec.conf`. Em alguns casos, essa suposição está correta. Em muitos outros, a causa está em uma camada inferior à configuração do próprio FIM: o subsistema de auditoria do sistema operacional, ou uma Group Policy que continua aplicada à OU do servidor, embora isso tenha sido esquecido ou passe despercebido durante a investigação. Um exemplo típico é um agente em um File Server Windows (Wazuh 4.14.7) sem nenhum evento de FIM (Figura 1 do Handbook).

Esse cenário foi uma das principais motivações para este trabalho. A expectativa é entregar uma referência de consulta rápida, clara e objetiva para quem ainda não possui conhecimentos avançados de Wazuh, especialmente no contexto do FIM. O material mapeia onde cada componente da configuração está localizado, tanto no servidor Wazuh quanto nos endpoints Windows e Linux. Mostra também como as regras do Linux Audit são efetivamente construídas e persistidas, e documenta os modos de falha que explicam grande parte dos relatos de eventos de exclusão que não chegam ao Wazuh.

Tudo foi validado em laboratório próprio, com agentes Windows e Linux monitorados pelo mesmo servidor Wazuh, e cada achado tem evidência do Wazuh Discover. O repositório existe para tornar esse conhecimento reutilizável: as regras de correlação, as configurações de agente e os achados podem ser implantados, testados e adaptados em vez de redescobertos.

> **A cobertura pode desaparecer sem erro no log.** Dois casos foram validados: no Windows, a cobertura whodata não é restaurada após o restart do manager (achado AO-7); no Linux, um caminho com `/*` em `<directories>` registra watches em arquivos individuais e deixa os arquivos novos sem cobertura realtime (achado AO-8). Evidências e mitigações no capítulo 10 do Handbook.

### O que este repositório entrega

Este repositório documenta um projeto de laboratório que foi do problema até a solução, com evidência em cada etapa. Ele entrega quatro capacidades construídas sobre o motor nativo de FIM:

**1. Regras de correlação de anomalia.** Detecção por threshold para operações massivas de arquivo (preparação de ransomware, anti-forense, entrega em massa de droppers), com `<if_matched_group>` e `<if_matched_sid>`. Seis regras customizadas, sem dependências externas.

**2. FIM Alert Investigation.** Painel de investigação assistida por IA integrado ao [WAZUH-Process-Tree-Viewer](https://github.com/mym0us3r/WAZUH-Process-Tree-Viewer). O analista seleciona um alerta FIM e aciona o Claude Sonnet 4.6 com o contexto completo (±60 s, mesmo agente). O resultado é um veredito estruturado com `risk_score`, técnicas MITRE com confiança, IOCs e ações recomendadas.

**3. Configuração endurecida de endpoints.** `ossec.conf` validado para Windows e Linux, com caminhos explícitos por usuário, `whodata` em diretórios de sistema e `realtime` em caminhos de usuário, mais os achados técnicos que o material oficial não cobre.

**4. Sysmon como camada complementar.** Cinco regras de pesquisa (100521, 100540, 100541, 100554 e 100555) que casam com as regras FIM por caminho e horário. Foram construídas a partir do repositório [Unified Sysmon Configs](https://github.com/mym0us3r/Unified-Sysmon-Configs) e estão disponíveis para a comunidade testar, modificar e adaptar à realidade do ambiente. Veja [Sysmon como Camada Complementar ao FIM](#sysmon-como-camada-complementar-ao-fim).

Tudo isso está consolidado no **Handbook** (EN-US, com versão PT-BR para referência), em [`docs/`](docs/).

> Desenvolvido como parte do [Programa Wazuh Ambassador](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

---

## Ambiente de Referência

| Componente | Plataforma | Papel |
|---|---|---|
| WZ-SRV | Ubuntu 24.04 LTS, 3,9 GB de RAM, Wazuh 4.14.8 | Manager, Indexer, Dashboard e WPTV (Flask) |
| LABDESK | Windows 11 Pro (build 26200), agente 4.14.8, Sysmon nativo (schema 4.91) | Agente Windows: FIM em sistema de arquivos e Registro, mais a camada Sysmon |
| labnix | Ubuntu 24.04.5, kernel 6.17.0, agente 4.14.8 | Agente Linux atual: realtime, whodata e auditd |
| pentlab | Kali Linux (kernel 6.x), agente 4.14.7 | Agente Linux das validações iniciais |
| Inteligência | Claude Sonnet 4.6, VirusTotal, AlienVault OTX, AbuseIPDB | Análise e enriquecimento do FIM Alert Investigation |

Parte dos cenários de correlação foi executada em 4.14.7 e o pipeline atual opera em 4.14.8. Os números de volume e latência refletem um servidor de 3,9 GB de RAM e não substituem um dimensionamento de produção.

---

## Por que FIM avançado?

```
Scan agendado:
  lê arquivo -> calcula hash -> compara -> alerta na mudança
  problema: tudo que acontece entre scans é invisível

FIM em tempo real sem contexto:
  arquivo criado às 14:32:07 -> alerta disparado
  analista revisa às 14:45 -> arquivo já executado ou deletado
  problema: detecção sem contexto é ruído

FIM Alert Investigation (este repositório):
  arquivo criado -> FIM detecta (regra 554, exibida como 100310)
  analista seleciona o alerta -> aciona o Claude Sonnet 4.6
  contexto ±60 s: arquivo, registro e processo correlacionados
  veredito: risk_score, MITRE ATT&CK, IOCs, ações recomendadas
```

---

## A História do Projeto

O projeto seguiu quatro etapas. Cada uma gerou achados que alteraram a etapa seguinte.

**Etapa 1 - Detectar comportamento, não só mudança.** Um alerta isolado de criação de arquivo diz pouco. A pergunta passou a ser "quantos, em quanto tempo, no mesmo agente". Surgiram as regras 100300 a 100304, baseadas em volume.

**Etapa 2 - O motor de correlação tem regras próprias.** Duas regras com `<if_matched_sid>` sobre o mesmo SID compartilham o acumulador e interferem entre si (achados AC-3, AC-5 e AC-6). A solução foi a **regra proxy 100310**, filha da 554, que reemite cada criação para dois grupos independentes (`fim_creation` e `fim_new_entry`) e isola os contadores de 100300 e 100301.

**Etapa 3 - Todo mecanismo tem efeito colateral.** A filha 100310 passou a suprimir a regra pai 554 em `wazuh-alerts-*`: só a 100310 chega ao índice. Com a 100310 em nível 0, o alerta some por completo e o evento aparece apenas em `wazuh-archives-*`, sem campo `rule`. A 100310 opera em nível 5 e o painel de investigação passou a tratá-la como regra de arquivo (achado AC-7).

**Etapa 4 - Do alerta ao veredito.** Com a detecção estável, o FIM Alert Investigation fecha o ciclo: contexto de ±60 s, enriquecimento de threat intelligence e análise do LLM. Latência FIM-to-verdict medida em labnix: **16 segundos**.

### Uma hipótese refutada, documentada de propósito

Durante a validação em Linux, uma janela de eventos realtime ausentes no labnix levou à hipótese de que o leitor inotify do `wazuh-syscheckd` estaria parado (stall), o que justificaria uma issue no repositório do Wazuh. Reproduzir antes de reportar mostrou o contrário:

- O `archives.json` do manager registra **41 eventos** do labnix na janela, **36 deles em modo `realtime`**.
- O `strace` do `syscheckd` mostra `read()` no descritor `anon_inode:inotify`. A observação original havia filtrado a syscall errada: o daemon espera com `pselect6`, que o filtro antigo não capturava.
- Os 21 eventos `added` sem regra associada são compatíveis com a criação encoberta pela regra proxy 100310 enquanto operava em nível 0 (efeito do achado AC-7), e não com eventos perdidos.

**Veredito: NÃO PROCEDE.** Não é issue no upstream. O achado AP-1 está documentado neste README como hipótese refutada, com o método e as falhas que a produziram. Ele não faz parte dos 15 achados do Handbook. O aprendizado útil é prático: para confirmar que o realtime entrega eventos, consulte `syscheck.mode` no `archives.json` (ou em `wazuh-archives-*`) e nunca consulte o `fim.db` ativo (retorna `database is locked`).

---

## Arquitetura

```
Agente (syscheckd)
  scheduled | realtime (inotify) | whodata (auditd / SACL)
        |
        v
Manager: analysisd
  regra 554 (added) -> filha 100310 -> grupos fim_creation, fim_new_entry
  regra 550 (modified) | 553 (deleted) | syscheck_file
        |
        v
Regras de correlação 100300-100304  ->  wazuh-alerts-*
        |
        v
FIM Alert Investigation (WPTV, aba Forensics)
  GET  /api/fim/alerts   -> lista de alertas FIM
  GET  /api/fim/context  -> contexto ±60 s (arquivo, registro, processo)
  POST /api/fim/analyze  -> Claude Sonnet 4.6 -> veredito estruturado
```

```
Nginx:
  /wptv/     -> Flask :5000 (WPTV - árvore de processos)
  /fim/      -> Flask :5000 (FIM Alert Investigation)
  /api/fim/  -> Flask :5000 (API do painel FIM)
```

O LLM recebe o contexto do evento, nunca o conteúdo do arquivo.

**Acesso aos dados:** o WPTV e o FIM Alert Investigation leem do Wazuh Indexer com o usuário de serviço dedicado e somente leitura `wptv_svc` (índices `wazuh-alerts-*` e `wazuh-archives-*`). As credenciais ficam em `/etc/wazuh-process-tree/wptv.env` (modo `600`, dono `wazuh-dashboard`). Ver [Passo 3](#passo-3---credenciais-do-wazuh-indexer-usuário-de-serviço-wptv_svc).

---

## Regras de Correlação de Anomalia

Arquivo: `/var/ossec/etc/rules/fim_anomaly_rules.xml` (permissões `660 wazuh:wazuh`).

| Regra | Nível | Correlação | Gatilho | MITRE |
|---|---|---|---|---|
| 100310 | 5 | `if_sid 554` | Proxy: reemite cada criação para `fim_creation` e `fim_new_entry` | - |
| 100300 | 10 | `if_matched_group fim_creation` | 3+ arquivos criados em 10 min (mesmo agente) | T1565, T1565.001, T1074 |
| 100301 | 12 | `if_matched_group fim_new_entry` | Mesmo MD5 (`md5_after`) em 3+ diretórios em 10 min | T1105, T1570 |
| 100302 | 10 | `if_matched_sid 550` | 3+ arquivos modificados em 10 min | T1565, T1565.001 |
| 100303 | 10 | `if_matched_sid 553` | 3+ arquivos excluídos em 10 min | T1485, T1070, T1561 |
| 100304 | 14 | `if_matched_group syscheck_file` | 5+ eventos mistos em 10 min | T1485, T1486, T1565 |

> **Nota técnica 1:** `<if_sid>` define uma regra filha (dispara no mesmo evento). `<if_matched_sid>` define correlação temporal (contador independente, `frequency` eventos dentro do `timeframe`). A 100310 usa o primeiro mecanismo para que 100300 e 100301 usem o segundo sobre grupos distintos.

> **Nota técnica 2:** Nos testes de laboratório no Wazuh 4.14.x, `<if_matched_sid>` com SIDs separados por vírgula não funcionou de forma confiável em regras de correlação. A 100304 usa `<if_matched_group>syscheck_file</if_matched_group>` para cobrir 550, 553 e 554 em uma única correlação.

> **Aviso de calibração:** `frequency="3"`, `timeframe="600"` e `ignore="30"` foram calibrados para laboratório. Em produção, ajuste contra um baseline de atividade normal por grupo de agentes.

### Matriz de validação

| Regra | Cenário | LABDESK (Windows) | pentlab (Linux) |
|---|---|---|---|
| 100310 | Proxy de isolamento (nível 5) | CONFIRMADO | - (validada em labnix) |
| 100300 | 3+ criações em 10 min | CONFIRMADO | CONFIRMADO |
| 100301 | Mesmo hash, diretórios distintos | NÃO CONFIRMADO | CONFIRMADO |
| 100302 | 3+ modificações em 10 min | CONFIRMADO | CONFIRMADO |
| 100303 | 3+ exclusões em 10 min | CONFIRMADO | CONFIRMADO |
| 100304 | 5+ eventos mistos (nível 14) | CONFIRMADO | CONFIRMADO |

Na regra 100301 em Windows, o `same_field` sobre campos `syscheck` não foi confirmado nos testes de 16/09/2026. Os endpoints Windows mantêm cobertura de criação via 100300 e de escalação via 100304.

---

## Achados Técnicos

Quinze achados validados e uma hipótese refutada, todos com evidência de laboratório. O detalhamento dos 15 achados (comportamento, impacto, mitigação) está no capítulo 10 do Handbook. A hipótese refutada (AP-1) está documentada em [Uma hipótese refutada, documentada de propósito](#uma-hipótese-refutada-documentada-de-propósito). Os achados são observações de laboratório no Wazuh 4.14.x e não comportamentos declarados na documentação oficial.

| ID | Achado | Tipo | Status |
|---|---|---|---|
| AC-1 | `same_field` deve usar `md5_after` | Correlação | RESOLVIDO |
| AC-2 | `if_matched_sid` com múltiplos SIDs não é confiável | Correlação | RESOLVIDO |
| AC-3 | Interferência de contador entre 100300 e 100301 | Correlação | RESOLVIDO |
| AC-4 | `wazuh-logtest` não processa eventos syscheck | Validação | ESPERADO |
| AC-5 | Interferência de contador confirmada no Linux | Correlação | RESOLVIDO |
| AC-6 | Interferência filho-pai na 100300 | Correlação | RESOLVIDO |
| AC-7 | Nível da 100310 e supressão da 554 | Correlação | RESOLVIDO |
| AO-1 | `field name="file"` e não `syscheck.path` | Regras | RESOLVIDO |
| AO-2 | Saturação do syscheck por fontes de ruído | Endpoint | RESOLVIDO |
| AO-3 | `auditpol` obrigatório para whodata em workgroup Windows | Endpoint | RESOLVIDO |
| AO-4 | `client_max_body_size` do nginx para payloads de análise | Integração | RESOLVIDO |
| AO-5 | AbuseIPDB só é consultado via `connect` do auditd | Integração | RESOLVIDO |
| AO-6 | VirusTotal não detecta payloads customizados | Integração | ESPERADO |
| AO-7 | SACL não restaurada após restart do manager | Windows | MITIGADO |
| AO-8 | Caminho com `/*` expande o glob em arquivos individuais | Endpoint | RESOLVIDO |
| AP-1 | Hipótese de stall do leitor inotify (refutada) | Daemon Linux | NÃO PROCEDE |

Dois achados merecem atenção imediata em qualquer implantação, porque degradam a cobertura sem registrar erro:

- **AO-7 (Windows):** após reiniciar o manager, o whodata no LABDESK ficou cerca de 25 minutos sem gerar eventos syscheck, até um `Restart-Service WazuhSvc` manual reaplicar a SACL. O `windows_audit_interval` apenas verifica a política e as SACLs e, em caso de divergência, move os diretórios para realtime; não reaplica a SACL. Mitigação: reiniciar o agente após o restart do manager.
- **AO-8 (Linux):** `<directories>` com `/*` registra watches em arquivos individuais e deixa os arquivos novos sem cobertura realtime. Use o diretório sem o curinga. Segundo a [documentação oficial](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html), o realtime funciona com diretórios, não com arquivos individuais.

---

## Estrutura do Repositório

```
wazuh-fim-adh/
│
├── rules/
│   └── fim_anomaly_rules.xml         # Regras 100310 + 100300-100304
│
├── config/
│   ├── ossec_MANAGER.conf            # ossec.conf do manager
│   ├── ossec_Endpoint_LABDESK.conf   # Agente Windows (LABDESK): paths + ignores
│   └── ossec_Endpoint_LABNIX.conf    # Agente Linux (LABNIX): whodata + realtime
│
├── sysmon/                           # Conjunto de pesquisa: Sysmon como camada sobre o FIM
│   └── fim_sysmon_rules.xml          # Regras 100521, 100540, 100541, 100554, 100555
│
├── wptv-fim/                         # WAZUH-Process-Tree-Viewer + FIM Alert Investigation
│   ├── server.py                     # Rotas Flask (/wptv/, /fim/, /api/fim/*)
│   ├── logic.py                      # Lógica da árvore de processos do WPTV
│   ├── logic_fim.py                  # Lógica de investigação FIM
│   ├── wptv.nginx.conf               # Proxy reverso nginx (Passo 5)
│   ├── wptv.env.example              # Modelo de variáveis (copiar para /etc/wazuh-process-tree/wptv.env)
│   ├── public/
│   │   ├── index.html                # Painel WPTV
│   │   └── fim.html                  # Painel FIM Alert Investigation
│   └── plugin/                       # Plugin do OpenSearch Dashboards (menu Forensics)
│       ├── install.sh
│       ├── opensearch_dashboards.json
│       ├── package.json
│       └── target/public/
│           ├── wptv.plugin.js
│           └── wptv.plugin.js.gz
│
├── docs/
│   ├── wazuh-fim-advanced-defenders-handbook-en-us.docx   # Handbook completo (EN-US)
│   └── wazuh-fim-advanced-defenders-handbook-pt-br.docx   # Handbook completo (PT-BR, referência)
│
├── README.md                         # English
├── README.pt-BR.md                   # Português (BR)
├── SECURITY.md                       # Política de segurança e reporte de vulnerabilidades
├── LICENSE                           # MIT
└── .gitignore                        # Exclui wptv.env, chaves e certificados
```

---

## Requisitos

- Wazuh Server 4.14.8 e agentes 4.14.8
- Python 3.10+ no servidor (para `logic_fim.py`)
- [WAZUH-Process-Tree-Viewer](https://github.com/mym0us3r/WAZUH-Process-Tree-Viewer) instalado (`/usr/share/wazuh-dashboard/plugins/process_tree_api/`)
- Usuário de serviço somente leitura `wptv_svc` (role `wptv_role`) no Wazuh Indexer, com acesso a `wazuh-alerts-*` e `wazuh-archives-*` (Passo 3)
- Chaves de API: VirusTotal, AlienVault OTX, AbuseIPDB e Anthropic, armazenadas em `/etc/wazuh-process-tree/wptv.env`
- Filebeat com o módulo archives habilitado (`archives.enabled: true` em `filebeat.yml`)
- `logall_json: yes` no `ossec.conf` do servidor, necessário para o contexto de processo no painel

---

## Deploy

### Passo 1 - Regras de correlação

```bash
cp rules/fim_anomaly_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/fim_anomaly_rules.xml
chmod 660 /var/ossec/etc/rules/fim_anomaly_rules.xml

# Validar a sintaxe antes de reiniciar
/var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5

systemctl restart wazuh-manager
```

### Passo 2 - Configuração dos agentes

Aplique `config/ossec_Endpoint_LABNIX.conf` ou `config/ossec_Endpoint_LABDESK.conf` ao `ossec.conf` do agente e substitua os placeholders de endereço do manager. Pontos de atenção:

- `whodata` em diretórios de sistema e `realtime` em caminhos de usuário.
- Diretórios sem `/*` (achado AO-8).
- Windows em workgroup: habilitar a auditoria de objeto com `auditpol` (achado AO-3).

```cmd
auditpol /set /subcategory:"File System" /success:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable
```

### Passo 3 - Credenciais do Wazuh Indexer (usuário de serviço `wptv_svc`)

O WPTV e o FIM Alert Investigation são servidos pelo mesmo serviço Flask (`wazuh-process-tree`, executado como `wazuh-dashboard`; o FIM acrescenta as rotas `/fim/` e `/api/fim/*`) e consultam o **Wazuh Indexer diretamente** como fonte primária de dados. Nenhum dos dois usa a conta `admin`. Crie um usuário de serviço dedicado e **somente leitura**, `wptv_svc`, restrito a:

- `wazuh-alerts-*` - eventos que dispararam regra (alertas FIM, incluindo 100310 e 100300-100304).
- `wazuh-archives-*` - eventos que não dispararam regra, incluindo os eventos de processo usados no contexto de ±60 s. Exige o módulo archives do Filebeat (ver Requisitos).

A role concede apenas `read` e `indices:data/read/search`, sem permissão de escrita em nenhum índice. As credenciais `admin` são usadas uma única vez, para criar a role e o usuário.

Criar a role:

```bash
curl -sk -X PUT "https://127.0.0.1:9200/_plugins/_security/api/roles/wptv_role" \
  -H "Content-Type: application/json" \
  -u "admin:<admin_password>" \
  -d '{
    "cluster_permissions": [
      "cluster:monitor/main"
    ],
    "index_permissions": [{
      "index_patterns": [
        "wazuh-alerts-*",
        "wazuh-archives-*"
      ],
      "allowed_actions": [
        "read",
        "indices:data/read/search"
      ]
    }]
  }'
```

Criar o usuário:

```bash
curl -sk -X PUT "https://127.0.0.1:9200/_plugins/_security/api/internalusers/wptv_svc" \
  -H "Content-Type: application/json" \
  -u "admin:<admin_password>" \
  -d '{
    "password": "<your_password>",
    "backend_roles": [],
    "attributes": {}
  }'
```

Mapear a role ao usuário:

```bash
curl -sk -X PUT "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/wptv_role" \
  -H "Content-Type: application/json" \
  -u "admin:<admin_password>" \
  -d '{
    "users": ["wptv_svc"]
  }'
```

Em seguida, grave as credenciais. O serviço carrega este arquivo pelo `EnvironmentFile` da unit do systemd:

```bash
mkdir -p /etc/wazuh-process-tree/certs
cp /etc/wazuh-indexer/certs/root-ca.pem /etc/wazuh-process-tree/certs/
cp wptv-fim/wptv.env.example /etc/wazuh-process-tree/wptv.env   # modelo com placeholders
vim /etc/wazuh-process-tree/wptv.env
```

```
WPTV_INDEXER_URL=https://127.0.0.1:9200
WPTV_INDEXER_INDEX=wazuh-alerts-*
WPTV_INDEXER_USER=wptv_svc
WPTV_INDEXER_PASSWORD=<your_password>
WPTV_INDEXER_CA_CERT=/etc/wazuh-process-tree/certs/root-ca.pem
WPTV_ARCHIVE_INDEX=wazuh-archives-*
```

```bash
chown wazuh-dashboard:wazuh-dashboard /etc/wazuh-process-tree/wptv.env
chmod 600 /etc/wazuh-process-tree/wptv.env
```

> `/etc/wazuh-process-tree/wptv.env` guarda a senha do Indexer e as chaves de API. Mantenha o modo `600`, dono `wazuh-dashboard`, e nunca o versione. A instalação completa do WPTV (ambiente virtual, permissões, nginx, plugin do OSD, unit do systemd) está no repositório [WAZUH-Process-Tree-Viewer](https://github.com/mym0us3r/WAZUH-Process-Tree-Viewer).

### Passo 4 - FIM Alert Investigation

```bash
DEST=/usr/share/wazuh-dashboard/plugins/process_tree_api

# Backup
cp $DEST/server.py $DEST/server.py.bak-$(date +%Y%m%d)

# Deploy
cp wptv-fim/logic_fim.py      $DEST/logic_fim.py
cp wptv-fim/server.py         $DEST/server.py
cp wptv-fim/public/fim.html   $DEST/public/fim.html

# Permissões
chown wazuh-dashboard:wazuh-dashboard \
  $DEST/logic_fim.py $DEST/server.py $DEST/public/fim.html
chmod 755 $DEST/logic_fim.py $DEST/server.py
chmod 644 $DEST/public/fim.html

# wptv.env - adicionar a chave Anthropic (as variáveis do Indexer foram definidas no Passo 3)
echo "WPTV_ANTHROPIC_API_KEY=<sua_chave>" >> /etc/wazuh-process-tree/wptv.env

# Reiniciar
systemctl restart wazuh-process-tree
```

### Passo 5 - Nginx (`/etc/nginx/sites-enabled/wptv`)

```nginx
server {
    listen 443 ssl;
    server_name YOUR-WAZUH-SERVER-IP;   # IP ou FQDN do servidor

    # Restringir o acesso HTTPS ao seu IP
    allow YOUR-ADMIN-IP;
    deny all;

    ssl_certificate     /etc/wazuh-dashboard/certs/wazuh-dashboard.pem;
    ssl_certificate_key /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem;

    # Payloads de análise FIM/WPTV podem superar o limite padrão de 1MB
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

> `client_max_body_size 10m` é obrigatório (achado AO-4): o payload do `POST /api/fim/analyze` ultrapassa o limite padrão de 1MB. Sem ele, o nginx devolve HTTP 413 em HTML antes de repassar ao Flask e o frontend falha com `Unexpected token '<'`.

---

## Validação

### Confirmar que o realtime entrega eventos

O alerta pode estar oculto pela regra proxy (AC-7). A fonte da verdade é o `archives.json`, que exige `logall_json: yes`. No manager:

```bash
grep -a '"syscheck"' /var/ossec/logs/archives/archives.json \
  | jq -c '{timestamp, agent:.agent.name, rule:.rule.id, mode:.syscheck.mode, event:.syscheck.event, path:.syscheck.path}'
```

O campo `mode` indica `realtime`, `whodata` ou `scheduled`. Evento `added` com `rule: null` indica criação encoberta pelo proxy em nível 0 (achado AC-7), e não evento perdido.

Para dias anteriores, o manager rotaciona o arquivo para `/var/ossec/logs/archives/YYYY/Mon/ossec-archive-DD.json.gz`; use `zcat -f <arquivo> | grep -a '"syscheck"' | jq ...`. O `grep -a` evita a mensagem `binary file matches`.

### Teste de criação, modificação e exclusão

```bash
# No agente Linux
echo "test" > /home/kr/Downloads/fim_test.txt        # 554 (exibida como 100310)
echo "more" >> /home/kr/Downloads/fim_test.txt       # 550
rm -f /home/kr/Downloads/fim_test.txt                # 553
```

Para acionar os limiares de correlação, repita a operação 3 vezes (ou 5 vezes para a 100304) em até 10 minutos.

---

## Evidências de Validação

Todas as imagens são capturas reais do Wazuh Discover e do painel FIM Alert Investigation. O Handbook traz o conjunto completo, com legenda.

### Regra 100310 - proxy da 554 (nível 5)

Validada em LABDESK (02:14:29 e 02:13:56 de 10/10/2026) e em labnix (02:30:14 e 02:31:41 com a descrição antiga, 02:35:52 com a nova).

![Regra 100310 - LABDESK](docs/ev_regra_100310_labdesk.png)

![Regra 100310 - labnix, descrição atualizada](docs/ev_regra_100310_labnix_descricao.png)

### Criação de arquivos - 554 e 100300 (labnix)

16 hits da 554 (`p100301v3.txt` criado em 09/10/2026 às 20:51:17, modo realtime) e 22 hits da 100300 em 24 horas.

![Regra 554 - labnix, 16 hits](docs/ev_regra_554_labnix_16_hits.png)

![Regra 100300 - labnix](docs/ev_regra_100300_labnix.png)

### Mesmo hash em diretórios distintos - 100301 (pentlab)

![Regra 100301 - pentlab](docs/ev_regra_100301_pentlab.png)

### Modificação de arquivos - 550 e 100302 (labnix)

25 hits da 550 (`elif.zip` e `file.zip` modificados em 09/10/2026 às 23:51) e a 100302 sobre `beacon_test.sh`.

![Regra 550 - labnix, 25 hits](docs/ev_regra_550_labnix_25_hits.png)

![Regra 100302 - labnix](docs/ev_regra_100302_labnix.png)

### Exclusão de arquivos - 553 e 100303 (labnix)

34 hits da 553 entre 23:08 e 23:15 de 09/10/2026, com a 100303 às 23:08:33 e 23:15:16.

![Regra 553 - labnix, 34 hits](docs/ev_regra_553_labnix_34_hits.png)

![Regra 100303 - labnix](docs/ev_regra_100303_labnix.png)

### Escalação - 100304 (LABDESK)

![Regra 100304 - LABDESK](docs/ev_regra_100304_labdesk.png)

### FIM Alert Investigation - simulação pós-exploração no Windows

O script `up.ps1` executou três fases no LABDESK: staging, reconhecimento (11 comandos) e cópia lateral. Resultado: 44 alertas FIM, regra 100302 disparada, correlação FIM + árvore de processos (EventID 4688) confirmada.

O painel lista a regra proxy 100310 (nível 5) ao lado do alerta de correlação 100302, de modo que a criação do `up.ps1` pode ser analisada a partir do alerta que de fato chega a `wazuh-alerts-*` (achado AC-7). Os valores do veredito variam com o alerta focal e a janela de contexto: esta execução parte do alerta de criação (risk_score 92), enquanto a execução mais abaixo parte da 100302 (risk_score 87).

![Alerta focal na regra proxy 100310 (nível 5): up.ps1 criado em Downloads no LABDESK, modo whodata, 2026-10-10 às 03:13:01](docs/ev_fim_investigation_focal_100310_labdesk.png)

![Veredito do LLM para o alerta focal 100310: risk_score 92, CRITICAL, mapeamento MITRE liderado por T1059.001 (97%)](docs/ev_fim_investigation_veredito_risk_92.png)

Partindo, em vez disso, do alerta de escalação 100302:

![Contexto de 14 eventos no janelamento de ±60 s](docs/ev_fim_investigation_context_14_eventos.png)

![Alerta focal 100302](docs/ev_fim_investigation_focal_alert_100302.png)

![Veredito do LLM - risk_score 87, CRITICAL, 11 técnicas MITRE](docs/ev_fim_investigation_veredito_risk_87.png)

![IOCs e ações recomendadas](docs/ev_fim_investigation_iocs_recomendacoes.png)

### Saída validada em Linux (labnix, 06/10/2026)

```
Alerta focal: PROC_CONTEXT.txt adicionado em /home/kr/Downloads/
Contexto ±60 s: 8 eventos de processo com key: lpe_quartet_root_netlink_route

Veredito LLM:
  risk_score: 50 | risk_level: MEDIUM
  T1068 Exploitation for Privilege Escalation - 52% de confiança
  IOC: /usr/bin/vmtoolsd disparando audit key de LPE
  Ação: auditar integridade do vmtoolsd e correlacionar a audit key
        na linha do tempo completa do SIEM
```

---

## Sysmon como Camada Complementar ao FIM

O foco deste projeto é o Wazuh FIM. O Sysmon entra apenas como uma camada adicional: ele responde **qual processo** tocou o arquivo, enquanto o FIM responde **o que mudou** (hash, tamanho, atributos). Os dois sinais são pareados por caminho (`syscheck.path` no lado FIM, `data.win.eventdata.targetFilename` no lado Sysmon) e por horário.

Os testes usaram o repositório [Unified Sysmon Configs](https://github.com/mym0us3r/Unified-Sysmon-Configs) como base. A partir dele foi escrito um novo conjunto de regras voltado à pesquisa, disponibilizado no GitHub para a comunidade testar, modificar e adaptar à realidade do ambiente onde será implementado. Os IDs das regras Sysmon começam em 100500, para não colidir com as regras FIM (100300 a 100310).

Arquivo: `/var/ossec/etc/rules/fim_sysmon_rules.xml` (permissões `660 wazuh:wazuh`).

| Regra | Nível | Evento Sysmon | Gatilho | MITRE | Par FIM |
|---|---|---|---|---|---|
| 100521 | 10 | EID 2 (data de criação alterada) | Timestamp alterado por interpretador (`powershell`, `pwsh`, `cmd`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`) | T1070.006 | 550 (atributo `mtime`, whodata) |
| 100540 | 12 | EID 11 (arquivo criado ou sobrescrito) | Executável ou script (`exe`, `dll`, `ps1`, `bat`, `vbs`, `js`, `hta`, `lnk` e outros) criado em caminho monitorado por interpretador | T1105, T1059 | 100310 (proxy da 554) |
| 100541 | 6 | EID 11 | Qualquer arquivo criado ou sobrescrito em caminho monitorado | - | 100300 ou 100302 |
| 100554 | 12 | EID 26 (exclusão de arquivo registrada) | Executável ou script excluído em caminho monitorado por interpretador | T1070.004 | 553 ou 100303 |
| 100555 | 6 | EID 26 | Qualquer arquivo excluído em caminho monitorado | T1070.004 | 553 ou 100303 |

### Pares validados

Uma execução de cada cenário no LABDESK (12/10/2026, horário local). A ordem de chegada dos dois sinais varia, então o pareamento é por caminho e horário, não por sequência.

| Cenário | FIM | Sysmon |
|---|---|---|
| Criar `.txt` | 100300 às 13:44:42.298 (whodata) | 100541 às 13:44:42.271 |
| Sobrescrever via `cmd` | 100302 às 14:28:43.364 (scheduled, tamanho 22 para 29) | 100555 às 14:18:57.882 e 100541 às 14:18:57.966 |
| Excluir `.txt` | 553 às 15:02:10.064 | 100555 às 15:02:10.109 |
| Drop de executável pelo PowerShell | 100310 às 15:42:02.912 (scheduled, SHA-256 `23240ef9...af56cd3`, tamanho 98304) | 100540 às 15:41:56.911 |
| Timestomping de `mtime` | 550 às 15:51:25.303 (whodata, `mtime` 1791831076 para 1559386800) | 100521 às 15:51:25.264 |
| Limpeza: exclusão de script e executável | 553 às 15:56:09.851 e 100303 às 15:56:10.793 | 100555 às 15:56:09.864 e 100554 às 15:56:09.893 |

**Casos somente FIM.** A sobrescrita com `Set-Content` (550 às 14:14:09.810), o append (550 às 14:38:54.918) e o `Rename-Item` (553 e 100310 às 14:51:45.810) não geraram evento no canal do Sysmon. Nesses casos o FIM é a única fonte, e esse é o argumento para tratar o Sysmon como camada e não como substituto.

### Deploy

```bash
# 1. WZ-SRV: copiar as regras, ajustar o dono e validar antes de reiniciar
cp sysmon/fim_sysmon_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/fim_sysmon_rules.xml
chmod 660 /var/ossec/etc/rules/fim_sysmon_rules.xml
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

No endpoint, o Sysmon precisa registrar o EID 2 (data de criação alterada), o EID 11 (arquivo criado) e o EID 26 (exclusão registrada) para o caminho monitorado, caso contrário as regras não têm o que casar. Parta das configurações nativas do repositório [Unified Sysmon Configs](https://github.com/mym0us3r/Unified-Sysmon-Configs), habilite esses três tipos de evento para o caminho em teste e aplique o resultado em um PowerShell elevado com `sysmon64 -c <configuração>.xml`.

Consulta do Discover que mostra os dois sinais da pasta monitorada:

```
agent.name: "LABDESK" and (syscheck.path: *fim_sysmon_lab* or data.win.eventdata.targetFilename: *fim_sysmon_lab*)
```

### Notas técnicas

- Caminhos Windows são armazenados com barras invertidas duplicadas, então as expressões PCRE2 usam quatro (`\\`) por separador.
- As regras stock do Sysmon para EID 11 (por exemplo a 92203) casam primeiro e ocultariam as regras irmãs seguintes. Por isso 100540 e 100541 são filhas de `61613,92202,92203,92211,92212,92215,92223,92227`.
- As regras 100554 e 100555 dependem de `<if_group>sysmon_event_26</if_group>`.
- Use o campo `timestamp` para comparar horários. O `syscheck.mtime_after` aparece 3 horas antes do horário real no Discover.
- Regras de frequência que tentaram correlacionar as duas fontes não dispararam nos testes de criação e exclusão, em nenhuma das ordens de chegada. Foram removidas, e o pareamento é feito no Discover com a consulta acima.

> **Aviso de adaptação:** o caminho monitorado (`File_Server_Test_Folder`), os níveis e a lista de interpretadores são valores de laboratório. Ajuste ao ambiente antes de usar as regras em produção.

Evidências (capturas reais do Wazuh Discover):

A numeração das figuras segue o Handbook (seção 8.5). A Figura 56 é uma captura do terminal; as Figuras 57 a 67 são consultas do Wazuh Discover, e cada legenda lista o `rule.id` dos alertas exibidos.

![Figura 56](docs/ev_sysmon_config_aplicada.png)

*Figura 56 - Validação do XML e aplicação da configuração do Sysmon nativo com sysmon -c no LABDESK (schema 4.91)*

![Figura 57](docs/ev_sysmon_criacao_100541_fim_100300.png)

*Figura 57 - Criação do a.txt no LABDESK: regra 100541 (Sysmon, EID 11, 13:44:42.241 e 13:44:42.271) seguida da 100300 (FIM, 13:44:42.298)*

![Figura 58](docs/ev_sysmon_setcontent_fim_550.png)

*Figura 58 - Sobrescrita com Set-Content: alerta 550 (FIM) às 14:14:09.810, sem alerta Sysmon associado (intervalo de 14:13 a 14:21)*

![Figura 59](docs/ev_sysmon_overwritecmd_100555_100541.png)

*Figura 59 - Sobrescrita com redirecionamento do cmd.exe: regras 100555 (Sysmon, EID 26, 14:18:57.882) e 100541 (Sysmon, EID 11, 14:18:57.966) com a imagem cmd.exe*

![Figura 60](docs/ev_sysmon_append_fim_550.png)

*Figura 60 - Anexar linha ao a.txt: consulta combinada por caminho (FIM ou Sysmon) retorna somente o alerta 550 (FIM) de 14:38:54.918*

![Figura 61](docs/ev_sysmon_rename_fim_553_100310.png)

*Figura 61 - Renomear arquivos: alertas 553 (a.txt) e 100310 (b.txt) do FIM às 14:51:45.810, sem alerta Sysmon associado*

![Figura 62](docs/ev_sysmon_exclusao_fim_553_100555.png)

*Figura 62 - Exclusão do b.txt: alerta 553 (FIM) e alerta 100555 (Sysmon, EID 26) no mesmo caminho*

![Figura 63](docs/ev_sysmon_executavel_100540.png)

*Figura 63 - Cópia do executável tool_ps.exe pelo PowerShell: alerta 100540 (Sysmon, EID 11)*

![Figura 64](docs/ev_sysmon_executavel_fim_100310.png)

*Figura 64 - Mesmo executável no FIM: alerta 100310 (proxy da 554, modo scheduled) com os hashes MD5 e SHA-256 do arquivo*

![Figura 65](docs/ev_sysmon_timestomp_100521.png)

*Figura 65 - Alteração das datas do a.txt (timestomp): alerta 100521 (Sysmon, EID 2)*

![Figura 66](docs/ev_sysmon_timestomp_fim_550.png)

*Figura 66 - Mesma operação no FIM: alerta 550 (modo whodata) com o atributo mtime alterado*

![Figura 67](docs/ev_sysmon_limpeza_100554_100303.png)

*Figura 67 - Limpeza dos arquivos de teste: 553 e 100555 (a.txt), 100554 (Sysmon, EID 26) e 100303 (FIM) para o tool_ps.exe*

---

## Mapeamento MITRE ATT&CK

| Técnica | ID | Regras |
|---|---|---|
| Data Manipulation | T1565 | 100300, 100302, 100304 |
| Stored Data Manipulation | T1565.001 | 100300, 100302 |
| Data Staged | T1074 | 100300 |
| Ingress Tool Transfer | T1105 | 100301, 100540 |
| Lateral Tool Transfer | T1570 | 100301 |
| Data Destruction | T1485 | 100303, 100304 |
| Indicator Removal | T1070 | 100303 |
| Timestomp | T1070.006 | 100521 |
| File Deletion | T1070.004 | 100554, 100555 |
| Command and Scripting Interpreter | T1059 | 100540 |
| Disk Wipe | T1561 | 100303 |
| Data Encrypted for Impact | T1486 | 100304 |

O capítulo 9 do Handbook cobre também o mapeamento de compliance (PCI DSS 4.0, NIST 800-53 Rev 5, HIPAA, GDPR e SOC 2).

---

## Conteúdo do Handbook

O Handbook é escrito em EN-US. Uma versão PT-BR fica em `docs/` como referência. Capítulos:

| Capítulo | Conteúdo |
|---|---|
| 1. Executive Summary | Resultados, estrutura e ambiente de referência |
| 2. Wazuh FIM Fundamentals | Arquitetura, os três modos, parâmetros, caminhos de rede e sincronização delta |
| 3. FIM on Windows | SACL, `auditpol`, GPO, `windows_audit_interval`, rename e Registro |
| 4. FIM on Linux | auditd, regras persistentes, CDB de audit-keys, provider eBPF, inotify e troubleshooting |
| 5. Anomaly Detection Rules | Seis regras, o padrão proxy da 100310 e evidências por plataforma |
| 6. FIM Alert Investigation | Arquitetura, threat intelligence, veredito do LLM e validações |
| 7. Complementary Rules from the Default Ruleset | Ciclo de vida do agente (504, 505, 506), overflow inotify (560) e Registro |
| 8. FIM from the Adversary's Perspective | Evasão, timestomping, padrão de ransomware e Sysmon como camada complementar (8.5) |
| 9. Compliance and MITRE ATT&CK | PCI DSS, NIST, HIPAA, GDPR, TSC e técnicas |
| 10. Validated Technical Findings | 15 achados validados (AC-1 a AC-7, AO-1 a AO-8) |
| 11. Reference Configurations | Novidades da 4.14.8, `ossec.conf` endurecido, estado do servidor |

---

## Segurança

O WPTV e o FIM Alert Investigation são ferramentas de analista para laboratório ou rede de administração. Revise os pontos abaixo antes de implantar.

**Controle de acesso.** O serviço Flask escuta somente em `127.0.0.1:5000` e não tem autenticação própria. O nginx encaminha `/wptv/`, `/fim/` e `/api/fim/` direto para ele, então esses caminhos não passam pelo login do Wazuh Dashboard. A regra `allow YOUR-ADMIN-IP; deny all;` em `wptv-fim/wptv.nginx.conf` é o único controle de acesso. Mantenha-a restrita aos endereços dos administradores.

**Acesso ao Indexer.** O serviço lê do Wazuh Indexer com o usuário somente leitura `wptv_svc` (role `wptv_role`, índices `wazuh-alerts-*` e `wazuh-archives-*`). Ver [Passo 3](#passo-3---credenciais-do-wazuh-indexer-usuário-de-serviço-wptv_svc).

**Segredos.** A senha do Indexer e as chaves de API ficam em `/etc/wazuh-process-tree/wptv.env` (modo `600`, dono `wazuh-dashboard`). O repositório traz apenas `wptv-fim/wptv.env.example` com placeholders. O `.gitignore` exclui `wptv.env`, `*.env` (exceto `*.env.example`), `*.pem` e `*.key`.

**TLS.** O `proxy_ssl_verify off` vale apenas para os saltos em loopback entre o nginx e os serviços locais. Defina `WPTV_INDEXER_CA_CERT` no `wptv.env`: sem ele, a verificação do certificado da conexão com o Indexer fica desativada e um aviso é gravado no log.

**Dados enviados a terceiros.** Todos os recursos abaixo são opcionais e permanecem desligados enquanto a respectiva chave não estiver definida no `wptv.env`.

| Recurso | Destino | Dados enviados |
|---|---|---|
| AI ANALYZE (WPTV) | API da Anthropic | Host, IP e ID do agente, nomes de processo, usuário, primeiros 200 caracteres da linha de comando, caminhos de arquivo, relações pai-filho |
| Investigate with AI (FIM Alert Investigation) | API da Anthropic | IDs e descrições de regra, caminhos de arquivo e de registro, tipos de evento, nomes de usuário e de processo, hashes, eventos de processo na janela de ±60 s, resultados de threat intelligence |
| Enriquecimento de threat intelligence | VirusTotal e AlienVault OTX; AbuseIPDB | SHA256 do arquivo (VirusTotal, OTX); endereços IP encontrados no contexto do evento (AbuseIPDB) |

Não habilite esses recursos onde caminhos, hostnames ou linhas de comando não podem sair da organização. Cada requisição de análise também consome cota da API da Anthropic, mais um motivo para manter a restrição do nginx.

Para reportar uma vulnerabilidade, consulte o [SECURITY.md](SECURITY.md).

---

## Limites da Validação

- O teste formal por threshold controlado das regras 100300 a 100304, com cenários documentados em LABDESK e labnix, é uma etapa em aberto. As evidências atuais vêm de scripts de simulação e de alertas reais indexados.
- A regra 100301 não foi confirmada em Windows.
- Os parâmetros de correlação são de laboratório e exigem baseline em produção.
- O manager roda o syscheck com `frequency` de 60 s (valor de laboratório, para acelerar a validação). Os endpoints LABDESK e LABNIX mantêm `frequency` de 3600 s, porque os caminhos monitorados usam `realtime` ou `whodata`.
- As regras Sysmon são um conjunto de pesquisa, validado com uma execução de cada cenário no LABDESK. O Sysmon complementa o FIM e não o substitui: algumas operações (sobrescrita com `Set-Content`, append, rename) não geraram evento Sysmon nos testes.
- Regras de frequência entre as duas fontes (FIM e Sysmon) não dispararam nos testes, então o pareamento é feito no Discover por caminho e horário.

---

## Referências

- [Documentação Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Regras FIM customizadas](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html)
- [Configuração syscheck](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)
- [Release notes 4.14.8](https://documentation.wazuh.com/current/release-notes/release-4-14-8.html)
- [MITRE ATT&CK - T1565 Data Manipulation](https://attack.mitre.org/techniques/T1565/)
- [MITRE ATT&CK - T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [MITRE ATT&CK - T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK - T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Unified Sysmon Configs](https://github.com/mym0us3r/Unified-Sysmon-Configs)
- [Sysmon - Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [WAZUH-Process-Tree-Viewer](https://github.com/mym0us3r/WAZUH-Process-Tree-Viewer)

---

## Autor

**Kislley Rodrigues (m0us3r)**
Wazuh Ambassador | Detection Engineering | Blue Team

---

## Agradecimentos

- **Equipe Wazuh** pela plataforma SIEM/XDR open source e pelo Programa Ambassador

---

*Regras de detecção, painel FIM Alert Investigation e configurações de agente validados no Wazuh 4.14.8, Windows 11 Pro build 26200, Sysmon schema 4.91, Ubuntu 24.04.5 kernel 6.17.0 e Claude Sonnet 4.6.*

---

## Atualização 2026-10-11

| Mudança | Detalhe |
|---|---|
| Hipótese AP-1 refutada | O suposto stall do leitor inotify do `syscheckd` no labnix não se confirmou: o realtime entrega eventos (41 eventos na janela, 36 em modo realtime). Não é issue do upstream. |
| Handbook revisado | 53 páginas, 15 achados validados e 1 hipótese refutada, com 9 novos prints do Wazuh Discover e legenda em cada figura. |
| Acesso ao Indexer documentado | O WPTV e o FIM Alert Investigation consultam o Wazuh Indexer com o usuário de serviço somente leitura `wptv_svc` (role `wptv_role`, índices `wazuh-alerts-*` e `wazuh-archives-*`). Credenciais em `/etc/wazuh-process-tree/wptv.env`. |
| Regra de verificação | Confirme o realtime por `syscheck.mode` no `archives.json`, use `strace -y` incluindo `pselect6` e não consulte o `fim.db` ativo. |

---

## Atualização 2026-10-12

| Mudança | Detalhe |
|---|---|
| Sysmon como camada complementar | Cinco regras de pesquisa (100521, 100540, 100541, 100554, 100555) pareadas com as regras FIM por caminho e horário, construídas a partir do repositório [Unified Sysmon Configs](https://github.com/mym0us3r/Unified-Sysmon-Configs). Disponíveis para a comunidade testar, modificar e adaptar. |
| Pares validados | Criação, sobrescrita via `cmd`, exclusão, drop de executável, timestomping e limpeza, cada um com o alerta FIM e o alerta Sysmon no mesmo caminho. |
| Casos somente FIM documentados | Sobrescrita com `Set-Content`, append e rename não geraram evento Sysmon: o FIM é a única fonte nesses casos. |
| Handbook revisado | 60 páginas, com a nova seção 8.5 "Sysmon como Camada Complementar ao FIM". |

---

## Atualização 2026-10-14

| Mudança | Detalhe |
|---|---|
| Handbook em EN-US | O Handbook passa a ser entregue em EN-US (62 páginas), com a versão PT-BR (63 páginas) mantida em `docs/` para referência. Contagem de páginas conforme exibida no Microsoft Word. |
| Revisão contra a documentação oficial | Afirmações conferidas com a documentação Wazuh 4.14 e o ruleset 4.14.8. Alinhados à documentação: o `windows_audit_interval` move o whodata para realtime em caso de divergência e não reaplica a SACL (seção 3.5, achado AO-7); a persistência por chave Run gera a regra 752 (valor adicionado); as regras nativas etiquetam o PCI DSS como `11.5`; a restrição de caminhos UNC passa a citar as notas de versão 4.13.0 (#30060). |
| Observações de laboratório identificadas | Os achados AC-1 a AC-7 e AO-1 a AO-8 estão marcados como observações de laboratório na 4.14.x, não como comportamentos declarados na documentação oficial. |
| Componente comunitário | O FIM Alert Investigation é declarado como componente comunitário, fora da plataforma Wazuh e sem suporte da Wazuh. |

---

## Wazuh

Este projeto foi desenvolvido como parte do [Programa Wazuh Ambassador](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

O Wazuh é uma plataforma de segurança gratuita e open source que oferece proteção unificada de XDR e SIEM.
Saiba mais em [wazuh.com](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).
