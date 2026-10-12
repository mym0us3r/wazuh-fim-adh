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
