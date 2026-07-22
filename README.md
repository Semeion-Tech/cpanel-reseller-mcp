# cPanel Reseller MCP

MCP global e multiusuário para operar um reseller cPanel com segurança. A fase 1 usa um
catálogo local estruturado; RAG está deliberadamente reservado para a fase 2.

## Arquitetura e garantias

O serviço roda na VPS Semeion como plano de controle HTTPS. Ele autentica cada pessoa/cliente com
token próprio, aplica RBAC e escopo por conta cPanel, chama WHM API 1 ou UAPI com credenciais de
menor privilégio e grava auditoria encadeada. Escritas passam obrigatoriamente por
`action_prepare` e `action_execute`; ações destrutivas exigem confirmação textual exata e podem
exigir um segundo administrador.

As consultas de conta aceitam UID, username, domínio, e-mail de contato ou IP e resolvem tudo
para o username canônico dentro do escopo do usuário. Respostas preservam o payload bruto para
compatibilidade e acrescentam `normalized_data`, `correlation_id` e erros estruturados. O dossiê
executa somente leituras, tolera seções indisponíveis e registra toda a cadeia com o mesmo ID de
correlação.

O catálogo diferencia seis classes de risco: `read`, `sensitive_read`,
`external_side_effect`, `reversible_write`, `destructive` e `privileged`. Operações avançadas sem
schema validado ficam bloqueadas por padrão. Leitura de alvos sensíveis como `.env`, `.my.cnf`,
`wp-config.php` e `config.php` também é negada por padrão.

Clientes MCP remotos usam `https://mcp-reseller.semeiontech.com/mcp`. Clientes que aceitam apenas
stdio executam `reseller-mcp-bridge`, que usa `mcp-remote` sem expor o bearer token no argv.

## Ferramentas públicas

- Inventário: `reseller_overview`, `accounts_list`, `account_resolve`, `account_inspect`.
- Diagnóstico: `account_dossier`, `account_healthcheck`.
- Descoberta: `capabilities_search`, `capability_describe`, `capability_check`.
- Execução: `query_execute`, `action_prepare`, `action_execute`, `action_cancel`,
  `action_approve`.
- Governança: `audit_search`, `job_get`, `observability_snapshot`.

O catálogo completo contém todas as operações anunciadas pelo servidor, porém operações não
curadas ficam restritas a administradores; funções de token, sessão, access hash e chamadas com
senha são bloqueadas pelo harness. Mesmo para administradores, capacidades avançadas sem schema
não são executáveis até serem curadas ou a proteção ser explicitamente desativada.

### Fluxo recomendado

1. Resolva a conta com `account_resolve` quando o identificador não for o username canônico.
2. Use `account_dossier` para uma visão completa ou `account_healthcheck` para achados priorizados.
3. Para uma operação específica, pesquise, descreva e execute `capability_check` antes da chamada.
4. Use `query_execute` apenas para leituras; qualquer escrita passa pelo fluxo prepare/execute.

Consulte [contratos e segurança](docs/api-contracts.md) e a
[decisão sobre a evolução do harness](docs/architecture/adr-001-modular-harness-and-memory.md).
Para trabalhar nessa evolução, siga o
[guia incremental para iniciantes](docs/architecture/incremental-harness-evolution-guide.md).

## Desenvolvimento

Requer Python 3.12 e `uv`.

```bash
uv sync --extra dev
uv run python scripts/capture_live_catalog.py
cp .env.example .env
uv run reseller-mcp-admin users create admin --role admin --scope '*'
uv run reseller-mcp-admin tokens issue admin codex
uv run reseller-mcp
```

## Gestão da equipe

```bash
reseller-mcp-admin users list
reseller-mcp-admin users create ana --role operator --scope acctalpha --scope acctbeta
reseller-mcp-admin users set-scopes ana --scope acctalpha
reseller-mcp-admin users set-active ana false
reseller-mcp-admin tokens issue ana claude-desktop
reseller-mcp-admin tokens list ana
reseller-mcp-admin tokens revoke KEY_ID
```

O token emitido é mostrado uma única vez. Cada combinação pessoa/cliente deve ter um token
distinto, permitindo revogação e rastreabilidade independentes.

## Deploy

O fluxo normal usa GitHub Actions:

1. Pull requests executam formatação, lint, tipagem, testes, auditoria de dependências, Trivy e
   build do container.
2. Push aprovado em `main` publica uma imagem imutável AMD64/ARM64 no GHCR.
3. O job `production` usa um runner dedicado na VPS, valida o container e `/healthz` e faz rollback
   automático em caso de falha.

O `.env`, o banco SQLite e os tokens upstream nunca transitam pelo Actions. Consulte o
[guia de CI/CD](docs/ci-cd.md) para configurar o runner dedicado, a proteção de branch e o ambiente
de produção.

Para bootstrap local ou recuperação manual, ainda é possível executar `docker compose up -d
--build` diretamente na VPS. Publique somente o proxy TLS; a porta 8787 permanece vinculada a
`127.0.0.1`.

Não versionar `.env`, tokens, access hash, dumps de auditoria ou o banco SQLite.

## Qualidade

```bash
uv run ruff check .
uv run mypy src/reseller_mcp
uv run pytest -q
```
