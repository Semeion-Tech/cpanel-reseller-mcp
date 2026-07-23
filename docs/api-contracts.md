# Contratos, segurança e diagnóstico

## Identidade da conta

`account_resolve(identifier)` compara o identificador, sem diferenciar maiúsculas e minúsculas,
com UID, username, domínio principal, e-mail de contato e IP. A busca começa no inventário já
filtrado pelo escopo RBAC; portanto, um identificador válido fora do escopo é reportado como não
encontrado. Ambiguidades são recusadas.

`account_inspect(account)` mantém os campos históricos de `OperationResult` na raiz da resposta e
acrescenta `resolved` com a identidade canônica.

## Dossiê e health check

`account_dossier(identifier, sections?)` consulta, em paralelo e somente para leitura:

- conta, domínios e bancos de dados;
- caixas postais, MX, encaminhamentos, autoresponders, SPF e DKIM;
- FTP, backups, banda, PHP, certificados SSL públicos e redirecionamento HTTPS;
- inventário raso de `public_html`, sem conteúdo de arquivos.

Uma falha de feature, permissão ou configuração afeta somente a operação correspondente. A seção
fica `partial`, `failed` ou `unavailable`, e a resposta inclui `limitations`. Todas as operações e
o evento final compartilham um `correlation_id`, que pode ser usado em `audit_search`.

`account_healthcheck(identifier)` deriva achados determinísticos e evidências do mesmo dossiê:
restrição de conta, pressão de disco, ausência de backup restaurável, SPF/DKIM inválidos, FTP
anônimo, PHP abaixo da baseline e seções incompletas. Ele não altera a conta nem corrige achados.

## Disponibilidade em três níveis

`capability_check(capability_id, identifier?)` separa:

1. disponibilidade no servidor e no catálogo;
2. autorização da role e existência de schema validado;
3. disponibilidade para a conta, incluindo features exigidas pelo cPanel.

Isso evita confundir “a função existe no servidor” com “esta conta pode executá-la”.

## Taxonomia de risco

| Risco | Exemplo | Regra |
|---|---|---|
| `read` | listar bancos | `query_execute` |
| `sensitive_read` | ler conteúdo de arquivo permitido | `query_execute`, role reforçada e guardrail de alvo |
| `external_side_effect` | enviar e-mail ou solicitar certificado | prepare/execute e confirmação humana |
| `reversible_write` | alterar configuração reversível | prepare/execute |
| `destructive` | remover conta, banco ou arquivo | confirmação exata; segundo aprovador opcional |
| `privileged` | operação administrativa ampla | role admin e perfil upstream admin |

Backups enviados a FTP, e-mails de ativação e solicitações de certificados são efeitos externos,
não simples leituras. Chaves privadas DKIM, access hashes, tokens, sessões e operações que recebem
senha permanecem bloqueados.

## Acesso a banco de dados

`database.query_readonly`, `database.transaction_execute` e
`workflow.database_migration_apply` alcançam o MySQL de uma conta por conexão TCP direta,
usando credenciais efêmeras provisionadas sob demanda via `uapi.Mysql.*` (nunca persistidas).
`query_readonly` aceita apenas um único `SELECT`. `transaction_execute` valida cada statement
via AST (`sqlglot`), permitindo somente `UPDATE`/`DELETE`/`INSERT`; o `action_prepare` roda um
backup das linhas afetadas e um dry-run com `ROLLBACK`, e o `action_execute` aplica com `COMMIT`
e pós-validação. `workflow.database_migration_apply` acrescenta um ledger versionado
(`migration_id` + checksum do SQL): reaplicar com o mesmo conteúdo é no-op; conteúdo diferente é
bloqueado.

## Schemas e normalização

As operações curadas declaram argumentos obrigatórios e `additionalProperties: false`. Entre os
contratos cobertos estão domínio para validação SPF/DKIM, agrupamento para banda, diretório para
listagem de arquivos e seleção explícita de certificado público no SSL. Operações descobertas ao
vivo sem schema ficam desabilitadas por padrão (`ALLOW_UNTYPED_ADVANCED=false`).

O payload upstream original permanece em `data`. `normalized_data` fornece nomes estáveis,
booleans, bytes, percentuais, contagens e timestamps ISO quando a fonte permite. Erros retornam
`code`, `category`, `retryable`, `hint` e `details`.

## Observabilidade

`observability_snapshot` é restrito a administradores e expõe apenas contagens e latência agregada
por capability e resultado. Não contém usernames, contas, argumentos ou respostas. A auditoria
SQLite continua sendo a fonte durável, encadeada por hash e pesquisável por correlação.
