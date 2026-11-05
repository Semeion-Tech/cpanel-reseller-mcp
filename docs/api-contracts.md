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

## Publicação de imagens

`workflow.images_publish` (escrita reversível, papel `operator`) publica imagens já colocadas no
staging por `POST /staging/images`. A rota autentica o bearer por conta própria (rotas
customizadas não passam pelo verificador do MCP), aceita só POST, valida cada arquivo pelos bytes
com Pillow e devolve `{"items": [...], "rejected": [{"name", "code", "message"}]}`; um arquivo
rejeitado não derruba os demais. No nginx, só essa rota aceita corpo de até 50 MB, com o limite do
ModSecurity elevado apenas nela.

O prepare confere posse e validade de cada `staging_id`, nomes, extensão contra o formato real e a
listagem do destino; a URL pública prevista vem do document root mais específico da conta. O
execute lista o destino de novo, envia o lote por sessão de cPanel (`create_user_session` e depois
`/execute/Fileman/upload_files` com `overwrite=0`) e verifica cada arquivo pela listagem e pelo
SHA-256 da URL. `verified` só é verdadeiro com todos os arquivos conferidos. Remoção continua com
`api2.Fileman.fileop` `trash`, que exige frase.

| Código | Quando |
|---|---|
| `IMAGE_NAME_INVALID` | Nome fora de `[a-z0-9._-]` com extensão de imagem. |
| `IMAGE_FORMAT_NOT_ALLOWED` | Bytes não decodificáveis ou formato fora de PNG/JPEG/WebP/GIF/AVIF. |
| `IMAGE_EXTENSION_MISMATCH` | Extensão de outro formato. |
| `IMAGE_TOO_LARGE` | Acima de 10 MB ou de 40 megapixels. |
| `BATCH_TOO_LARGE` | Lote acima de 40 MB ou de 20 arquivos. |
| `STAGING_NOT_FOUND` | ID inexistente, expirado ou de outro usuário. |
| `DUPLICATE_NAME` | Nome repetido no lote. |
| `DESTINATION_EXISTS` | Arquivo com o mesmo nome no destino (nunca sobrescreve). |
| `DESTINATION_PARENT_MISSING` | Diretório de destino inexistente (crie com `api2.Fileman.mkdir`). |
| `UPLOAD_SESSION_DENIED` | O perfil do upstream não tem a ACL `create-user-session`. |
| `UPLOAD_FAILED` | O cPanel recusou um ou mais arquivos; o resultado lista cada um. |

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
