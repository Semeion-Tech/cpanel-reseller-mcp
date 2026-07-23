# Acesso seguro ao banco de dados (P0 #1)

## Contexto e problema

Não existe hoje nenhuma forma segura de executar SQL contra o banco MySQL de uma conta cPanel
gerenciada pelo reseller-mcp. A prática atual, manual e não auditada, é publicar um arquivo PHP
temporário em `public_html`, disparar a execução via HTTP e apagar o arquivo em seguida. Isso
expõe uma janela pública de execução arbitrária de código, não deixa auditoria estruturada, não
tem backup automático, e depende de disciplina manual para não esquecer de apagar o arquivo.

Este documento cobre o primeiro item P0 do roadmap priorizado: introduzir três capabilities novas
— `database.query_readonly`, `database.transaction_execute` e
`workflow.database_migration_apply` — que substituem esse improviso por um caminho nativo,
auditado e alinhado ao modelo de segurança já existente no harness (catálogo de capabilities,
`query_execute` para leituras, `action_prepare`/`action_execute` para escritas).

Os outros dois itens P0 do roadmap (confiabilidade de `action_prepare`/`action_execute` e redação
automática de segredos em `Fileman.get_file_content`) ficam fora de escopo desta spec e serão
tratados em specs separadas.

## Descoberta técnica

O cliente `cpanel.py` só fala WHM API1/UAPI por HTTPS; não há execução de código nem SSH em
runtime (o script `capture_live_catalog.py` usa SSH, mas é uma ferramenta manual de
desenvolvimento, não algo que o servidor MCP em produção executa).

O catálogo ao vivo capturado (`data/live_operations.json`) confirma que **não existe nenhuma API
UAPI/WHM para executar SQL arbitrário**. O módulo `Mysql` só gerencia bancos, usuários e
privilégios: `create_database`, `create_user`, `set_password`, `set_privileges_on_database`,
`delete_user`, `delete_host`, `dump_database_schema` (somente schema, não dados), `add_host`
(libera um host remoto a acessar o MySQL da conta), `locate_server`/`get_server_information`
(descobre host/porta) e `get_restrictions`.

Isso é suficiente para montar uma conexão TCP direta e efêmera ao MySQL da conta, sem depender de
código publicado dentro do webspace do cliente.

## Arquitetura

### Ciclo de vida da conexão (efêmero, sem credenciais persistidas)

Para cada chamada de `database.*`:

1. `Mysql::locate_server` / `get_server_information` — resolve host/porta do MySQL da conta.
2. `Mysql::add_host` — libera o IP de saída da VPS Semeion como host remoto autorizado. Idempotente:
   verifica se a entrada já existe antes de duplicar.
3. `Mysql::create_user` + `set_password` (senha aleatória gerada em memória, nunca persistida) +
   `set_privileges_on_database` — cria um usuário descartável com o privilégio mínimo necessário:
   `SELECT` apenas para `query_readonly`; privilégios de escrita restritos ao banco alvo para
   `transaction_execute`/`migration_apply`.
4. Conexão TCP direta via driver MySQL assíncrono (nova dependência de runtime — `asyncmy` ou
   `aiomysql`, a decidir na fase de implementação), com timeout curto.
5. Bloco `finally`: `Mysql::delete_user` e, se foi este harness quem criou a entrada de host,
   `Mysql::delete_host`. Isso deve rodar mesmo se a query falhar ou o processo crashar no meio.

**Reaper de órfãos:** como a etapa 5 pode falhar (crash do processo, rede indisponível na hora do
cleanup), é necessário um job de manutenção que audite periodicamente usuários/hosts MySQL
efêmeros que ultrapassaram um TTL curto (ex.: 5 minutos) e não foram removidos, e os revogue. Sem
isso, uma falha de cleanup vira uma porta aberta esquecida.

### Risco em aberto — spike de conectividade (passo 0 da implementação)

Não está confirmado que a porta MySQL das contas é de fato alcançável por TCP a partir da VPS
Semeion após o `add_host` — o firewall do provedor de hospedagem pode bloquear a porta
externamente mesmo com o ACL do MySQL liberado no cPanel. Antes de implementar o restante, a
implementação deve validar isso numa conta de teste: `add_host` + `create_user` + tentativa de
`SELECT 1` via TCP.

**Fallback documentado (só entra em jogo se o spike falhar):** execução mediada via cPanel —
publicar um script PHP efêmero com nome aleatório e token de uso único, gerado e apagado
automaticamente pelo próprio harness (não mais manual), com janela de exposição minimizada. Este
fallback não é implementado nesta fase a menos que o spike confirme que a via direta não funciona.

### Guardrails de SQL

Defesa em profundidade além dos privilégios do usuário MySQL efêmero:

- `database.query_readonly` rejeita, na camada de aplicação, qualquer statement que não seja
  `SELECT` puro.
- `database.transaction_execute` e `workflow.database_migration_apply` bloqueiam DDL/DCL
  perigosos mesmo que o usuário efêmero não devesse ter privilégio para eles (`DROP DATABASE`,
  `GRANT`, `CREATE USER`, `REVOKE`, etc.) — proteção contra erro de escopo de privilégio.
- Limite de linhas retornadas e timeout de execução em todas as três capabilities.

## Capabilities

### `database.query_readonly`

- Risco: `sensitive_read`. Despachada via `query_execute` (somente leitura, sem prepare/execute).
- Entrada: `{account, database, sql, params}`.
- `sql` deve ser um único `SELECT` parametrizado; `params` é lista posicional ou dict nomeado
  conforme a sintaxe do driver escolhido.

### `database.transaction_execute`

- Risco: `reversible_write` (ou `destructive`, dependendo dos statements — a classificação final
  de risco por statement é decidida na implementação). Despachada via `action_prepare` +
  `action_execute`, reusando o mecanismo de confirmação humana e `idempotency_key` já existente no
  harness.
- Entrada: `{account, database, statements: [{sql, params}]}`.
- `action_prepare`:
  1. Valida os statements contra os guardrails.
  2. Roda um `SELECT` das linhas-alvo (derivado do `WHERE`/`JOIN` de cada statement) → snapshot de
     backup salvo como arquivo privado (formato JSON).
  3. Roda a transação real terminando em `ROLLBACK` (dry-run) para provar que aplica sem erro,
     sem persistir a mudança.
- `action_execute` (após confirmação humana explícita, igual ao restante do sistema): roda a
  mesma transação terminando em `COMMIT`, seguida de pós-validação (recontagem ou checksum das
  linhas afetadas, comparado ao esperado do dry-run).

### `workflow.database_migration_apply`

- Usa a mesma máquina do `transaction_execute` (backup de linhas-alvo, dry-run com rollback,
  execução real com commit, pós-validação), mas adiciona rastreio versionado.
- Entrada: `{account, database, migration_id, statements: [{sql, params}]}`.
- Nova tabela `db_migrations` no SQLite do próprio reseller-mcp (`db.py`):
  `account, database, migration_id, checksum, applied_at, backup_ref, rows_affected, status`.
- Regra de idempotência: reaplicar o mesmo `migration_id` com o mesmo checksum do SQL é um no-op
  seguro (retorna o resultado já registrado); reaplicar o mesmo `migration_id` com um checksum
  diferente é bloqueado com erro explícito, exigindo um novo `migration_id`.

## Integração com o harness existente

`ApiFamily.WORKFLOW` já existe no enum (`models.py`) mas nunca foi implementado como caminho de
despacho — hoje `query_execute`, `prepare_action` e `execute_action` só sabem chamar
`self.cpanel.call()` (HTTP para WHM/UAPI). Esta spec introduz um registro de handlers Python para
capabilities da família `WORKFLOW`, para que o harness despache para as novas rotinas de banco em
vez de HTTP — mantendo auditoria (`AuditLog`), `correlation_id`, `OperationResult`,
`Preparation`/`idempotency_key` e o fluxo prepare/execute idênticos ao resto do sistema.

## Tratamento de erros

Segue a taxonomia de erro já estabelecida (`code`, `category`, `retryable`, `hint`, `details`).
Casos novos a cobrir: MySQL inalcançável por TCP (`UPSTREAM_NETWORK_ERROR`, com `hint` apontando
para o fallback ou para investigar firewall), feature Remote MySQL desabilitada na conta
(`ACCOUNT_FEATURE_UNAVAILABLE`), statement rejeitado pelos guardrails (`VALIDATION_ERROR`),
checksum de migration divergente (`MIGRATION_CHECKSUM_MISMATCH`), falha de cleanup pós-execução
(logada e sinalizada para o reaper, mas não bloqueia o resultado da operação principal).

## Testes

- Unit tests mockando `CPanelClient` para as chamadas UAPI `Mysql::*` (provisionamento e cleanup
  de credenciais efêmeras).
- Testes de integração contra um MySQL real em container Docker efêmero, para provar: SQL
  parametrizado funciona, dry-run com `ROLLBACK` não persiste nada, backup de linhas-alvo é
  gravado corretamente, `COMMIT` real aplica e passa na pós-validação, e o ledger de migrations
  bloqueia reaplicação com checksum divergente e é no-op com checksum igual.
- Segue o padrão já usado no repo (pytest + fixtures em `tests/conftest.py`).

## Fora de escopo desta spec

- Confiabilidade de `action_prepare`/`action_execute` para payloads maiores e busca por
  `idempotency_key`/`preparation_id`/`correlation_id` (P0 #2, spec separada).
- Redação automática de segredos em `Fileman.get_file_content` (P0 #3, spec separada).
- Operações de arquivo (`file_stat`, `save_private_file`, `delete_file`, filtro
  `only_these_files`) (P1, spec separada).
- Provisionamento de segredos de longa duração (`workflow.secret_provision`) (P1, spec separada) —
  esta spec usa apenas credenciais de banco efêmeras, não persistidas.
- Smoke test seguro e workflow completo de deploy (P1/P2, specs separadas, dependem desta).
