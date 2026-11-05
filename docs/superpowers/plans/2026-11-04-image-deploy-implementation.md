# Plano de implementação: deploy de imagens pelo MCP

> Passos marcados com `- [ ]`. Cada fatia termina com testes verdes, PR próprio (só quando o Kleber pedir) e, quando houver escrita no servidor, canário ao vivo com nomes `mcptest-*`.

**Objetivo:** dar ao MCP autonomia para publicar imagens em `public_html` de uma conta cPanel, em lote, sem que o binário passe pelo modelo nem pelos argumentos das ferramentas. O caso que motivou foi o das peças de e-mail do m-dias: as imagens saem de `mail-marketing/emails/static/` e vão para `public_html/mail-campanha/images` da conta `promocaosaborque`, publicadas hoje à mão pelo Gerenciador de Arquivos.

**Arquitetura:** o upload tem dois tempos.

1. **Staging.** Um comando local, `reseller-mcp-upload`, envia os arquivos por multipart para `POST /staging/images` no servidor do MCP, com o mesmo bearer token da bridge, lido do Keychain. O servidor valida cada imagem, guarda o arquivo com prazo de validade e devolve um `staging_id` para cada uma.
2. **Publicação.** `workflow.images_publish` entra no pipeline normal (`action_prepare` e depois `action_execute`), referenciando os `staging_id`. O execute abre uma sessão de cPanel com `create_user_session`, usando o perfil `operator`, e envia o lote multipart para `/execute/Fileman/upload_files` com `overwrite=0`. Em seguida verifica a publicação pela listagem e pelo SHA-256 da URL pública.

**Evidência ao vivo (2026-11-04, conta `promocaosaborque`):**
- O proxy WHM `/json-api/uapi_cpanel` ignora corpo multipart e responde `"You must specify at least one file to upload."`. Por isso o transporte atual (`cpanel.py`, tudo em query string) não serve para upload.
- `create_user_session` (service `cpaneld`) com um token que tenha a ACL `create-user-session`, seguido da troca da URL da sessão por cookie e do multipart em `/cpsess…/execute/Fileman/upload_files`, funcionou: `{"succeeded": 1, "uploads": [{"status": 1, "file": "...", "size": 78, "reason": "Êxito ao carregar “...”."}]}`. A URL pública respondeu HTTP 200 e o SHA-256 bateu.
- Um JPEG real de 150 KB em multipart passa pelo ModSecurity do vhost. Um corpo de 3 MB recebe 413 (`client_max_body_size 2m`).
- A imagem do container não tem Pillow.

## Decisões fechadas

| Tema | Decisão |
|---|---|
| Origem dos bytes | Staging local pela bridge. Nada de base64 nos argumentos, nada de download por URL. |
| Formatos | PNG, JPEG, WebP, GIF e AVIF, detectados pelos bytes e decodificados com Pillow. A extensão precisa bater com o formato real. SVG fica de fora. |
| Reencode | Não. O arquivo é publicado byte a byte como foi enviado. |
| Lote | Sim, até 20 imagens por ação. |
| Sobrescrita | Proibida (`DESTINATION_EXISTS`). Mudar uma imagem significa criar um nome novo (`-02`, `-03`), como já se faz no m-dias. |
| Remoção | Fica fora deste workflow. Continua com `api2.Fileman.fileop trash`, que é destrutivo e exige frase. |
| Perfil do token | `operator`. O Kleber adiciona a ACL `create-user-session` a esse token. |
| Limite do vhost | Sobe só na rota de staging (ver Tarefa 0). O resto do vhost continua em 2 MB. |

## Limites (constantes em `image_workflows.py`)

- 10 MB por arquivo, 40 MB por lote e 20 arquivos por lote.
- Até 40 megapixels por imagem, ajustado em `Image.MAX_IMAGE_PIXELS`, como proteção contra decompression bomb.
- O staging expira em 1 hora, e o arquivo é apagado do staging depois de uma publicação bem-sucedida.
- O nginx da rota `/staging/` fica em `client_max_body_size 50m`, o que cobre um lote cheio com folga para o overhead do multipart.

## Restrições globais

- Python 3.12 com `uv`. `uv run ruff check`, `uv run ruff format --check`, `uv run mypy` e `uv run pytest` passam ao fim de cada tarefa.
- Os testes usam o formato real das respostas, já capturado acima. O simulador reproduz o comportamento do servidor (proxy que ignora multipart, sessão negada sem ACL), para que o teste falhe quando a correção não estiver aplicada.
- A URL e o cookie da sessão (`cpsess…`) são segredos: nunca vão para log, audit nem resposta de ferramenta. É preciso conferir que `audit.redact` cobre esses dois.
- Os bytes da imagem nunca entram no audit. Entram só o nome, o tamanho, o tipo, as dimensões e o SHA-256.
- Commits em português, sem `Co-Authored-By`, e sem a palavra barrada pelo hook do repositório.

---

## Tarefa 0: pré-requisitos de operação (Kleber)

- [ ] Adicionar a ACL `create-user-session` ao token `operator` do reseller `integer`.
- [ ] Conferir com `myprivs` usando o perfil `operator`. Pode ser pelo `scripts/` ou pelo mesmo teste descartável de 2026-11-04.
- [ ] Atualizar `deploy/nginx.conf.example` com um `location /staging/` próprio, mantendo os mesmos headers e o mesmo `proxy_pass` do `/mcp`, e com `client_max_body_size 50m;` e `proxy_request_buffering on;`. Aplicar com `deploy/publish_endpoint.sh`, que já roda `nginx -t` e o reload.
- [ ] Repetir o teste do WAF com um lote multipart de cerca de 30 MB de JPEGs reais para `/staging/images` (sem token: o esperado é 401 da aplicação, nunca 403 nem 413).

## Tarefa 1: transporte de upload no `CPanelClient`

**Arquivos:** `src/reseller_mcp/cpanel.py` e `tests/test_cpanel_upload.py` (novo).

- [ ] `async def upload_files(self, account: str, directory: str, files: list[tuple[str, bytes, str]], *, profile: str = "operator") -> dict[str, Any]`:
  1. Chama `GET /json-api/create_user_session` com `user=<account>` e `service=cpaneld`. Uma resposta sem `data.url` vira `CPanelError(code="UPLOAD_SESSION_DENIED", category="policy")`, preservando o `metadata.reason`.
  2. Abre um cliente efêmero para o host e a porta da URL da sessão, com `follow_redirects=True`, e faz o GET na URL para obter o cookie. O cliente é fechado no `finally`.
  3. Envia `POST /cpsess…/execute/Fileman/upload_files` com `data={"dir": directory, "overwrite": "0"}` e `files={"file-1": ..., "file-N": ...}`.
  4. Devolve `data` normalizado: `{"succeeded", "failed", "uploads": [{"file", "size", "status", "reason"}]}`. Se `status` vier 0 ou houver `errors`, levanta `CPanelError(code="UPLOAD_FAILED")` com os motivos em `details`.
- [ ] Sem retry automático: o upload não é idempotente.
- [ ] Testes com `httpx.MockTransport`:
  - sessão negada, usando o texto real `"Permission denied: You do not have the required privileges to run “create_user_session”."`;
  - lote com sucesso, usando o formato real capturado;
  - falha parcial (`failed > 0`);
  - a URL da sessão não aparece no `str()` das exceções.

## Tarefa 2: armazenamento e validação do staging

**Arquivos:** `src/reseller_mcp/image_staging.py` (novo), `src/reseller_mcp/db.py` (nova tabela), `pyproject.toml` e `uv.lock` (`pillow`, mais `python-multipart` se ainda não vier pelo `mcp`), e `tests/test_image_staging.py`.

- [ ] Tabela `image_staging` com as colunas `id`, `username`, `original_name`, `format`, `mime`, `width`, `height`, `size`, `sha256`, `created_at` e `expires_at`. O arquivo fica em `data/staging/<id>`, no volume que já existe no `compose.yaml`.
- [ ] `ImageStaging.store(username, filename, data) -> StagedImage`:
  - impõe o tamanho máximo antes de decodificar;
  - abre com Pillow, roda `Image.open(...).verify()` e depois reabre para ler o formato e as dimensões;
  - aceita apenas os formatos `PNG`, `JPEG`, `WEBP`, `GIF` e `AVIF`, e qualquer outro dá `IMAGE_FORMAT_NOT_ALLOWED`;
  - o nome segue `^[a-z0-9][a-z0-9._-]{0,99}\.(png|jpe?g|webp|gif|avif)$`, sem `..` e sem nome oculto, ou dá `IMAGE_NAME_INVALID`;
  - a extensão precisa corresponder ao formato real, ou dá `IMAGE_EXTENSION_MISMATCH`.
- [ ] `get(username, id)` só devolve itens do próprio usuário que ainda não expiraram (`STAGING_NOT_FOUND`). `purge_expired()` roda no startup e a cada `store`.
- [ ] Conferir se o Pillow da imagem Docker (base `python:3.12-slim`) decodifica AVIF. Se não decodificar, a Pillow ≥ 11.3 já traz o AVIF no wheel, e cabe um teste que falhe sem ele.
- [ ] Testes com PNG, JPEG, WebP, GIF e AVIF reais gerados em fixture; PHP com extensão `.png`; JPEG renomeado para `.png`; SVG; arquivo truncado; imagem acima do limite de pixels; item expirado; item de outro usuário.

## Tarefa 3: rota HTTP `POST /staging/images`

**Arquivos:** `src/reseller_mcp/server.py` e `tests/test_staging_route.py`.

- [ ] `@mcp.custom_route("/staging/images", methods=["POST"])`. Rotas customizadas não passam pelo `token_verifier`, então a autenticação é explícita: `Authorization: Bearer` validado por `runtime.tokens.authenticate`, com 401 em qualquer falha. O papel mínimo é `operator`, ou a rota responde 403.
- [ ] Lê o multipart em streaming, aplica os limites por arquivo e por lote (413 com código `IMAGE_TOO_LARGE` ou `BATCH_TOO_LARGE`) e chama `ImageStaging.store` para cada arquivo.
- [ ] A resposta é JSON: `{"items": [{"staging_id", "name", "format", "width", "height", "size", "sha256", "expires_at"}], "rejected": [{"name", "code", "message"}]}`. Um arquivo rejeitado não derruba os outros.
- [ ] Grava um evento de audit `staging.images` com os metadados, sem os bytes.
- [ ] Testes com o `TestClient` do Starlette: sem token, token de `viewer`, lote misto (válido e inválido), lote acima do limite.

## Tarefa 4: comando local `reseller-mcp-upload`

**Arquivos:** `src/reseller_mcp/upload_cli.py` (novo), `pyproject.toml` (`[project.scripts]`), `docs/client-configuration.md` e `tests/test_upload_cli.py`.

- [ ] Comando `reseller-mcp-upload <arquivos ou pasta>...`, feito com Typer. Lê `RESELLER_MCP_ACCESS_TOKEN` e `RESELLER_MCP_URL` (a base é derivada removendo `/mcp`). O token nunca aparece no argv nem na saída.
- [ ] Expande pastas (só arquivos de imagem, sem recursão), confere localmente o tamanho e a extensão e envia um único multipart.
- [ ] Imprime o JSON da resposta. É isso que o agente usa para montar o `action_prepare`.
- [ ] Wrapper `~/.local/share/integer-reseller-mcp/upload.sh`, no mesmo padrão do `run.sh`: lê o token do Keychain e faz `exec .venv/bin/reseller-mcp-upload "$@"`. O exemplo fica documentado em `docs/client-configuration.md`.
- [ ] Testes com `respx` ou `MockTransport`, cobrindo o token ausente e a pasta com arquivos que não são imagem.

## Tarefa 5: workflow `workflow.images_publish`

**Arquivos:** `src/reseller_mcp/image_workflows.py` (novo), `src/reseller_mcp/harness.py` (registro dos hooks), `src/reseller_mcp/catalog.py` (risco, papel, perfil, palavras de busca e schema) e `tests/test_image_workflows.py`.

- [ ] Catálogo: `"workflow.images_publish": (Risk.REVERSIBLE_WRITE, Role.OPERATOR, "operator")`, buscável por "imagem publicar upload enviar subir arquivo png jpg webp e-mail assets".
- [ ] Schema de entrada:
  ```json
  {"type": "object", "additionalProperties": false,
   "required": ["dest_dir", "items"],
   "properties": {
     "dest_dir": {"type": "string", "minLength": 1},
     "items": {"type": "array", "minItems": 1, "maxItems": 20,
       "items": {"type": "object", "additionalProperties": false, "required": ["staging_id"],
         "properties": {"staging_id": {"type": "string"}, "name": {"type": "string"}}}}}}
  ```
  `dest_dir` é relativo a `public_html`, por exemplo `mail-campanha/images`. `name` é opcional e substitui o nome original, com as mesmas regras da Tarefa 2.
- [ ] `prepare`:
  - `dest_dir` normalizado, sem `..`, sem caminho absoluto, sem segmento oculto e contido em `public_html`, aproveitando as regras de `_check_fileop` em `policy.py`;
  - cada `staging_id` existe, é do usuário e não expirou;
  - não há nomes repetidos no lote (`DUPLICATE_NAME`);
  - a extensão do nome final bate com o formato do staging;
  - `api2.Fileman.listfiles` no destino: se o diretório não existir, `DESTINATION_PARENT_MISSING` (criar com `api2.Fileman.mkdir` antes); se algum nome já existir, `DESTINATION_EXISTS`, listando quais;
  - `before_state` = listagem do destino, e o impacto informa nomes, tamanhos e URLs públicas previstas.
- [ ] URL pública prevista: o domínio principal vem de `domains_data` e o docroot de `public_html`. Se o destino ficar sob o docroot de um subdomínio ou addon, usa esse domínio. Se não houver mapeamento, a ação continua sem URL e o verificador usa só a listagem.
- [ ] `execute`:
  - antes de enviar, lista o destino de novo e aborta se algum arquivo tiver aparecido entre o prepare e o execute;
  - chama `CPanelClient.upload_files` com o lote inteiro;
  - verifica cada arquivo por listagem (presente, com o tamanho igual ao do staging) e, quando há URL, por GET com HTTP 200 e SHA-256 igual ao do staging;
  - `verified` só é verdadeiro com todos os itens conferidos;
  - em caso de sucesso, apaga os itens do staging e devolve `{"published": [{"name", "url", "sha256", "size"}], "verified", "warnings"}`.
- [ ] Falha parcial: os arquivos que subiram são reportados como publicados e o resto como falha, sem rollback automático. A limpeza fica com o `fileop trash`, com frase.
- [ ] Testes com o simulador: lote ok; destino inexistente; conflito no prepare; arquivo que surge entre o prepare e o execute; SHA divergente na URL (`verified=false` com aviso); falha parcial do cPanel; staging de outro usuário; `dest_dir` com `..`.

## Tarefa 6: documentação

- [ ] `docs/api-contracts.md`: a rota `/staging/images`, o workflow e os códigos de erro novos (`UPLOAD_SESSION_DENIED`, `UPLOAD_FAILED`, `IMAGE_*`, `STAGING_NOT_FOUND`, `BATCH_TOO_LARGE` e `DUPLICATE_NAME`).
- [ ] `docs/client-configuration.md`: instalar e usar o `upload.sh`, com o fluxo completo de um exemplo do m-dias.
- [ ] `INSTRUCTIONS` em `server.py`: uma linha dizendo que imagens se publicam com `reseller-mcp-upload` e depois `workflow.images_publish`, e que nunca se manda o binário em argumento.

## Tarefa 7: deploy e canário ao vivo

- [ ] PR, CI verde, merge e aprovação do environment `production`, tudo pelo Kleber.
- [ ] Canário na conta `promocaosaborque`:
  1. `api2.Fileman.mkdir` de `public_html/mcptest-images`.
  2. `reseller-mcp-upload` com `mcptest-a.png`, `mcptest-b.jpg`, `mcptest-c.webp`, `mcptest-d.gif` e `mcptest-e.avif`, geradas na hora.
  3. `workflow.images_publish` com o lote, conferindo `verified=true`, HTTP 200 e SHA-256 pelo `curl` local.
  4. Repetir o mesmo lote e confirmar que o prepare recusa com `DESTINATION_EXISTS`.
  5. `fileop trash` de `public_html/mcptest-images`, com a frase autorizada pelo Kleber, e confirmar 404 nas URLs.
- [ ] Primeiro uso real: as imagens da próxima peça do m-dias em `public_html/mail-campanha/images`.
- [ ] Atualizar o Mem0 com o estado entregue e substituir a memória `c1567451` (m-dias), que hoje diz que o upload é manual.

## Fora do escopo

- SVG, reencode, redimensionamento e geração de 2x.
- Sobrescrita e remoção dentro do workflow.
- Upload de outros tipos de arquivo (código continua chegando por Git).
- Contas sem token `operator` com `create-user-session`: o prepare falha com `UPLOAD_SESSION_DENIED`, e a correção é de ACL, não de código.
