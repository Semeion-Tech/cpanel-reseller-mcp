# Configuração de clientes

Cada pessoa e cada cliente de IA recebe um bearer token próprio. Não reutilize um token entre
usuários, ChatGPT, Codex, Claude Desktop ou automações.

## Cliente MCP HTTP

- URL: `https://mcp-reseller.semeiontech.com/mcp`
- Transporte: Streamable HTTP
- Header: `Authorization: Bearer SEU_TOKEN`

## Codex

Guarde o token em uma variável de ambiente e registre o endpoint:

```bash
export CPANEL_RESELLER_MCP_TOKEN='rmcp_...'
codex mcp add cpanel-reseller \
  --url https://mcp-reseller.semeiontech.com/mcp \
  --bearer-token-env-var CPANEL_RESELLER_MCP_TOKEN
```

Na estação administrativa deste projeto, o token fica no Keychain do macOS e o Codex usa o
wrapper local protegido; nenhum segredo é inserido em `config.toml`.

## Clientes somente stdio

Instale o pacote Python do projeto e configure:

```json
{
  "mcpServers": {
    "cpanel-reseller": {
      "command": "reseller-mcp-bridge",
      "env": {
        "RESELLER_MCP_URL": "https://mcp-reseller.semeiontech.com/mcp",
        "RESELLER_MCP_ACCESS_TOKEN": "rmcp_..."
      }
    }
  }
}
```

Em ambientes de equipe, substitua o valor literal por um secret manager ou variável injetada pelo
runtime. O bridge usa `mcp-remote` e mantém o bearer fora dos argumentos do processo.

## Emissão e revogação

Na VPS Semeion:

```bash
cd /home/semeion-tech/cpanel-reseller-mcp
docker compose exec reseller-mcp reseller-mcp-admin users create USUARIO \
  --role operator --scope acctalpha
docker compose exec reseller-mcp reseller-mcp-admin tokens issue USUARIO CLIENTE
docker compose exec reseller-mcp reseller-mcp-admin tokens revoke KEY_ID
```

Use `viewer` para consultas, `operator` para operações reversíveis e `admin` para o catálogo
avançado e ações destrutivas. Escopos aceitam uma ou mais contas cPanel; `*` é acesso global ao
reseller e deve ficar restrito a administradores.

## Configuração do upstream cPanel/WHM (servidor)

`RESELLER_MCP_CPANEL_RESELLER` no `.env` do servidor **precisa ser o usuário reseller real da
WHM** — o valor `demo-reseller` do `.env.example` é só placeholder e resulta em `Access denied`
mesmo com token válido. O mesmo vale para `RESELLER_MCP_CPANEL_BASE_URL`, que aponta para o
endpoint WHM do servidor (`https://<seu-servidor>:2087`).

A conexão ao WHM usa três tokens próprios (`RESELLER_MCP_CPANEL_READER_TOKEN`,
`_OPERATOR_TOKEN`, `_ADMIN_TOKEN`), com ACLs crescentes:

- **reader:** `acct-summary`, `basic-system-info`, `basic-whm-functions`, `cpanel-api`,
  `list-accts`, `list-pkgs`, `mailcheck`, `mysql-info`, `show-bandwidth`, `ssl-info`.
- **operator:** ACLs do reader + `create-acct`, `create-dns`, `edit-dns`, `edit-mx`,
  `manage-dns-records`, `ssl`, `suspend-acct`.
- **admin:** herda operator, sem restrição adicional de ACL.

Autenticação direta na WHM API usa o header `Authorization: whm <reseller>:<TOKEN>`. Ao criar um
token novo via `api_token_create`, capturar e persistir o segredo imediatamente — a WHM não deixa
recuperar depois. `.env` é gitignored e deve ficar com `chmod 600`; os valores dos três tokens
nunca devem ir para memória de IA, logs ou conversa — só os nomes/labels, se precisar rastrear
qual token é qual para revogação.
