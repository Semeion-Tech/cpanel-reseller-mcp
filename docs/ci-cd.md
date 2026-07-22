# CI/CD com GitHub Actions

## Pipeline

O workflow [`.github/workflows/ci-cd.yml`](../.github/workflows/ci-cd.yml) possui quatro gates:

1. `Quality, tests and security`: Python 3.12, dependências congeladas, Ruff, Mypy estrito,
   Pytest, Actionlint, ShellCheck, `pip-audit` e Trivy para vulnerabilidades, segredos e
   configuração insegura.
2. `Container build`: build AMD64 sem permissões de escrita para validar o container em todos os
   eventos, inclusive pull requests públicos.
3. `Publish signed container`: job privilegiado que existe somente para push em `main` e publica a
   imagem multi-arquitetura AMD64/ARM64 no GHCR. A tag de deploy é imutável (`sha-<commit>`);
   `main` é apenas uma conveniência. A imagem usa o mesmo `uv.lock` congelado auditado no gate
   anterior, a imagem-base Python está fixada por digest e o artefato inclui SBOM, proveniência e
   uma atestação assinada pelo GitHub.
4. `Deploy production`: ambiente GitHub `production`, runner dedicado na VPS, backup online do
   SQLite, lock de concorrência, pull da imagem, health check interno e externo e rollback.

Pull requests, pushes em `main`, execução manual e a varredura semanal de segunda-feira acionam
CI. Somente `push` em `main` pode publicar imagem e implantar produção. Execuções concorrentes de
produção nunca cancelam umas às outras.

As Actions externas estão fixadas por SHA completo. O Dependabot monitora `uv`, Docker e as
próprias GitHub Actions semanalmente.

## Configuração obrigatória no GitHub

Crie o environment `production` em **Settings → Environments**:

- limite o deployment à branch `main`;
- não armazene tokens cPanel, `.env` ou o banco no GitHub.

No plano GitHub Free, o repositório público permite required reviewers, wait timer e restrição do
environment à branch protegida. O deploy não precisa de secrets permanentes: usa somente o
`GITHUB_TOKEN` efêmero para ler a imagem do GHCR.

Configure proteção de `main` exigindo pull request e os checks:

- `Quality, tests and security`;
- `Container build`.

Em **Settings → Actions → General**, mantenha o `GITHUB_TOKEN` com permissões mínimas. O workflow
eleva `packages: write` somente no job que publica no GHCR e usa `packages: read` no deploy. Esse
token temporário também autentica a VPS no GHCR e é removido ao final.

## Runner dedicado

O SSH real da VPS está disponível apenas pelo Tailscale; a porta pública `2222` responde pelo nginx
e não pode ser usada por runners hospedados no GitHub. Por isso, somente o job de produção usa um
self-hosted runner dedicado, rotulado `cpanel-reseller-production`.

O serviço roda como `semeion-tech`, dono do diretório
`/home/semeion-tech/cpanel-reseller-mcp` e membro do grupo `docker`. O pipeline não usa `sudo`.
Outros usuários administrativos não recebem jobs deste repositório.

O runner recebe apenas jobs que exigem simultaneamente os labels:

- `self-hosted`;
- `Linux`;
- `ARM64`;
- `cpanel-reseller-production`.

Jobs de pull request, testes, scanners e builds continuam exclusivamente em runners hospedados no
GitHub. Código de PR não é executado no host de produção.

## Produção e dados persistentes

O checkout efêmero do runner fornece `compose.yaml` e `deploy/remote_deploy.sh`; o script altera
somente o Compose do diretório de produção. Permanecem intocados:

- `.env` com modo `600`;
- volume `reseller_mcp_data` e sua auditoria SQLite;
- catálogo montado em `data/`;
- tokens em `secrets/`.

Antes de trocar o container, o script cria um backup SQLite consistente em
`/app/data/pre-deploy.db`, salva o Compose anterior e marca a imagem corrente como `:rollback`.

## Rollback

Falha de pull, inicialização, health check Docker ou `https://mcp-reseller.semeiontech.com/healthz`
restaura automaticamente o Compose e a imagem anteriores.

Para rollback manual:

```bash
ssh semeion
cd /home/semeion-tech/cpanel-reseller-mcp
export RESELLER_MCP_IMAGE="$(cat .deploy/previous-image)"
docker compose up -d --no-build --force-recreate reseller-mcp
docker compose ps
curl -fsS https://mcp-reseller.semeiontech.com/healthz
```

O backup SQLite não é restaurado automaticamente: as migrações do serviço são aditivas e restaurar
o banco poderia apagar auditoria produzida depois do deploy. Use `pre-deploy.db` apenas após análise
explícita do incidente.

## Crons operacionais

A seguinte tarefa deve ser executada periodicamente (recomendado: a cada 5 minutos) via crontab no
host de produção:

```cron
*/5 * * * * reseller-mcp-admin reap-mysql-grants >> /var/log/reseller-mcp/reap.log 2>&1
```

Essa tarefa revoga usuários MySQL efêmeros e entradas de host cuja TTL expirou, limpando grants
órfãos que não foram imediatamente revogados durante o encerramento de sessão (rede instável ou
falha de serviço cPanel). É um mecanismo de segurança que evita manter credenciais temporárias ativas
além do esperado.

## Primeira ativação

Antes do primeiro merge em `main`:

1. confirme que o runner `semeion-cpanel-reseller` está online;
2. confirme que Actions pode publicar packages no GHCR;
3. proteja `main` com os checks obrigatórios quando o plano do GitHub permitir;
4. execute o primeiro workflow manualmente para validar CI, sem deploy;
5. faça o primeiro push em `main` acompanhado e confirme o rollback tag na VPS.
