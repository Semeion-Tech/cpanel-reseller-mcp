# ADR-001 — Harness modular e memória opcional

- Status: proposta aceita para evolução incremental
- Data: 2026-07-21
- Escopo: arquitetura interna do `cpanel-reseller-mcp`

## Contexto

O servidor é um plano de controle determinístico sobre WHM/UAPI. Ele precisa ser previsível em
RBAC, escopo de conta, validação, confirmação e auditoria. As primeiras consultas mostraram valor
em workflows compostos, mas não demonstraram necessidade de um agente autônomo dentro do servidor.

A estrutura considerada foi:

```text
agents/
workflows/
providers/
prompts/
tools/
memory/
guardrails/
observability/
config/
```

## Decisão

Manter um monólito modular e adotar as fronteiras conforme existir mais de uma implementação ou
responsabilidade concreta:

```text
src/reseller_mcp/
├── workflows/       # dossiê, health check e futuras jornadas determinísticas
├── providers/       # cPanel e, futuramente, adaptador opcional de memória
├── tools/           # contratos MCP finos, sem regra de negócio
├── guardrails/      # RBAC, escopo, risco, validação e confirmação
├── observability/   # métricas sanitizadas e auditoria
└── config/          # settings e composição
```

Os módulos atuais não serão movidos apenas para reproduzir a árvore. A migração acontecerá quando
um domínio ganhar volume suficiente para justificar um pacote, preservando imports e contratos.

`agents/` não será introduzido no núcleo nesta fase. Se surgir planejamento não determinístico ou
coordenação entre especialistas, a camada de agentes ficará acima dos workflows e dependerá deles,
nunca contornará guardrails. `prompts/` será criado somente quando o MCP publicar prompts ou quando
um agente real existir; decisões de segurança não podem depender de texto de prompt.

## Memória e Mem0

Mem0 pode ser implementado atrás de uma interface opcional, desabilitada por padrão. Conteúdo
permitido:

- preferências duráveis do usuário;
- aliases de conta explicitamente confirmados;
- convenções operacionais e decisões arquiteturais estáveis.

Conteúdo proibido:

- tokens, senhas, chaves privadas ou qualquer segredo;
- payloads brutos, logs e dossiês completos;
- estado atual de conta, quota, backup, DNS ou disponibilidade;
- auditoria, aprovações, idempotência ou qualquer dado usado para autorização.

WHM/UAPI continua sendo a fonte de verdade operacional. SQLite continua sendo a fonte de auditoria
e estado transacional. Uma falha do Mem0 não pode impedir consultas, alterar políticas ou converter
uma negação em permissão. Leituras de memória devem indicar proveniência e nunca ser tratadas como
evidência atual sem nova consulta ao cPanel.

As configurações `MEMORY_PROVIDER`, `MEM0_ENDPOINT` e `MEM0_USER_ID` já reservam o contrato, mas
nenhuma chamada de memória ocorre enquanto `MEMORY_PROVIDER=none`.

## Consequências

### Positivas

- O servidor permanece simples, testável e determinístico.
- Workflows podem crescer sem duplicar resolução de conta, normalização e auditoria.
- Memória não entra no caminho crítico nem amplia o domínio de confiança.
- Uma futura camada de agentes reaproveita ferramentas seguras em vez de reimplementar controles.

### Custos e riscos

- A árvore alvo aparecerá gradualmente, não em uma reorganização imediata.
- Um adaptador Mem0 exigirá política de retenção, exclusão, consentimento e testes de isolamento.
- Promover memória para fonte de verdade criaria risco de dados obsoletos e decisões incorretas;
  isso fica explicitamente vedado.

## Gatilhos para reavaliar

Reavaliar `agents/` quando houver pelo menos um fluxo que exija planejamento entre múltiplos passos
não conhecido em tempo de desenvolvimento. Reavaliar Mem0 quando houver casos de uso aprovados,
modelo de ameaça, contrato de exclusão e owner operacional definidos.
