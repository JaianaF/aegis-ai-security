# AegisAI Security — v0.3

Plataforma defensiva para testar aplicações com IA por API, com foco em chatbots, RAG, agentes e MCP.

> Use somente em sistemas que você possui ou tem autorização explícita para testar.

## Destaques da v0.3

- Organizações e projetos para separar avaliações por workspace.
- Targets vinculados a projetos.
- Fila de scans no banco e worker separado.
- Headers do scan criptografados temporariamente e removidos ao final da execução.
- Recuperação de jobs travados/stale.
- Auditoria estática de manifests/tools MCP sem executar ferramentas.
- Detecção opcional de Promptfoo e garak instalados no ambiente.
- Audit trail de ações administrativas e scans.
- Retest e comparação de regressão.
- Exportação JSON e SARIF 2.1.0.
- Docker Compose com API, worker e laboratório vulnerável.
- CI com instalação do pacote, compile smoke test e pytest.

## Probes defensivos

A suíte integrada inclui testes não destrutivos para:

- prompt injection direta com canários sintéticos;
- indirect prompt injection em conteúdo RAG explicitamente não confiável;
- possível exposição de system/developer instructions;
- padrões de secrets e possível PII durante probes de extração;
- excessive agency e alegações de ações privilegiadas;
- boundaries de agentes;
- influência de metadata/tools MCP.

Os probes embutidos não tentam executar shell, modificar dados, persistir payloads, burlar autenticação ou explorar o host.

## Rodar localmente

Requer Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .

python -m pytest -q

bash run_demo.sh
```

Se as portas padrão estiverem ocupadas:

```bash
DASHBOARD_PORT=8001 MOCK_PORT=8011 bash run_demo.sh
```

Abra o dashboard informado no terminal.

Credenciais da demo:

```text
usuário: admin
senha: aegis-demo
```

O laboratório vulnerável padrão fica em:

```text
http://127.0.0.1:8010/vulnerable/chat
```

Request template:

```json
{
  "message": "{{PROMPT}}"
}
```

Response path:

```text
response
```

Para a suíte ampliada, habilite Chat + RAG + Agent + MCP.

## Fluxo assíncrono

Ao iniciar um scan, a API retorna `202` e cria um job em estado `queued`.

O worker executa:

```text
queued -> running -> completed
```

ou:

```text
queued -> running -> failed
```

Os headers enviados para autenticar a API alvo são criptografados no payload temporário do job e apagados depois da execução.

## MCP Audit

O endpoint `POST /api/mcp/audit` faz análise estática do manifest fornecido e procura sinais como:

- ferramentas associadas a shell/exec/admin/delete/SQL;
- schemas com `additionalProperties=true`;
- argumentos sensíveis como command, shell, path, URL, query, SQL, token, password, secret e key;
- ferramentas sem descrição de escopo.

Ele não invoca as ferramentas analisadas.

## Integrações

`GET /api/integrations` informa a disponibilidade de:

- Aegis built-in engine;
- Promptfoo;
- garak.

Promptfoo e garak são opcionais nesta versão. A v0.3 detecta sua presença no PATH, mas não os executa automaticamente.

## Principais endpoints

- `POST /api/login`
- `GET/POST /api/organizations`
- `GET/POST /api/projects`
- `GET/POST /api/targets`
- `POST /api/scans`
- `POST /api/scans/{id}/retest`
- `GET /api/scans`
- `GET /api/scans/{id}`
- `GET /api/scans/{id}/report.json`
- `GET /api/scans/{id}/report.sarif`
- `POST /api/mcp/audit`
- `GET /api/integrations`
- `GET /api/audit-events`
- Swagger: `/docs`

## Docker Compose

```bash
docker compose up --build
```

O Compose inicia:

- `aegis`: dashboard/API;
- `worker`: executor assíncrono;
- `mock-ai`: laboratório local vulnerável.

API e worker compartilham o mesmo volume SQLite da demo.

Dentro do container, cadastre o laboratório usando:

```text
http://mock-ai:8010/vulnerable/chat
```

## Segurança

- Targets privados/localhost são bloqueados por padrão e só ficam disponíveis quando `ALLOW_PRIVATE_TARGETS=true` é habilitado explicitamente para um laboratório autorizado.
- Redirects não são seguidos.
- Secrets e PII detectados são redigidos das evidências.
- Credenciais de APIs alvo não devem ser colocadas na URL ou request template persistente.
- Altere `ADMIN_PASSWORD` e `APP_SECRET` antes de expor a aplicação fora da máquina local.

## Limitações atuais

- Autenticação ainda é single-admin; RBAC e usuários por organização ficam para uma versão posterior.
- SQLite é o padrão da demo; a camada SQLAlchemy já aceita outro `DATABASE_URL`, mas migrações Alembic/PostgreSQL completas ainda não estão fechadas.
- Promptfoo/garak são detectados, mas ainda não fazem parte da fila de execução.
- Auditoria MCP atual é estática; ainda não inspeciona um servidor MCP remoto nem executa tools.
- Testes RAG/Agent/MCP observam o comportamento exposto pela API e não instrumentam internamente vector DBs ou tool gateways.

## Próximos passos

- PostgreSQL + Alembic.
- RBAC e usuários por organização.
- Executor Promptfoo/garak isolado.
- Scanner de servidor MCP com allowlist e sandbox.
- Test datasets para isolamento RAG multi-tenant.
- Upload automatizado de SARIF para GitHub Code Scanning.
- Dashboard de tendências e relatório executivo.
