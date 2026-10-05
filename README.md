# AegisAI Security — v0.2

Plataforma defensiva para testar aplicações com IA por API. A v0.2 adiciona autenticação local, presets de provedores, perfis de capacidade (Chat/RAG/Agent/MCP), novos probes não destrutivos, reteste, comparação com baseline anterior e exportação JSON/SARIF.

> Use somente em sistemas que você possui ou tem autorização explícita para testar.

## O que a v0.2 testa

- Prompt injection direta com canário sintético.
- Indirect prompt injection/RAG com conteúdo explicitamente marcado como não confiável.
- Possível vazamento de system/developer instructions.
- Exposição de padrões de secrets e possível PII durante probes de extração.
- Comportamento de excessive agency e alegações de ações privilegiadas sem aprovação.
- Boundary tests para agentes e MCP/tool metadata sem executar ferramentas reais.
- Regressão: compara achados novos/resolvidos com o scan anterior do mesmo target.

Os probes embutidos não tentam executar shell, modificar dados, persistir payloads, burlar autenticação ou explorar o host.

## Rodar a demo

Requer Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./run_demo.sh
```

Abra `http://127.0.0.1:8000`.

Credenciais da demo:

```text
usuário: admin
senha: aegis-demo
```

O laboratório vulnerável fica em:

```text
http://127.0.0.1:8010/vulnerable/chat
```

Cadastre com:

```json
{
  "message": "{{PROMPT}}"
}
```

Response path: `response`.

Marque Chat + RAG + Agent + MCP para ver a suíte ampliada. Para comparar com um alvo que recusa os testes, use `http://127.0.0.1:8010/secure/chat`.

## Produção/local privado

Copie `.env.example` para `.env` e troque obrigatoriamente `ADMIN_PASSWORD` e `APP_SECRET`. Mantenha `ALLOW_PRIVATE_TARGETS=false` quando não estiver testando um laboratório privado autorizado.

## Presets de API

O painel oferece presets para:

- Generic HTTP API
- OpenAI-compatible
- Anthropic Messages API
- Google Gemini
- Azure OpenAI
- Ollama

As credenciais devem ser informadas **somente nos headers efêmeros do scan**. O Aegis não persiste esses headers. Não coloque API keys na URL ou no request template salvo.

Exemplos de headers efêmeros:

```json
{"Authorization":"Bearer SUA_CHAVE"}
```

```json
{"x-api-key":"SUA_CHAVE","anthropic-version":"2023-06-01"}
```

```json
{"x-goog-api-key":"SUA_CHAVE"}
```

## API

- `POST /api/login`
- `GET /api/provider-presets`
- `POST /api/targets`
- `GET /api/targets`
- `POST /api/scans`
- `POST /api/scans/{id}/retest`
- `GET /api/scans`
- `GET /api/scans/{id}`
- `GET /api/scans/{id}/report.json`
- `GET /api/scans/{id}/report.sarif`
- Swagger: `/docs`

## GitHub / CI

A v0.2 inclui `.github/workflows/ci.yml`, executando `pytest` em pushes e pull requests.

## Limitações atuais

- Scans ainda são executados no processo web; fila Redis/Celery fica para a próxima etapa.
- Os testes RAG/Agent/MCP avaliam comportamento observável pela API; ainda não fazem instrumentação interna de vector DB, tool gateway ou servidor MCP.
- O login atual é single-admin e usa token assinado; organizações/tenants e RBAC ficam para a próxima etapa.
- Integração nativa com Promptfoo/garak ainda não está embutida.

## Próximos passos

- PostgreSQL + Alembic e organizações/tenants.
- Worker assíncrono Redis/Celery.
- Test harness para tool calls reais com allowlist e sandbox.
- Scanner de MCP manifest/tools e políticas de escopo.
- RAG test datasets e isolamento multi-tenant.
- Integração Promptfoo/garak.
- GitHub SARIF upload/code scanning.
- PDF executivo e dashboards de tendências.

## Docker Compose

```bash
docker compose up --build
```

Abra `http://127.0.0.1:8000` e use `admin / aegis-demo`. Como o scanner roda dentro do container, para o laboratório do Compose cadastre o target:

```text
http://mock-ai:8010/vulnerable/chat
```

Em instalação real, altere as credenciais e o `APP_SECRET` do Compose antes de expor o serviço.
