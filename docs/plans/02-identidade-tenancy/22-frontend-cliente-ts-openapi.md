# 22 — Cliente TypeScript gerado do `openapi.json` (épico: 02-identidade-tenancy)

**Agente:** frontend-ui · **Modelo:** sonnet · **Depende de:** 11 · **Paralelo com:** 13, 14

## Objetivo
O frontend fala com a API Rust só por um cliente tipado gerado do contrato; um contrato alterado sem regenerar chumba o `verify`.

## Pode alterar
- `frontend-web/src/lib/api/{schema.d.ts,client.ts,server.ts,index.ts}`, `frontend-web/src/lib/api/client.test.ts`, `frontend-web/scripts/check-api.mjs` (criar); `frontend-web/package.json`, `package-lock.json`, `eslint.config.*` (editar)

## Não tocar
- `backend-rust/` — só leitura de `backend-rust/openapi.json` (contrato; se estiver errado, parar e reportar); `frontend-web/src/components/**`, `src/app/**`, tokens e CSP — aprovados (este cartão não cria UI); `.env*`

## Contexto exato (colado da spec; não ler a spec)
```
Regra de frontend: API Rust só via cliente gerado do openapi.json; nunca tipos escritos à mão para respostas da API. Server Components por defeito. Tenant pelo cabeçalho Host. JS próprio da rota ≤ 30 KB gzip acima do runtime.
Contrato: backend-rust/openapi.json (gerado por `cargo run --bin openapi`; o frontend NÃO o gera nem o edita). Hoje tem /healthz, /readyz e GET /api/v1/tenant → {"slug","name","tenant_type","country_code","currency","template_layout","theme_config","legal_config"}.
Ferramentas (devDependency com versão fixada; justificar no PR): `openapi-typescript` gera src/lib/api/schema.d.ts; em runtime `openapi-fetch` (≈ 6 KB, sem geração de código de runtime). Sem axios, sem cliente escrito à mão.
Scripts: "gen:api": gera schema.d.ts a partir de ../backend-rust/openapi.json · "check:api": gera para um ficheiro temporário e compara; diferente → sai ≠ 0 com a mensagem "openapi.json mudou: corre npm run gen:api" · "verify" passa a começar por check:api. schema.d.ts vai para o git e fica fora do lint/format (cabeçalho "gerado, não editar").
server.ts (só servidor; `import "server-only"`): createServerApi(headers) para Server Components/Actions:
  baseUrl = API_INTERNAL_URL (variável de servidor, nunca NEXT_PUBLIC_).
  Reencaminha o tenant: X-Forwarded-Host = Host do pedido recebido + X-Internal-Token = INTERNAL_PROXY_TOKEN (segredo de servidor; a API ignora X-Forwarded-Host sem ele). Estes dois cabeçalhos NUNCA saem para o browser nem entram em código cliente.
  Reencaminha o cookie de sessão e o X-Request-Id; `cache: "no-store"` por omissão (respostas por utilizador nunca ficam em cache partilhada).
client.ts (browser): createBrowserApi() com baseUrl relativa (mesmo domínio), `credentials: "same-origin"`; em pedidos que não sejam GET/HEAD envia X-CSRF-Token (obtido de GET /api/v1/auth/session quando existir no contrato; até lá o parâmetro é opcional e tipado).
Erros: a API responde {"code": "not_found|unauthorized|forbidden|validation|conflict|internal", "message", "fields"?}. Expor ApiError tipado; nunca mostrar `message` de erros `internal`; sem alert()/confirm()/prompt().
ESLint: regra que proíbe `fetch(` para caminhos /api/ fora de src/lib/api, e a importação de server.ts em ficheiros "use client". Nenhum segredo em NEXT_PUBLIC_*; não registar corpos de resposta em consola.
```

## Feito quando
- [ ] `npm run gen:api` gera `schema.d.ts`; um teste de tipos falha a compilar se se ler um campo que não existe na resposta de `/api/v1/tenant`
- [ ] `client.test.ts` (vitest, `fetch` simulado): `createServerApi` envia `X-Forwarded-Host` + `X-Internal-Token` + cookie; `createBrowserApi` não os envia e põe `X-CSRF-Token` só em mutações; 404 vira `ApiError` com `code: "not_found"`
- [ ] Alterar à mão uma cópia do `openapi.json` no teste faz `check:api` sair ≠ 0; com o contrato atual sai 0
- [ ] `INTERNAL_PROXY_TOKEN` e `API_INTERNAL_URL` não aparecem em nenhum chunk de `.next/static` depois do build (grep no script de teste)
- [ ] Orçamento: a home continua ≤ runtime + 30 KB gzip

## Prova (um comando)
`cd frontend-web && npm run verify` → esperado: `check:api`, typecheck, lint, testes e build verdes

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Esqueleto, CSP com nonce e componentes (Modal/Toast/Popover/Drawer) — `cd frontend-web && npm run test:e2e` (axe 0 violações a 375/1440 px) · `npm audit --omit=dev` com 0 vulnerabilidades
