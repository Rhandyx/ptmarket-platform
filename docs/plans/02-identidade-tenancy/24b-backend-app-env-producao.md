# 24b — API Rust: `APP_ENV` obrigatório e recusa de configurações de dev em produção (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** sonnet · **Depende de:** 17 (mexe no `config.rs`) · **Paralelo com:** 18 só se o 18 não tocar em `config.rs`

> Dívida das auditorias de 11/11b: com `TRUSTED_PROXY_CIDRS` vazio em produção, o travão de Hosts e o rate limit contam toda a gente atrás da Cloudflare/Next como um só IP.

## Objetivo
A API só arranca com `APP_ENV` explícito. Em `production` e `staging` exige o que em dev é opcional.

## Pode alterar
- `backend-rust/src/config.rs` (+ testes no próprio módulo), `backend-rust/src/main.rs` (só a mensagem de arranque), `backend-rust/.env.example`; nos testes de integração, só o helper que constrói o `Config` (definir `APP_ENV=test`)

## Não tocar
- `src/identity/`, `src/audit/`, `src/tenancy/`, `src/http/` (exceto o que o compilador obrigar por causa do novo campo); `migrations/`. Nunca ler `.env`.

## Contexto exato
```
APP_ENV ∈ {development, test, staging, production} (exato). Ausente/outro → ConfigError::Missing/Invalid("APP_ENV", "development | test | staging | production").
Config ganha `app_env: AppEnv` (enum) com `is_strict()` (staging | production).
Em strict, erro de arranque (ConfigError::Invalid com a razão, sem valores) quando:
  - TRUSTED_PROXY_CIDRS vazio/ausente;
  - INTERNAL_PROXY_TOKEN ausente (o SSR do Next precisa dele para reenviar o Host e o IP reais);
  - CSRF_KEY ausente;
  - PLATFORM_ADMIN_HOST ausente;
  - BIND_ADDR em 0.0.0.0/[::] SEM TRUSTED_PROXY_CIDRS (redundante com a 1.ª regra; não duplicar o teste).
Em development/test tudo fica como hoje.
.env.example: APP_ENV=development, com um comentário que explica as regras de produção.
```

## Feito quando
- [ ] Testes em `config.rs`: sem APP_ENV → erro legível; `production` sem cada uma das 4 variáveis → erro que nomeia a variável; `production` completo → ok; `development` mínimo (o OK atual + APP_ENV) → ok
- [ ] Nenhum valor de segredo aparece nas mensagens (teste: o erro não contém o valor do CSRF_KEY nem das URLs)

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api` → esperado: 0 falhas (todos os testes, porque o `Config` é partilhado)
