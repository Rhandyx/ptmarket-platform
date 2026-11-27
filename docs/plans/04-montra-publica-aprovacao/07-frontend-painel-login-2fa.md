# 07 — Frontend: painel `admin.ptmarket.pt`, esqueleto, login de staff e 2FA (épico: 04-montra-publica-aprovacao)

**Agente:** frontend-ui · **Modelo:** opus (autenticação) · **Depende de:** — (a API de staff já existe) · **Paralelo com:** 01–06 (não toca em Rust nem em BD) · **Auditoria:** security-auditor obrigatório · **Prova:** ux-reviewer em browser real, obrigatória

## Objetivo
Um utilizador de backoffice entra em `/painel/entrar` com email e palavra-passe, faz o 2FA e chega a `/painel`, que mostra as áreas do seu papel. Sai com "Terminar sessão".

## Pode alterar
- `frontend-web/src/app/painel/**` (criar: `layout.tsx`, `page.tsx`, `entrar/`, `2fa/`, Server Actions, CSS modules, testes vitest); `src/lib/platform-host.ts` e `src/lib/api/staff.ts` (criar); `src/proxy.ts` + `tests/security-headers.test.ts` (só o que o Turnstile exige, ver abaixo); `.env.example` (só nomes); `e2e/painel-login.spec.ts` (criar)

## Não tocar
- `backend-rust/`, `openapi.json`, `src/lib/api/{schema.d.ts,server.ts,client.ts}` (contrato: se faltar algo, PARAR e reportar); `src/app/{page.tsx,layout.tsx,design-system/,registar-loja/}`; `src/components/ui/` (usar, não alterar). Passkeys e ativação do TOTP ficam fora (cartão 08). Nunca ler `.env`.

## Contexto exato (spec 12 §2–§3; spec 14 §8; contrato já no `openapi.json`)
```
Só no Host da plataforma: o layout de /painel faz notFound() se o Host do pedido ≠ PLATFORM_ADMIN_HOST (variável de servidor; helper isPlatformAdminHost em src/lib/platform-host.ts). metadata robots noindex; páginas dinâmicas, sem cache.
POST /api/v1/staff/auth/login {"email" ≤255, "password" 1..128, "turnstile_token"?} → 200 {"mfa_required": bool} + Set-Cookie __Host-ptm_admin (HttpOnly, Secure, SameSite=Strict) · 401 sempre igual (o corpo pode trazer "captcha_required": true → mostrar o Turnstile e repetir com o token) · 429 com Retry-After · 503
GET /api/v1/staff/me → {"id","full_name","roles":[{"role","tenant_id","store_id","sponsor_entity_id"}],"mfa_verified"} · 401 → /painel/entrar
GET /api/v1/auth/session → {"authenticated","actor_type","csrf_token"} (token para o cabeçalho X-CSRF-Token em TODAS as mutações com sessão)
POST /api/v1/staff/mfa/verify {"code"} (TOTP de 6 dígitos ou código de recuperação) → 204 + Set-Cookie (sessão rodada) · 401 código errado/repetido · 409 TOTP não ativo → redirecionar para /painel/2fa/ativar (cartão 08; até lá, página "em breve") · 429
POST /api/v1/auth/logout (X-CSRF-Token) → limpar e voltar a /painel/entrar
Mecânica: formulários + Server Actions (funciona sem JS) sobre createServerApi(headers()). O helper src/lib/api/staff.ts: reenvia a Origin do pedido; obtém o csrf_token no servidor antes de cada mutação; copia para o browser TODOS os Set-Cookie da resposta da API, sem alterar atributos. O valor do cookie, a password, o código e o token nunca vão para logs, estado de cliente, URL ou mensagens de erro.
Redirecionamentos só para caminhos fixos (/painel, /painel/2fa, /painel/entrar): sem parâmetro "next" (evita open redirect).
Mensagens: uma só para 401 ("Email ou palavra-passe incorretos."), sem dizer se a conta existe; 429 → "Demasiadas tentativas. Tente de novo dentro de N minutos."; 503 → "Serviço indisponível. Tente de novo."
Campos: label visível; autocomplete="username" / "current-password" / "one-time-code"; inputmode="numeric" no código; colar permitido (WCAG 3.3.8: nunca bloquear gestores de passwords); erros em role="alert" ligados por aria-describedby; foco no primeiro erro.
Turnstile (só quando captcha_required): site key em NEXT_PUBLIC_TURNSTILE_SITE_KEY; script com o nonce da CSP; em proxy.ts acrescentar apenas frame-src https://challenges.cloudflare.com (e o script-src só se o nonce + strict-dynamic não bastar). Nenhuma outra diretiva muda.
/painel (depois do 2FA): saudação com full_name e um cartão por área do papel. sponsor_admin → "Patrocínios" (ligação a /painel/patrocinios, cartão 09); restantes papéis → "Em breve". Cabeçalho com "Terminar sessão" (form POST).
UI: nunca alert()/confirm()/prompt(); só tokens; rem/clamp; alvos ≥ 24×24 px; foco visível; reflow a 320 px; claro e escuro; prefers-reduced-motion.
```

## Feito quando
- [ ] Vitest: 401 mostra a mensagem única; `captcha_required` mostra o Turnstile; 409 no 2FA redireciona; o helper copia os `Set-Cookie` e envia `X-CSRF-Token` só em mutações; nenhum segredo aparece em props de componentes de cliente
- [ ] `/painel/**` num Host de canal → 404; sem sessão → `/painel/entrar`; com sessão sem 2FA → `/painel/2fa`; `tests/security-headers.test.ts` atualizado e verde (CSP continua sem `unsafe-inline`)
- [ ] Fluxo completo sem JavaScript e só com teclado; `e2e/painel-login.spec.ts` (axe sem violações AA)
- [ ] Prova `ux-reviewer`: Chromium + WebKit, 375 e 1440 px, claro e escuro, login + 2FA + logout reais com um utilizador de dev (criado pelo supervisor), uma captura por estado

## Prova (um comando)
`cd frontend-web && npm run verify` → esperado: tudo verde (check:api, typecheck, lint, test, build)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Cabeçalhos de segurança e CSP — `tests/security-headers.test.ts`; `/`, `/design-system` e `/registar-loja` sem alterações (o `ux-reviewer` confirma); `npm run test:e2e` (overlays)
