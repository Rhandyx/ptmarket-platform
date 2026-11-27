# 08 — Frontend: painel, ativação do 2FA (TOTP) e códigos de recuperação (épico: 04-montra-publica-aprovacao)

**Agente:** frontend-ui · **Modelo:** opus (autenticação) · **Depende de:** 07 · **Paralelo com:** 01–06, 10–12 (pastas diferentes) · **Auditoria:** security-auditor obrigatório · **Prova:** ux-reviewer em browser real, obrigatória

## Objetivo
Um `sponsor_admin` novo, que ainda não tem 2FA, ativa-o no primeiro acesso e guarda os códigos de recuperação. Sem isto não consegue chegar ao ecrã de aprovação.

## Pode alterar
- `frontend-web/src/app/painel/2fa/ativar/**` (criar: página, Server Actions, CSS module, testes vitest); `e2e/painel-totp.spec.ts` (criar)

## Não tocar
- `backend-rust/`, `openapi.json`, `src/lib/api/**` (usar `staff.ts` do cartão 07 sem o alterar; se faltar algo, PARAR e reportar); `src/proxy.ts`; o resto de `src/app/painel/` (só leitura); `src/components/ui/`. Sem dependências novas (ver "QR"). Nunca ler `.env`.

## Contexto exato (contrato já no `openapi.json`; spec 12 §3)
```
Entrada: sessão de staff ainda sem 2FA (o cartão 07 redireciona para aqui quando /staff/mfa/verify devolve 409). Sem sessão → /painel/entrar. Se o TOTP já estiver ativo (409 no enroll) → /painel/2fa.
POST /api/v1/staff/mfa/totp/enroll (X-CSRF-Token, sem corpo) → 200 {"otpauth_uri","secret_base32"} — mostrado SÓ agora · 409 já ativo
POST /api/v1/staff/mfa/totp/confirm {"code"} (X-CSRF-Token) → 200 {"recovery_codes":[10 strings]} + Set-Cookie (sessão nova, já com 2FA) — mostrados SÓ agora · 401 código errado · 409 · 429 com Retry-After
Passo 1 (um ecrã): explicação curta; o segredo em grupos de 4 caracteres dentro de <code>, com botão "Copiar"; ligação "Abrir na aplicação de autenticação" (href = otpauth_uri, só se começar por "otpauth://"); campo do código (autocomplete="one-time-code", inputmode="numeric", 6 dígitos) e botão "Ativar".
  QR: v1 SEM código QR (gerá-lo exige uma dependência nova; decisão registada no índice). Não desenhar um QR à mão nem chamar serviços externos: o segredo nunca sai do nosso domínio.
Passo 2: lista dos 10 códigos de recuperação (<ol>, fonte monoespaçada), botões "Copiar todos" e "Descarregar .txt" (Blob local, sem rede), aviso "Só os verá esta vez. Cada código serve uma vez." e caixa "Guardei os códigos em local seguro" obrigatória antes de "Continuar" → /painel.
Segredos: o segredo, o otpauth_uri e os códigos nunca vão para URL, localStorage/sessionStorage, cookies, logs, analytics nem títulos de página; páginas sem cache; recarregar o passo 2 não volta a mostrar os códigos (mostra "Os códigos já foram apresentados" e o caminho para /painel).
Mecânica: Server Actions com o helper do cartão 07 (CSRF + cópia dos Set-Cookie). O passo 1 funciona sem JS; "Copiar" e "Descarregar" são melhorias com JS (sem JS, o texto continua selecionável).
Feedback: "Copiado" em Toast (role="status"), nunca alert(); erro de código em role="alert" ligado ao campo; 429 → "Demasiadas tentativas. Tente de novo dentro de N minutos."
UI: só tokens; rem/clamp; alvos ≥ 24×24 px; foco visível e gerido entre passos (foco no título do passo 2); reflow a 320 px; claro e escuro; prefers-reduced-motion. WCAG 3.3.8: permitir colar o código.
```

## Feito quando
- [ ] Vitest: o `otpauth_uri` só vira ligação se começar por `otpauth://`; "Continuar" fica desligado até marcar a caixa; 401 mostra erro no campo sem perder o segredo já mostrado; 409 no enroll redireciona
- [ ] Nenhum segredo em `localStorage`, `sessionStorage`, URL ou HTML em cache (teste e2e inspeciona os três); recarregar o passo 2 não repete os códigos
- [ ] Fluxo só com teclado e com leitor de ecrã (títulos de passo anunciados); `e2e/painel-totp.spec.ts` com axe sem violações AA
- [ ] Prova `ux-reviewer`: Chromium + WebKit, 375 e 1440 px, claro e escuro, ativação real com uma aplicação TOTP e login seguinte com o código, uma captura por passo (com os segredos tapados)

## Prova (um comando)
`cd frontend-web && npm run verify` → esperado: tudo verde

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Login e 2FA do cartão 07 — `npx playwright test e2e/painel-login.spec.ts`; `tests/security-headers.test.ts` sem alterações
