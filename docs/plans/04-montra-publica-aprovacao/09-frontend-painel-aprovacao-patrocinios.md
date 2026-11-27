# 09 — Frontend: painel, ecrã de aprovação de patrocínios do `sponsor_admin` (épico: 04-montra-publica-aprovacao)

**Agente:** frontend-ui · **Modelo:** opus (decisão com efeito na comissão; anti-IDOR) · **Depende de:** 06, 07, 08; cartão 20 do épico 03 · **Paralelo com:** 10–12 (pastas diferentes) · **Auditoria:** security-auditor obrigatório · **Prova:** ux-reviewer em browser real, obrigatória

## Objetivo
O `sponsor_admin` vê os pedidos e as lojas patrocinadas da sua entidade e aprova, rejeita ou revoga, com confirmação clara e sem pop-ups nativos.

## Pode alterar
- `frontend-web/src/app/painel/patrocinios/**` (criar: página, Server Actions, componentes, CSS modules, ficheiro único de strings, testes vitest); `src/lib/api/schema.d.ts` (só por `npm run gen:api`, depois do 06); `e2e/painel-patrocinios.spec.ts` (criar)

## Não tocar
- `backend-rust/`, `openapi.json` (se faltar um campo, PARAR e reportar); `src/lib/api/{server,client,staff}.ts`; `src/proxy.ts`; o resto de `src/app/painel/` (só leitura); `src/components/ui/` (usar Modal e Toast). Nunca ler `.env`.

## Contexto exato (cartões 06 e 20; spec 14 §2 e §7)
```
GET /api/v1/sponsors/mine → [{"id","kind","name","slug","logo_key","has_channel"}] (entidades do utilizador). 0 → estado vazio "Sem entidades atribuídas"; 1 → direta; ≥ 2 → seletor (rádios/abas) com nome e tipo. O entity_id usado nas chamadas vem SEMPRE desta lista: um ?entidade=<id> no URL que não esteja nela → notFound(), sem chamar a API com ele.
GET /api/v1/sponsors/{entity_id}/sponsorships?status=&cursor=&limit= → [{"id","status","valid_from","valid_to","store":{"id","name","slug","legal_name","nif","storefront_dicofre"},"requested_at","decided_at"}] (cursor opaco; limit ≤ 100; usar 25)
POST …/sponsorships/{id}/approve {"valid_from"?, "valid_to"?} → 200 {"id","status":"active","valid_from","valid_to"} · 422 'not_eligible'
POST …/sponsorships/{id}/reject {"reason": 1..500} · POST …/sponsorships/{id}/revoke {"reason": 1..500}
  404 = não existe ou é de outra entidade · 409 = já decidido ou período ativo sobreposto · 401 → /painel/entrar · 403 → /painel/2fa. Todas as mutações com X-CSRF-Token (helper do cartão 07).
Estados: pending → active | rejected; active → revoked | expired. Abas por estado: "Pendentes" (por defeito), "Ativos", "Histórico" (rejected, revoked, expired). "Carregar mais" = ligação com ?cursor= (funciona sem JS).
Cada linha: nome da loja, designação legal, NIF, código DICOFRE da montra, data do pedido, estado em texto + ícone (nunca só cor), vigência. Em 375 px a tabela passa a cartões; em desktop, <table> com <caption> e <th scope>.
Só se mostra o que vem no contrato: NUNCA pedir nem inventar IBAN, email, telefone, comissões ou dados de compradores (RGPD, minimização; spec 14 §7).
Aprovar: Modal (<dialog> do design system) com o nome da loja, datas opcionais "Início" e "Fim" (type="date", Europe/Lisbon; vazio = agora / sem fim; fim > início validado antes de enviar) e o texto: "A loja passa a mostrar o selo da entidade e a beneficiar das condições de patrocínio."
Rejeitar / Revogar: Modal com motivo obrigatório (textarea 1..500, contador ligado por aria-describedby). Revogar avisa: "Efeito imediato: a loja perde o selo desta entidade e deixa de constar no domínio da entidade, se for o único patrocínio." Botão destrutivo com texto explícito ("Revogar patrocínio"), nunca "OK".
Sem atualização otimista: esperar a resposta, mostrar Toast de sucesso (role="status") e recarregar a lista do servidor. Botão com aria-busy e desligado durante o envio (sem duplo envio). Erros no próprio Modal em role="alert": 409 → "Este pedido já foi decidido ou existe um período ativo sobreposto." (e recarregar); 422 → "A morada da loja está fora da área da entidade."; 404 → "Pedido não encontrado."
Datas e horas: Intl.DateTimeFormat('pt-PT', timeZone Europe/Lisbon). Textos num só ficheiro de strings (a redação final é do owner).
UI: nunca alert()/confirm()/prompt(); só tokens; alvos ≥ 24×24 px; foco preso no Modal e devolvido ao botão de origem; Esc fecha; reflow a 320 px; claro e escuro.
```

## Feito quando
- [ ] Vitest (respostas simuladas): seletor com 2 entidades; `?entidade` fora da lista → 404 sem chamada à API; motivo vazio ou com 501 caracteres não envia; fim ≤ início não envia; 409/422/404 mostram a mensagem certa; nada otimista
- [ ] **Co-patrocínio:** a mesma loja aparece uma vez em cada entidade; revogar numa não altera a linha na outra
- [ ] Aprovar, rejeitar e revogar funcionam sem JavaScript (formulário + Server Action, com página de confirmação em vez do Modal); `e2e/painel-patrocinios.spec.ts` com axe sem violações AA
- [ ] Prova `ux-reviewer`: Chromium + WebKit, 375 e 1440 px, claro e escuro, aprovar + rejeitar + revogar reais contra a API de dev, só teclado, uma captura por estado

## Prova (um comando)
`cd frontend-web && npm run verify` → esperado: tudo verde

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Login, 2FA e ativação — `npx playwright test e2e/painel-login.spec.ts e2e/painel-totp.spec.ts`; `npm run check:api` depois do `gen:api`
