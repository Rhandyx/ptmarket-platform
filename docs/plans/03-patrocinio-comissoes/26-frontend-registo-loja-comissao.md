# 26 — Frontend: registo da loja, âncora da comissão, selos, aviso e escolha do plano (épico: 03-patrocinio-comissoes)

**Agente:** frontend-ui · **Modelo:** sonnet · **Depende de:** 17, 18 (`openapi.json` com geo, elegíveis e preview) · **Paralelo com:** 19–25 (não toca em Rust, Go nem BD) · **Prova:** ux-reviewer em browser real, obrigatória

## Objetivo
O futuro lojista escolhe a freguesia da loja, vê a comissão normal e, se houver patrocinadores, `8% → 0%` com os selos e o aviso, e escolhe o plano. O envio do registo fica desligado (ver "Não tocar").

## Pode alterar
- `frontend-web/src/app/registar-loja/**` (criar: página, CSS module, componentes `CommissionAnchor`, `SponsorBadges`, `PlanPicker`, `ParishPicker`, testes vitest); `frontend-web/src/lib/api/**` (cliente tipado gerado por `npm run gen:api`); `frontend-web/src/styles/tokens.css` (só tokens novos, se faltarem)

## Não tocar
- `backend-rust/`, `openapi.json` (contrato: se faltar um campo, PARAR e reportar); `src/app/design-system/`, `layout.tsx`. O endpoint de registo da loja não existe neste épico (épico de onboarding): o botão final fica `aria-disabled` com a explicação visível "Registo disponível em breve"; não simular o envio. Nunca ler `.env`.

## Contexto exato (spec 14 §4, §6; CLAUDE.md regra 4)
```
Formulário: 1) mostra 8%; 2) com a freguesia confirmada, deteta os patrocinadores parceiros e mostra ~~8%~~ 0% com os logótipos; 3) avisa que a isenção depende de validação e que, se cessar, se aplica a comissão padrão (plano escolhido).
API (tudo inteiros; NENHUM valor hardcoded no frontend, nem o 8%):
  GET /api/v1/geo/districts · /geo/municipalities?district=DD · /geo/parishes?municipality=DDCC → [{"code","name"}]
  GET /api/v1/signup/commission-preview?dicofre=DDCCFF → {"reference_bps", "sponsored": {"applied_bps","sponsors":[{"id","kind","name","slug","logo_key"}]} | null, "plans":[{"plan_code","is_default","tiers":[{"gmv_from_cents","gmv_to_cents","monthly_fee_cents","marginal_commission_bps"}]}]}
Dinheiro: sem floats e sem contas no frontend: só formatar. bps → percentagem com divisão inteira e resto (800 → "8%", 650 → "6,5%"); cêntimos → euros com Intl.NumberFormat('pt-PT', currency EUR) a partir de inteiros. Sem código postal neste épico: 3 seletores encadeados distrito → concelho → freguesia.
Âncora: <p>Comissão: <del>8%</del> <ins>0%</ins></p>, com texto só para leitores de ecrã ("Comissão normal 8%. Com patrocínio: 0%."), porque <del>/<ins> nem sempre são anunciados; o 0% não pode depender só da cor. Sem patrocinadores: mostra só "8%", sem <del>.
Selos: logótipo + nome + tipo (Câmara Municipal / Junta de Freguesia / Associação), pela ordem que a API devolve (municipality → parish → association); alt = nome da entidade; sem logo_key → só texto. Com 2 ou mais (co-patrocínio) mostram-se todos e o 0% aparece UMA vez.
Aviso (texto visível junto à âncora, não em tooltip): "A isenção depende da validação pela entidade patrocinadora. Até à aprovação, e se o patrocínio terminar, aplica-se a comissão do plano que escolher." A redação final dos Termos está pendente do owner: manter o texto num só ficheiro de strings.
Planos: grupo de rádio (fieldset + legend), 'commission_payg' pré-selecionado (is_default); cada plano mostra os escalões numa <table> com <caption> e <th scope>: volume mensal, mensalidade, comissão "só sobre o excedente". Valores sem IVA: dizê-lo ("Aos valores acresce IVA à taxa legal").
UI: nunca alert()/confirm()/prompt(); sem pop-ups; estados de carregamento e de erro no próprio sítio (role="status"/"alert"); WCAG 2.2 AA: foco visível, alvos ≥ 24×24 px, contraste AA, navegação completa por teclado, labels ligadas, erros associados por aria-describedby, reflow a 320 px, respeitar prefers-reduced-motion. Só tokens de `tokens.css`. Layout próprio (Amazon/AliExpress são anti-referência).
```

## Feito quando
- [ ] Sem freguesia: só "8%" (vindo da API); com freguesia sem patrocinadores: igual; com patrocinadores: `<del>8%</del> <ins>0%</ins>` + selos + aviso; mudar a freguesia atualiza tudo sem recarregar
- [ ] **Co-patrocínio:** freguesia com Câmara + Junta mostra os 2 selos pela ordem certa e um só "0%" (teste vitest com a resposta simulada)
- [ ] Testes vitest: formatação de bps e cêntimos (sem floats), tabela dos 2 planos a partir da resposta, erro da API mostrado em `role="alert"`, botão final desligado com explicação
- [ ] Prova `ux-reviewer` em browser real (Chromium + WebKit, 320 px e desktop, só teclado, leitor de ecrã anuncia a âncora completa, axe sem violações AA), com capturas anexas ao relatório

## Prova (um comando)
`cd frontend-web && npm run verify` → esperado: tudo verde (check:api, typecheck, lint, test, build)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Página inicial e design system — incluídos no `npm run verify`; o `ux-reviewer` confirma que `/` e `/design-system` não mudaram
