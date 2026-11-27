# 00 — Índice do épico 03: Patrocínio, Comissões, Planos e DICOFRE

Fonte canónica: spec 14 (decisão do owner de 26/11/2026). Cada executor lê **só o seu cartão**. Próxima migration: **0027**; as migrations são imutáveis depois de aplicadas.

**Regra de entrega:** nunca há testes vermelhos entre cartões. Cada cartão (ou par atómico) só é entregue e commitado com `migrations/tests/run.sh`, `cargo test -p ptmarket-api` (suite completa), `go test -race ./...` e, se tocar no contrato, `npm run verify` verdes.

## Ordem de execução (a ordem manda; o número é só o nome do cartão)
| Passo | Cartão | Agente | Modelo | Depende de | Migration |
|---|---|---|---|---|---|
| 1 | 01 `geo_dicofre` | db-architect | sonnet | — | 0027 |
| 1∥ | 12 `money`: comissão efetiva (função pura) | rust-core | opus | — | — |
| 2 | 02 Seed DICOFRE por CSV local | db-architect | sonnet | 01 | — |
| 3 | 03 `sponsor_entities` + papel `sponsor_admin` | db-architect | opus | 01 | 0028 |
| 4 | 04 Colunas de `stores` + trinco da exceção de comissão | db-architect | opus | 01, 03 | 0029 |
| 5 | 13 Painel único: login, papéis, tenant pelo papel, helpers de teste no canal nacional | rust-core | opus | 03, 04 | — |
| 6 | 05 `stores.tenant_id` → canal nacional (dados) | db-architect | opus | 04, 13 | 0030 |
| 7 | 06 `store_sponsorships` | db-architect | opus | 03, 05 | 0031 |
| 8 | 07 `platform_settings` + `billing_plan_tiers` (seed) | db-architect | opus | 06 | 0032 |
| 9 | **Par A:** 08 Visibilidade por canal (view, RLS, selos, trinco) → 16 `tenancy::portal` | db-architect → rust-core | opus | 06, 07, 13 | 0033 |
| 10 | **Par B:** 08b Isolamento por loja na RLS (`app.store_id`) → 14 Âmbito de loja/entidade no tx + `RequireSponsorAdmin` | db-architect → rust-core | opus | par A | 0035 |
| 11 | 09 `store_verifications` (código cifrado) | db-architect | opus | par B | 0036 |
| 12 | 10 `identity_admin_verification_*` | db-architect | opus | 09 | 0037 |
| 13 | 11 Kinds críticos (alteração selada) | db-architect | opus | 10 | 0038 |
| 14 | 15 Passkeys de staff com um só `rp_id` | rust-core | opus | 14 | — |
| 15 | 17 `sponsors`: geografia e entidades elegíveis | rust-core | sonnet | 15 | — |
| 16 | 18 Comissão: leitura da BD + preview do registo | rust-core | opus | 12, 14, 17 | — |
| 17 | 19 Patrocínios: API do lojista | rust-core | opus | 14, 18 | — |
| 18 | 20 Patrocínios: API do `sponsor_admin` | rust-core | opus | 19, 16, 11 | — |
| 19 | 21 Storage privado + URL assinado de 5 min | rust-core | opus | 20 (série) | — |
| 20 | 22 Verificações: envio pelo lojista (cifra `VERIFICATION_ENC_KEY`) | rust-core | opus | 21, 09 | — |
| 21 | 23 Verificações: revisão pelo super_admin | rust-core | opus | 22, 10 | — |
| ∥ | 24 Go: job `active` → `expired` | go-integrations | sonnet | 06, 11 | — |
| ∥ | 25 Go: job de eliminação de ficheiros | go-integrations | sonnet | 09, 21, 24 | — |
| ∥ | 26 Frontend: registo da loja (âncora, selos, plano) | frontend-ui | sonnet | 17, 18 | — |
| — | 90 Nota: pré-requisitos para encomendas, pagamentos e onboarding | — | — | — | — |

## Como se evita a janela vermelha
- **13 antes do 05:** o Rust passa a decidir pelo papel e os testes passam a semear lojas no canal nacional enquanto as lojas ainda podem estar em tenants municipais. Assim, mover os dados (05) não parte nada.
- **Par A (08 → 16)** e **Par B (08b → 14):** a migration e a adaptação Rust correm seguidas, sem mais nada pelo meio, e fazem **um só commit** no fim do par, com tudo verde. Dentro do par o cartão de BD lista as falhas Rust que o cartão seguinte fecha.
- BD e Rust alternam numa só fila (passos 1–21): nunca correm ao mesmo tempo com migrations a mudar. Só o 12 (puro) corre em paralelo com a BD.

## Paralelismo
```
Fila única BD/Rust: 01 → 02 → 03 → 04 → 13 → 05 → 06 → 07 → [08 → 16] → [08b → 14] → 09 → 10 → 11 → 15 → 17 → 18 → 19 → 20 → 21 → 22 → 23
Em paralelo:  12 com os passos 1–4 · 24 depois do 11 (com Rust 15+) · 25 depois do 21 e do 24 · 26 depois do 18 (com Rust 19–23 e com Go)
```
`security-auditor` obrigatório: 08, 08b, 10, 13, 14, 15, 16, 20, 21, 22, 23. Prova `ux-reviewer`: 26.

## Passo do supervisor antes de carregar dados reais com o cartão 02
Obter os dados abertos oficiais da CAOP/DGT (versão mais recente) e convertê-los para o CSV intermédio `code,name`. Os códigos que desapareceram não se apagam: ficam com `valid_to`. O cartão 02 em si só precisa dos fixtures.

## Decisões de arquitetura (aprovadas pelo supervisor, salvo indicação)
1. `tenant_admin` sem acesso a lojas; `sponsor_admin` com 2FA obrigatório e ator `Municipal`; staff só em `PLATFORM_ADMIN_HOST`; venda partida com um só arredondamento.
2. Isolamento entre lojas do mesmo país em duas camadas: extractor + RLS RESTRICTIVE por `app.store_id` / `app.sponsor_entity_id` (exceções: ator `admin` e leitura pública pelo portal). O checkout multi-loja resolve-se no épico de encomendas (nota 90, ponto 3).
3. A app não escreve `custom_commission_bps`, `kyc_verified` nem `commission_override_bps`; a edição pelo super_admin fica para o backoffice.
4. Código da Certidão Permanente só cifrado (AES-256-GCM `v1:<kid>`, `VERIFICATION_ENC_KEY`), decifrado a pedido do super_admin com evento `store_verification.code_viewed`.
5. Por rever: sem pesquisa por código postal e sem endpoint de registo da loja (botão final do 26 desligado); módulo Rust novo `sponsors`; planos por `CHECK` em `billing_plan_code`; passkeys de staff antigas com `rp_id` de canal ficam inválidas (dados de dev).

## Perguntas em aberto para o owner (dados, dinheiro, legal)
1. **`commission_override_bps` ≠ 0:** quem o pode definir e em que casos. Até decidir, fica sempre 0.
2. **IVA sobre a comissão e as mensalidades** (contabilista): confirmar que os valores são sem IVA e que os 23% vão na fatura mensal; o cartão 26 mostra "acresce IVA".
3. **Textos legais:** versão dos Termos (`terms_version`), redação final do aviso da isenção e pré-aviso de 15 dias aos lojistas antes de mudar comissões (Regulamento (UE) 2019/1150, P2B).
4. **Fonte código postal → freguesia** (CTT licenciada ou alternativa) para um épico futuro.
5. **Certidão Permanente:** só o formato exato do código de acesso (a guarda cifrada está decidida).
