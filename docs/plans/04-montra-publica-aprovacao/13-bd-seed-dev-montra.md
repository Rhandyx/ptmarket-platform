# 13 — Dados de demonstração de dev para a montra e para o painel (épico: 04-montra-publica-aprovacao)

**Agente:** db-architect · **Modelo:** sonnet · **Depende de:** par 03 + 04 (BD na 0040) · **Paralelo com:** 05, 06 e os cartões de frontend (não cria migrations)

## Objetivo
A BD de dev fica com um catálogo pequeno e realista para as provas em browser real: dois canais, lojas com e sem patrocínio, co-patrocínio, uma promoção Omnibus e um pedido pendente. Tudo removível com um comando.

## Pode alterar
- `infra/scripts/dev-seed-montra.sql` (criar); `infra/README.md` (uma secção curta "Dados de demonstração da montra")

## Não tocar
- `migrations/` (nenhuma migration nova; os dados de demonstração nunca vão numa migration); `backend-rust/`, `frontend-web/`; utilizadores, sessões e papéis (`users`, `user_roles`: o supervisor cria o `sponsor_admin` de dev pela via suportada); volumes Docker e outras BD. Nunca ler `.env`.

## Contexto exato (regras do projeto; spec 14 §1–§2)
```
Só dev. O script corre com psql como o migrator de dev e RECUSA correr sem `-v confirm_dev=yes` (RAISE no topo). Cabeçalho a dizer: nunca em staging nem em produção.
Dois modos: `-v mode=seed` (por defeito) e `-v mode=remove`. Idempotente: correr duas vezes não duplica (ON CONFLICT / verificação por slug). Tudo o que cria tem slug com o prefixo `demo-`; o modo remove apaga só esses registos, pela ordem das FK (product_price_history tem ON DELETE RESTRICT: se não se puder apagar o histórico como migrator, o remove despublica os produtos e desativa as lojas `demo-` em vez de apagar, e diz isso na saída).
Caixa negra: toda a mutação precisa de app.actor_type (senão a BD faz RAISE): usar o ator `system` e um request id próprio, como os testes SQL de migrations/tests/ fazem. Nunca desligar triggers nem tocar em audit.*.
Conteúdo mínimo:
  - Canal nacional PT: usar o tenant national_portal de PT que já existir (não criar outro: há um índice único por país). Canal white-label `demo-camara` (tenant_type municipal, custom_domain `demo-camara.localhost`).
  - Entidades: 1 Câmara (municipality, com channel_tenant_id = canal demo-camara), 1 Junta (parish, sem canal), 1 Associação. Áreas DICOFRE reais da CAOP já carregada (validar com length() + FK, nunca regex só de algarismos: há códigos com letras).
  - 6 lojas no canal nacional (uma loja só pode viver num tenant national_portal): 2 só com a Câmara; 1 co-patrocinada Câmara + Junta; 1 só com a Associação; 1 sem patrocínio; 1 com um pedido `pending` à Câmara. Uma com vat_exempt_art53 = true; uma em modo férias; os três shipping_scope representados. stores tem grants por coluna e o trinco da exceção de comissão: não escrever custom_commission_bps, kyc_verified nem commission_override_bps.
  - 12 categorias em 2 níveis (slugs `demo-…`, nomes {"pt": …}); 2 sem produtos.
  - ~40 produtos publicados + 2 não publicados; 5 com 2–3 variantes; 3 esgotados (stock_qty 0); títulos com acentos ("Pão de Mafra") para a pesquisa. Preços em cêntimos (BIGINT), vat_rate_bps explícito (600 / 1300 / 2300; 0 na loja do art. 53.º). images = '[]' (não há storage: a montra mostra o marcador tipográfico).
  - Omnibus: em 3 variantes, baixar o preço com um UPDATE depois do INSERT (o trigger grava o histórico e calcula lowest_price_30d_cents); em 1, subir o preço. Nunca escrever em product_price_history nem em lowest_price_30d_cents à mão.
  - Patrocínios: os `active` com valid_from = now(); 1 com valid_to no passado (prova que sai do white-label sem job). Respeitar as transições que a BD impõe (pending → active).
README: os dois comandos (seed e remove), o Host a usar em dev para cada canal e a nota de que os testes automáticos não dependem destes dados.
```

## Feito quando
- [ ] Depois do seed, como `ptmarket_app` no contexto do canal nacional: `portal_products` devolve os ~40 publicados; no contexto de `demo-camara`: só os das lojas com patrocínio ativo da Câmara; `portal_search_product_ids('pao', NULL, 10)` encontra "Pão de Mafra"
- [ ] Correr o seed duas vezes não muda as contagens; `mode=remove` deixa as views do portal sem nenhum registo `demo-`; sem `confirm_dev=yes` o script aborta sem escrever
- [ ] **Sem interferência:** com os dados carregados, `migrations/tests/run.sh` e `cargo test -p ptmarket-api` continuam verdes. Se algum teste falhar por causa dos dados → correr `mode=remove`, PARAR e reportar (não alterar testes)

## Prova (um comando)
`psql "postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket" -v confirm_dev=yes -f infra/scripts/dev-seed-montra.sql` → esperado: termina sem erro e imprime as contagens (lojas, produtos, variantes, patrocínios)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `migrations/tests/run.sh`; `cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api`
