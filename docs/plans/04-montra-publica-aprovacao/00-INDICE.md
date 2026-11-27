# 00 — Índice do épico 04: Montra Pública e ecrã de aprovação do `sponsor_admin`

Decisão do owner de 27/11/2026. Fontes: spec 14 §1–§2 e §7–§8, spec 11 §2–§6, spec 12 §2–§3. Cada executor lê **só o seu cartão**. Próximas migrations: **0039** e **0040**; são imutáveis depois de aplicadas.

**Pré-requisito:** cartões 15–20 e 26 do épico 03 fechados (o 06 e o 09 usam a API do 20). Os cartões 21–25 do épico 03 continuam em pausa e não são precisos aqui.

**Regra de entrega:** nunca há testes vermelhos entre cartões. Cada cartão (ou par atómico) só é entregue e commitado com `migrations/tests/run.sh`, `cargo test -p ptmarket-api` (suite completa), `go test -race ./...` e, se tocar no contrato ou no frontend, `npm run verify` verdes.

## Ordem de execução (a ordem manda; o número é só o nome do cartão)
| Passo | Cartão | Agente | Modelo | Depende de | Migration |
|---|---|---|---|---|---|
| 1 | **Par A:** 01 Views de portal (produtos, variantes, categorias) + fecho da leitura direta → 02 `tenancy::portal`: catálogo por canal | db-architect → rust-core | opus | épico 03 (0038) | 0039 |
| 1∥ | 07 Painel: esqueleto, login de staff e 2FA | frontend-ui | opus | — | — |
| 2 | **Par B:** 03 Pesquisa (FTS + função do portal) → 04 `tenancy::portal`: pesquisa, lojas por cursor, perfil da loja | db-architect → rust-core | opus | par A | 0040 |
| 2∥ | 08 Painel: ativação do TOTP e códigos de recuperação | frontend-ui | opus | 07 | — |
| 3 | 05 Rotas públicas `/api/v1/catalog/*` + OpenAPI | rust-core | opus | pares A e B | — |
| 3∥ | 13 Dados de demonstração de dev (script, sem migration) | db-architect | sonnet | par B | — |
| 4 | 06 `GET /api/v1/sponsors/mine` | rust-core | opus | 05; épico 03 cartão 20 | — |
| 4∥ | 10 Montra: fundações (canal, tema, rodapé legal, componentes) | frontend-ui | sonnet | 05, 07 | — |
| 5 | 09 Painel: ecrã de aprovação de patrocínios | frontend-ui | opus | 06, 07, 08 | — |
| 5∥ | 11 Montra: página inicial, categorias, listagem, pesquisa | frontend-ui | sonnet | 10 (13 para a prova) | — |
| 5∥ | 12 Montra: ficha de produto, loja e entidade | frontend-ui | sonnet | 10 (13 para a prova) | — |

## Como se evita a janela vermelha
- **Par A (01 → 02)** e **Par B (03 → 04):** a migration e a adaptação Rust correm seguidas, sem mais nada pelo meio, e fazem **um só commit** no fim do par. A 0039 fecha a leitura pública direta de `products`/`product_variants`, por isso parte testes Rust que o 02 adapta; o cartão de BD entrega a lista dessas falhas.
- BD e Rust numa só fila: `01 → 02 → 03 → 04 → 05 → 06`. O 13 não cria migrations e pode correr com o 05/06, mas mexe nos dados de dev: se partir algum teste, remove os dados e pára.
- Frontend: o `schema.d.ts` só é regenerado (`npm run gen:api`) pelo 10 (depois do 05) e pelo 09 (depois do 06), nunca por dois cartões ao mesmo tempo. 11 e 12 têm pastas disjuntas; o 11 é o único que apaga `src/app/page.tsx`.

## Paralelismo
```
Fila única BD/Rust: [01 → 02] → [03 → 04] → 05 → 06
Frontend:           07 → 08 ─────────────────────────→ 09 (depois do 06)
                    07 + 05 → 10 → 11 ∥ 12
Dados de dev:       13 depois do par B (em paralelo com 05, 06 e o frontend)
```
`security-auditor` obrigatório: 01, 02, 03, 04, 05, 06, 07, 08, 09 e 12 (helper JSON-LD). Prova `ux-reviewer` (browser real, 375 e 1440 px, claro e escuro): 07, 08, 09, 10, 11, 12.

## Passos do supervisor
- Antes das provas do 07–09: criar em dev um utilizador `sponsor_admin` (e um segundo, de outra entidade, para o teste de IDOR) pela via suportada; o 13 não cria utilizadores.
- Confirmar a exceção de SQL: as views `portal_products`, `portal_product_variants`, `portal_categories` e a função `portal_search_product_ids` leem-se com `query_as`/`query_scalar` estático + casts (como `portal_stores`); atualizar `.claude/rules/rust.md`.

## Decisões de arquitetura (do arquiteto; o supervisor pode rever)
1. **Leitura pública só pelo portal:** a 0039 retira `portal_read` e o ramo público de `store_scope_select` em produtos, variantes e histórico de preços. O checkout futuro terá a sua própria via (nota 90 do épico 03, ponto 3).
2. **Stock:** a montra só recebe `in_stock` (booleano); a quantidade nunca sai da BD. `sku`, `compare_at_price_cents`, `catalog_item_id` e `ai_enriched` também não.
3. **Omnibus:** o único preço riscado é `lowest_price_30d_cents`, e só quando o preço atual é inferior. Sem percentagens (seriam contas de dinheiro fora do `money`).
4. **Pesquisa v1:** FTS `simple` sem acentos, por função `SECURITY DEFINER` do portal (a view `security_barrier` não usaria o GIN); ordem por mais recentes. Relevância e tolerância a erros ficam para o motor externo (`SearchBackend`).
5. **Paginação:** cursor pelo `id` (UUIDv7) em produtos e por `(name, id)` em lojas; páginas de 24, máximo 48. Sem ordenação por preço na v1.
6. **URL do produto:** `/produto/<uuid>` (os produtos não têm slug). Imagens só de `/media/…` do próprio domínio; sem storage, a montra mostra um marcador tipográfico.
7. **Painel:** vive em `/painel/**`, só no Host da plataforma; Server Actions sobre a API (sem JS obrigatório). Ativação do TOTP **sem QR** (exigia uma dependência nova). Login por passkey fica para o épico de backoffice.
8. **Fora deste épico:** carrinho e checkout, sitemap por domínio, `hreflang`/canal ES, cache HTTP, convites da entidade, relatórios das entidades.

## Riscos
- Fecho da leitura direta (0039) toca em 6 ficheiros de teste SQL e 3 de Rust: é o cartão mais delicado; a auditoria do par A deve ser feita antes do par B.
- Os testes Rust usam a BD de dev: os dados do 13 podem interferir (o cartão manda remover e parar).
- O SSR conta como um só IP no travão de login enquanto o Next não reenviar o IP real (já registado no ESTADO).
- Sem fotografias reais, a prova de "layout transcendente" faz-se com marcadores tipográficos.

## Perguntas em aberto para o owner (marca, dinheiro, legal); nenhuma bloqueia o arranque
1. **Marca:** nome, logótipo, paleta e fontes do `lojaportugal.pt`. Por defeito: tokens atuais do design system.
2. **Fotografias de demonstração** (com direitos de uso) para a prova visual. Por defeito: marcadores tipográficos.
3. **Compra antes de haver checkout:** por defeito, sem botão de compra; texto "Compra online disponível em breve" e contacto da loja.
4. **Stock:** por defeito só "Disponível"/"Esgotado". "Últimas unidades" só com decisão sua (risco de padrão enganoso, DSA art. 25.º).
5. **PVP recomendado** (`compare_at_price_cents`): por defeito não se mostra. Mostrá-lo precisa de parecer jurídico (pode confundir-se com redução de preço).
6. **Preço por unidade de medida** (DL 138/90; ES RD 3423/2000) em produtos a peso ou volume: não há campos na BD. Tem de ficar resolvido antes de vender alimentar a granel.
7. **Identificação do vendedor:** a página da loja mostra designação legal, NIF, morada, email e telefone (obrigatório por lei). Num ENI são dados pessoais: confirmar que o registo o avisa.
8. **Textos:** Termos, Privacidade e a redação dos avisos de aprovação e de revogação no painel. Por defeito: textos provisórios num só ficheiro.
9. **Revogação de patrocínio:** hoje tem efeito imediato (spec 14). Confirmar com o jurista se o Reg. (UE) 2019/1150 exige pré-aviso ao lojista quando a comissão muda por essa via.
10. **Ordenação e destaques:** por defeito "mais recentes primeiro", sem destaques pagos. Destaques pagos obrigam a divulgar os critérios (DSA art. 27.º) e são decisão comercial sua.
