# 05 — Módulo `money`: cêntimos, bps, half-up, IVA incluído (épico: 01-fundacao)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 04 · **Paralelo com:** 03, 09

## Objetivo
Existe um único sítio no backend onde se faz aritmética e arredondamento de dinheiro, com vetores de teste fixos.

## Pode alterar
- `backend-rust/src/money/**` (criar); `backend-rust/src/lib.rs` (só `pub mod money;`); `backend-rust/Cargo.toml` (só `rust_decimal`, `proptest` em dev)

## Não tocar
- Resto de `backend-rust/src/` — cartões 04 e 06; `migrations/`, `infra/`, `workers-go/`, `frontend-web/` — outros cartões

## Contexto exato (colado da spec; não ler a spec)
```
Regra: dinheiro nunca em float. i64 cêntimos; percentagens em bps i32 (2300 = 23%, 650 = 6,5%); rust_decimal::Decimal nos cálculos intermédios.
D7: price_cents = PVP com IVA incluído (obrigatório B2C em PT). Arredondamento aritmético (half-up) POR LINHA, só neste módulo; tem de dar os mesmos cêntimos que o Moloni (o teste de paridade com faturas reais é do 1.º cartão de payments — até lá split_vat é provisório e fica assim documentado).
Tipos: Cents(i64), Bps(i32) com construtor validado 0..=10000. Entradas negativas, bps fora do intervalo ou overflow → Err (AppError::Validation / erro próprio convertível); nunca panic, nunca wrap.
half_up(d: Decimal) -> i64 = d.round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
mul_bps(c, bps) = half_up(c × bps / 10000)                       — comissões, cashback
line_total(unit, qty: u32) = unit × qty (checked)
split_vat(gross, bps) -> (net, vat): net = half_up(gross × 10000 / (10000 + bps)); vat = gross − net   — aplica-se ao total da LINHA; net + vat == gross sempre
effective_vat_bps(store_vat_exempt_art53: bool, product_bps) -> Bps = 0 se a loja estiver no Art. 53.º do CIVA (isenção PT), senão product_bps
Vetores mul_bps: (1000, 650) = 65 · (1999, 650) = 130 [129,935] · (50, 500) = 3 [2,5] · (10, 500) = 1 [0,5] · (9, 500) = 0 [0,45] · (x, 0) = 0 · (x, 10000) = x
Vetores split_vat: (1230, 2300) = (1000, 230) · (999, 2300) = (812, 187) · (999, 600) = (942, 57) · (100, 1300) = (88, 12) · (2100, 2100) = (1736, 364) [IVA ES 21%] · (999, 0) = (999, 0) [Art. 53.º]
```

## Feito quando
- [ ] API pública pequena e documentada; `Display` de `Cents` em formato pt-PT (`12,30 €`) só para logs/testes
- [ ] Teste novo `money::tests`: todos os vetores acima, à letra
- [ ] Teste de propriedades (proptest): `net + vat == gross`; `0 ≤ mul_bps(c, b) ≤ c`; monotonia em `c`
- [ ] Casos de erro: cêntimos negativos, `Bps(10001)`, `Bps(-1)`, `line_total(i64::MAX, 2)` → `Err`, sem panic
- [ ] Teste `money::no_float`: nenhum `f32`/`f64`/`as f` em `src/money/`

## Prova (um comando)
`cd backend-rust && cargo test -p ptmarket-api money` → esperado: todos os testes `money::*` passam, 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Health e AppError do cartão 04 — `cd backend-rust && cargo test -p ptmarket-api http::health`
