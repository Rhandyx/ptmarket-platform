---
paths:
  - "migrations/**"
---
# SQL (migrations) — specs: 02 §4 com as alterações da 11 §2

- Migrations sequenciais e **imutáveis** depois de aplicadas em staging; corrigir = nova migration.
- PostgreSQL 18. PK `UUID DEFAULT uuidv7()` (valor normalmente gerado em Rust, v7); dinheiro `BIGINT` cêntimos; percentagens `INT` bps; nunca `REAL`/`FLOAT`/`NUMERIC` para dinheiro.
- Aplicar a 11 §2: `product_variants`, `stock_reservations`, `outbox_events`, `customers`, `catalog_item_id`, `currency`.
- RLS ativo em todas as tabelas com `tenant_id`; índices compostos começam por `tenant_id`.
- `CHECK` para invariantes (preços ≥ 0, qty > 0, estados em lista fechada).
- Toda a FK tem índice. `ON DELETE` explícito.
- Testar: `sqlx migrate run` numa BD limpa + rollback mental documentado no topo da migration.
