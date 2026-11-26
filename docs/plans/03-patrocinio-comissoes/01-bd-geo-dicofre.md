# 01 — BD: tabela de referência `geo_dicofre` (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** sonnet · **Depende de:** — · **Paralelo com:** 12 (Rust puro, sem BD)

## Objetivo
Existe a tabela oficial de distritos, concelhos e freguesias (vazia), só de leitura para a app, pronta para o seed (cartão 02) e para as FKs dos cartões 03 e 04.

## Pode alterar
- `migrations/0027_geo_dicofre.sql`, `migrations/tests/geo_dicofre.sql` (criar); `migrations/tests/run.sh` (só registar o teste novo, se a lista for explícita)

## Não tocar
- `migrations/0001–0026` (imutáveis); `infra/postgres/init/` (não há alteração selada aqui); `backend-rust/`, `workers-go/`. Nunca ler `.env`.

## Contexto exato (spec 14 §5 + decisão do supervisor; não ler a spec)
```
geo_dicofre: referência (distrito DD, concelho DDCC, freguesia DDCCFF, nome, caop_version), carregada dos dados abertos oficiais da CAOP/DGT por script de seed, NÃO por migration. A reorganização de freguesias de 2025 alterou códigos e os patrocínios antigos têm de continuar a resolver → uma linha NUNCA é apagada; um código que desaparece fica com valid_to preenchido.
CREATE TABLE geo_dicofre (
    code VARCHAR(6) PRIMARY KEY CHECK (code ~ '^[0-9]{2}([0-9]{2}([0-9]{2})?)?$'),
    level VARCHAR(12) NOT NULL CHECK (level IN ('district', 'municipality', 'parish')),
    parent_code VARCHAR(4) REFERENCES geo_dicofre (code) ON DELETE RESTRICT,
    name VARCHAR(160) NOT NULL, caop_version VARCHAR(16) NOT NULL /* última versão da CAOP em que o código apareceu */, valid_to TIMESTAMPTZ /* NULL = em vigor */,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (level = CASE length(code) WHEN 2 THEN 'district' WHEN 4 THEN 'municipality' ELSE 'parish' END),
    CHECK ((length(code) = 2 AND parent_code IS NULL) OR parent_code = left(code, length(code) - 2)));
CREATE INDEX geo_dicofre_parent_idx ON geo_dicofre (parent_code) WHERE valid_to IS NULL;   -- não validar a gama de DD (ilhas incluídas); sem tenant_id (dado público)
RLS: ENABLE + FORCE; policy de SELECT para ptmarket_app USING (true); GRANT SELECT a ptmarket_app; nenhuma escrita para app nem worker. DELETE bloqueado por trigger (RAISE) para todos, incluindo o migrator.
Tabela nova → bloco L1 condicional: copiar o DO $$ … $$ da 0018 (linhas 77–98: zz_audit_row + zz_audit_truncate, ENABLE ALWAYS, só se a L2 ainda não os criou) com ARRAY['geo_dicofre']. Nunca SET ROLE para um papel sem acesso a audit (lição L2).
```

## Feito quando
- [ ] BD limpa e BD com L2: a 0027 aplica; `geo_dicofre` tem os dois triggers `zz_audit_*`
- [ ] Teste novo `geo_dicofre`: aceita `11`, `1106`, `110601` com pais coerentes; recusa código com 3 ou 5 dígitos, `level` errado, pai errado e freguesia sem concelho (FK)
- [ ] Como `ptmarket_app`: SELECT funciona sem tenant no contexto; INSERT, UPDATE e DELETE → 42501; DELETE como migrator → erro do trigger

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `geo_dicofre` (com a 2.ª passagem L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Caixa negra L1/L2 — incluída no `run.sh`. Suites completas verdes antes de fechar: `cargo test -p ptmarket-api` e `cd workers-go && go test -race ./...`
