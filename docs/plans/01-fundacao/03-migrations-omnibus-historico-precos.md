# 03 — Histórico de preços Omnibus garantido pela BD (épico: 01-fundacao)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 02 · **Paralelo com:** 05, 09

## Objetivo
Qualquer alteração de preço de uma variante fica registada num histórico só de acréscimo e o "preço mais baixo dos últimos 30 dias" é calculado pela BD, não pela aplicação.

## Pode alterar
- `migrations/0007_price_history.sql`, `migrations/tests/omnibus.sql` (criar)

## Não tocar
- `migrations/0001`–`0006` e `tests/rls.sql` — imutáveis (cartão 02); corrigir = nova migration
- `infra/`, `backend-rust/`, `workers-go/`, `frontend-web/` — outros cartões

## Contexto exato (colado da spec; não ler a spec)
```
Regra legal: PT DL 70/2007 (red. DL 109-G/2021) e ES art. 20 Ley 7/1996 (RDL 24/2021) — ao anunciar uma redução, indicar o preço mais baixo praticado nos 30 dias anteriores à redução. O histórico é a prova perante a ASAE: nunca se altera nem se apaga.
product_price_history(id UUID PRIMARY KEY DEFAULT uuidv7(), tenant_id UUID NOT NULL, variant_id UUID NOT NULL, FOREIGN KEY (tenant_id, variant_id) REFERENCES product_variants(tenant_id, id) ON DELETE RESTRICT, price_cents BIGINT NOT NULL CHECK (price_cents >= 0), recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()); índices (tenant_id, variant_id, recorded_at DESC) e (recorded_at)
RLS: ENABLE + FORCE. T := NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
  policy SELECT TO ptmarket_app USING (tenant_id = T); GRANT SELECT TO ptmarket_app (sem INSERT/UPDATE/DELETE: a app nunca escreve aqui)
  policy INSERT TO CURRENT_USER WITH CHECK (tenant_id = T)  -- o dono, para a função SECURITY DEFINER abaixo
Trigger 1, BEFORE INSERT OR UPDATE ON product_variants (SECURITY INVOKER):
  INSERT → NEW.lowest_price_30d_cents := NULL
  UPDATE com NEW.price_cents IS DISTINCT FROM OLD.price_cents → NEW.lowest_price_30d_cents := (SELECT min(h.price_cents) FROM product_price_history h WHERE h.variant_id = OLD.id AND h.recorded_at >= COALESCE((SELECT max(p.recorded_at) FROM product_price_history p WHERE p.variant_id = OLD.id AND p.recorded_at <= now() - interval '30 days'), '-infinity'))
  UPDATE sem mudança de preço → NEW.lowest_price_30d_cents := OLD.lowest_price_30d_cents (a coluna nunca é escrita pela app)
Trigger 2, AFTER INSERT OR UPDATE ON product_variants, só quando o preço é novo ou mudou: INSERT INTO product_price_history(tenant_id, variant_id, price_cents) VALUES (NEW.tenant_id, NEW.id, NEW.price_cents) — função SECURITY DEFINER com SET search_path = pg_catalog, public
Porquê a subquery: o preço em vigor no início da janela foi gravado ANTES dos 30 dias; tem de entrar no mínimo.
Vetores: 1000 (há 40 d) → 2000 (há 5 d) → 1500 agora ⇒ lowest = 1000 · 1000 (há 40 d) → 2000 (há 35 d) → 1500 agora ⇒ lowest = 2000 · variante nova ⇒ NULL e 1 linha no histórico
```

## Feito quando
- [ ] Rollback mental no topo; `0007` aplica-se em cima de `0001`–`0006` numa BD limpa
- [ ] Teste novo `tests/omnibus.sql`: os 3 vetores (datas recuadas como superuser, alterações de preço com `SET ROLE ptmarket_app` + contexto); UPDATE sem mudança de preço não cria linha; app que escreve `lowest_price_30d_cents` à mão é ignorada
- [ ] Casos de erro: app faz INSERT/UPDATE/DELETE no histórico → 42501; tenant A não lê o histórico do B (0 linhas); apagar variante com histórico → 23503

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM` (inclui `omnibus.sql`), código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Isolamento RLS do cartão 02 — o mesmo `migrations/tests/run.sh` tem de continuar a passar `rls.sql` sem alterações ao ficheiro
