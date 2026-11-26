# 17 — Rust: módulo `sponsors` com geografia e entidades elegíveis (leitura pública) (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** sonnet · **Depende de:** 15 (série Rust; BD fechada no 11) · **Paralelo com:** — (Rust em série)

## Objetivo
O formulário de registo consegue listar distritos, concelhos e freguesias e saber que entidades patrocinadoras cobrem uma freguesia confirmada.

## Pode alterar
- `backend-rust/src/sponsors/{mod,geo,eligibility,http}.rs` (criar); `src/lib.rs`, `src/http/{mod,openapi}.rs`, `openapi.json`, `.sqlx/**`; `backend-rust/tests/sponsors_public.rs` (criar)

## Não tocar
- `src/identity/`, `src/tenancy/`, `src/money/`, `src/audit/`; `migrations/` (só leitura). O módulo `sponsors` é o dono de `geo_dicofre`, `sponsor_entities`, `sponsor_entity_areas` e `store_sponsorships`: nenhum outro módulo as lê diretamente.

## Contexto exato (spec 14 §2, §5, §6)
```
Elegibilidade pela morada física da loja (storefront_dicofre, 6 dígitos): municipality cobre o concelho (DDCC); parish cobre a freguesia (DDCCFF); association cobre uma lista de áreas DICOFRE configurada na entidade.
Código postal → DICOFRE: um código postal não corresponde sempre a uma só freguesia e a fonte CP → concelho está POR FECHAR (base dos CTT licenciada). Neste épico NÃO há pesquisa por código postal: o lojista escolhe distrito → concelho → freguesia. geo_dicofre(code, level, parent_code, name, caop_version, valid_to): valid_to NULL = código em vigor; um código com valid_to continua a existir (patrocínios antigos), mas não se oferece a quem se regista.
Query de elegibilidade ($1 = dicofre de freguesia, $2 = país):
  SELECT e.id, e.kind, e.name, e.slug, e.logo_key FROM sponsor_entities e WHERE e.is_active AND e.country_code = $2 AND (
        (e.kind = 'municipality' AND e.area_code = left($1, 4)) OR (e.kind = 'parish' AND e.area_code = $1)
     OR (e.kind = 'association' AND EXISTS (SELECT 1 FROM sponsor_entity_areas a WHERE a.sponsor_entity_id = e.id AND left($1, length(a.area_code)) = a.area_code)))
  ORDER BY CASE e.kind WHEN 'municipality' THEN 1 WHEN 'parish' THEN 2 ELSE 3 END, e.name
Endpoints públicos (sem sessão; qualquer Host conhecido, incluindo o de plataforma; leitura em state.db_replica; as 3 tabelas têm RLS de leitura USING (true) e não precisam de tenant no contexto):
  GET /api/v1/geo/districts → [{"code","name"}] · GET /api/v1/geo/municipalities?district=DD → idem · GET /api/v1/geo/parishes?municipality=DDCC → idem (só valid_to IS NULL; por nome)
  GET /api/v1/sponsors/eligible?dicofre=DDCCFF → [{"id","kind","name","slug","logo_key"}] na ordem fixa dos selos
Validação: parâmetros só com dígitos e o tamanho exato (senão 400); dicofre inexistente ou fora de vigor → 404; queries com deny_unknown_fields; Cache-Control: public, max-age=300. País = 'PT' fixo neste épico (constante com nome).
API interna para os cartões 18–20: sponsors::eligibility::covers(tx, entity_id, dicofre) -> bool (aceita códigos fora de vigor) e sponsors::eligibility::eligible_for(tx, dicofre, country) -> Vec<SponsorSummary>.
SQL com sqlx::query!/query_as! (tabelas normais: a exceção das views não se aplica). Sem dados pessoais: sem auditoria síncrona.
```

## Feito quando
- [ ] `sponsors_public`: freguesia coberta por Câmara + Junta + Associação devolve as 3 pela ordem fixa (**co-patrocínio possível**); a freguesia vizinha do mesmo concelho devolve só a Câmara; associação com área de concelho cobre todas as freguesias dele
- [ ] Entidade inativa ou de outro país não aparece; `dicofre=1106` (4 dígitos), letras ou parâmetro desconhecido → 400; freguesia com `valid_to` preenchido não sai na lista e dá 404 na elegibilidade pública
- [ ] Nenhuma resposta traz `channel_tenant_id` nem contactos; `openapi.json` atualizado

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test sponsors_public` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suite completa `cargo test -p ptmarket-api` (mesmas variáveis) e contrato da API: `cd frontend-web && npm run gen:api && npm run verify`
