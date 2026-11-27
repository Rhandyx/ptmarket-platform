//! Catálogo público por canal (cartão 04/02; spec 14 §1.1) contra o Postgres real: produtos,
//! variantes e categorias só pelas views da 0039, isolamento entre canais, paginação por cursor,
//! Omnibus e art. 53.º.
//!
//! A pool da app faz `SET ROLE ptmarket_app`. Tenants, entidades e categorias semeiam-se como dono;
//! lojas, produtos, preços e patrocínios pela app com o âmbito da loja (`begin_store_tx`) e as
//! decisões com o âmbito da entidade (`begin_sponsor_tx`).
//!
//! Mundo (todas as lojas no nacional PT): `s1` Câmara A (canal CA) + Junta J (sem domínio) · `s2`
//! Câmara B (canal CB) · `s3` sem patrocínio, isenta pelo art. 53.º. Categorias `raiz` ← `meio` ←
//! `folha`; `outra` à parte; `vazia` sem produtos.

use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    error::AppError,
    identity::rbac::{SponsorScope, StoreScope},
    tenancy::{
        CountryCode, PortalCategory, PortalProductCard, PortalReadTx, ProductFilter,
        ResolvedTenant, TenantId, TenantType, begin_portal_read_tx,
        db::{begin_sponsor_tx, begin_store_tx},
    },
};
use serde_json::json;
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

type TestResult = anyhow::Result<()>;

const IBAN: &str = "PT50000201231234567890154";
const SKU: &str = "SKU-SEGREDO-0402";

async fn app_pool(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(2)
        .after_connect(|c, _meta| {
            Box::pin(async move {
                sqlx::query!("SET ROLE ptmarket_app").execute(c).await?;
                Ok(())
            })
        })
        .connect_with(conn.clone())
        .await
}

fn merchant() -> AuditCtx {
    AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None)
}

async fn seed_tenant(
    owner: &PgPool,
    slug: &str,
    tenant_type: TenantType,
    country: CountryCode,
) -> sqlx::Result<ResolvedTenant> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code)
         VALUES ($1, $2, $3, $4, $5, $6)",
        id,
        slug,
        format!("{slug}.ptmarket.invalid"),
        slug,
        tenant_type.as_str(),
        country.as_str()
    )
    .execute(owner)
    .await?;
    Ok(ResolvedTenant::for_tests(
        TenantId::for_tests(id),
        tenant_type,
        country,
    ))
}

async fn seed_entity(
    owner: &PgPool,
    kind: &str,
    slug: &str,
    area: &str,
    channel: Option<&ResolvedTenant>,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code,
                                       channel_tenant_id)
         VALUES ($1, $2, 'PT', $3, $3, $4, $5)",
        id,
        kind,
        slug,
        area,
        channel.map(|c| c.id().as_uuid())
    )
    .execute(owner)
    .await?;
    Ok(id)
}

async fn seed_category(
    owner: &PgPool,
    slug: &str,
    parent: Option<Uuid>,
    sort_order: i32,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO categories (id, parent_id, slug, name, sort_order) VALUES ($1, $2, $3, $4, $5)",
        id,
        parent,
        slug,
        json!({"pt": slug}),
        sort_order
    )
    .execute(owner)
    .await?;
    Ok(id)
}

/// Loja na app (com IBAN, para provar que não sai): o âmbito da própria loja.
async fn seed_store(
    app: &PgPool,
    t: &ResolvedTenant,
    slug: &str,
    art53: bool,
) -> anyhow::Result<StoreScope> {
    let scope = StoreScope::for_tests(t.id(), Uuid::now_v7());
    let mut tx = begin_store_tx(app, &scope, &merchant()).await?;
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email,
                             vat_exempt_art53)
         VALUES ($1, $2, $3, $3, $3, '500000000', $4, 'loja@test.invalid', $5)",
        scope.store_id(),
        t.id().as_uuid(),
        slug,
        IBAN,
        art53
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(scope)
}

/// Patrocínio `active` desde ontem: a loja pede e a entidade aceita.
async fn sponsor(app: &PgPool, scope: &StoreScope, entity: Uuid) -> anyhow::Result<()> {
    let id = Uuid::now_v7();
    let mut tx = begin_store_tx(app, scope, &merchant()).await?;
    sqlx::query!(
        "INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id)
         VALUES ($1, $2, $3, $4)",
        id,
        scope.tenant().as_uuid(),
        scope.store_id(),
        entity
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let decider = AuditCtx::for_tests(ActorType::Municipal, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_sponsor_tx(
        app,
        scope.tenant(),
        &SponsorScope::for_tests(entity),
        &decider,
    )
    .await?;
    sqlx::query!(
        "UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
         WHERE id = $1",
        id
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Variante a semear: (preço em cêntimos, stock, ativa).
type V = (i64, i32, bool);

/// Produto com variantes (SKU e `compare_at` preenchidos, para provar que não saem):
/// (produto, variantes).
async fn seed_product(
    app: &PgPool,
    scope: &StoreScope,
    title: &str,
    category: Option<Uuid>,
    published: bool,
    variants: &[V],
) -> anyhow::Result<(Uuid, Vec<Uuid>)> {
    let mut tx = begin_store_tx(app, scope, &merchant()).await?;
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO products (id, tenant_id, store_id, category_id, title, vat_rate_bps,
                               is_published)
         VALUES ($1, $2, $3, $4, $5, 2300, $6)",
        id,
        scope.tenant().as_uuid(),
        scope.store_id(),
        category,
        json!({"pt": title}),
        published
    )
    .execute(&mut *tx)
    .await?;
    let mut vids = Vec::new();
    for &(price, stock, active) in variants {
        let vid = Uuid::now_v7();
        sqlx::query!(
            "INSERT INTO product_variants (id, tenant_id, product_id, sku, price_cents,
                                           compare_at_price_cents, stock_qty, is_active)
             VALUES ($1, $2, $3, $4, $5, 99999, $6, $7)",
            vid,
            scope.tenant().as_uuid(),
            id,
            SKU,
            price,
            stock,
            active
        )
        .execute(&mut *tx)
        .await?;
        vids.push(vid);
    }
    tx.commit().await?;
    Ok((id, vids))
}

/// Muda o preço (uma transação por mudança: o Omnibus da BD regista cada uma).
async fn set_price(
    app: &PgPool,
    scope: &StoreScope,
    variant: Uuid,
    price: i64,
) -> anyhow::Result<()> {
    let mut tx = begin_store_tx(app, scope, &merchant()).await?;
    let r = sqlx::query!(
        "UPDATE product_variants SET price_cents = $2 WHERE id = $1",
        variant,
        price
    )
    .execute(&mut *tx)
    .await?;
    anyhow::ensure!(r.rows_affected() == 1, "preço não mudou");
    tx.commit().await?;
    Ok(())
}

struct World {
    app: PgPool,
    np: ResolvedTenant,
    ca: ResolvedTenant,
    cb: ResolvedTenant,
    camara_a: Uuid,
    junta_j: Uuid,
    s: [StoreScope; 3],
    /// raiz, meio, folha, outra, vazia.
    cat: [Uuid; 5],
    /// p1 (s1, folha) · p2 (s2, outra) · p3 (s3, sem categoria) · rascunho (s1) · sem variante
    /// ativa (s1).
    p: [Uuid; 5],
}

async fn world(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> anyhow::Result<World> {
    let owner = opts
        .clone()
        .max_connections(1)
        .connect_with(conn.clone())
        .await?;
    sqlx::query!(
        "INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
            ('93', 'district', NULL, 'Distrito Teste', 'T'),
            ('9301', 'municipality', '93', 'Concelho A', 'T'),
            ('9302', 'municipality', '93', 'Concelho B', 'T'),
            ('930101', 'parish', '9301', 'Freguesia J', 'T')"
    )
    .execute(&owner)
    .await?;
    let np = seed_tenant(
        &owner,
        "nacional-pt",
        TenantType::NationalPortal,
        CountryCode::Pt,
    )
    .await?;
    let ca = seed_tenant(&owner, "canal-a", TenantType::Municipal, CountryCode::Pt).await?;
    let cb = seed_tenant(&owner, "canal-b", TenantType::Municipal, CountryCode::Pt).await?;
    let camara_a = seed_entity(&owner, "municipality", "camara-a", "9301", Some(&ca)).await?;
    let camara_b = seed_entity(&owner, "municipality", "camara-b", "9302", Some(&cb)).await?;
    let junta_j = seed_entity(&owner, "parish", "junta-j", "930101", None).await?;
    let raiz = seed_category(&owner, "t-raiz", None, -3).await?;
    let meio = seed_category(&owner, "t-meio", Some(raiz), -2).await?;
    let folha = seed_category(&owner, "t-folha", Some(meio), -1).await?;
    let outra = seed_category(&owner, "t-outra", None, -1).await?;
    let vazia = seed_category(&owner, "t-vazia", Some(raiz), -1).await?;

    let app = app_pool(opts, conn).await?;
    let s1 = seed_store(&app, &np, "s1", false).await?;
    let s2 = seed_store(&app, &np, "s2", false).await?;
    let s3 = seed_store(&app, &np, "s3", true).await?;
    sponsor(&app, &s1, camara_a).await?;
    sponsor(&app, &s1, junta_j).await?;
    sponsor(&app, &s2, camara_b).await?;
    let (p1, _) = seed_product(&app, &s1, "p1", Some(folha), true, &[(1000, 3, true)]).await?;
    let (p2, _) = seed_product(&app, &s2, "p2", Some(outra), true, &[(500, 0, true)]).await?;
    let (p3, _) = seed_product(&app, &s3, "p3", None, true, &[(700, 1, true)]).await?;
    let (draft, _) =
        seed_product(&app, &s1, "rascunho", Some(outra), false, &[(100, 1, true)]).await?;
    let (inactive, _) =
        seed_product(&app, &s1, "inativo", Some(outra), true, &[(100, 1, false)]).await?;
    Ok(World {
        app,
        np,
        ca,
        cb,
        camara_a,
        junta_j,
        s: [s1, s2, s3],
        cat: [raiz, meio, folha, outra, vazia],
        p: [p1, p2, p3, draft, inactive],
    })
}

async fn open(app: &PgPool, channel: &ResolvedTenant) -> anyhow::Result<PortalReadTx> {
    let ctx = AuditCtx::for_tests(ActorType::Anonymous, None, None, None);
    Ok(begin_portal_read_tx(app, channel, &ctx).await?)
}

fn ids(cards: &[PortalProductCard]) -> Vec<Uuid> {
    cards.iter().map(|c| c.id).collect()
}

/// `has_products` das categorias de `ids`, pela ordem de `ids`.
fn has(cats: &[PortalCategory], ids: &[Uuid]) -> Vec<bool> {
    ids.iter()
        .map(|id| cats.iter().any(|c| c.id == *id && c.has_products))
        .collect()
}

async fn page_ids(tx: &mut PortalReadTx, filter: &ProductFilter) -> anyhow::Result<Vec<Uuid>> {
    Ok(ids(&tx.products_page(filter, None, 48).await?.items))
}

#[sqlx::test(migrations = "../migrations")]
async fn channels_only_see_products_of_their_stores(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let [p1, p2, p3, draft, inactive] = w.p;
    let [raiz, meio, folha, outra, vazia] = w.cat;
    let all = ProductFilter::default();

    // Canal A: só o produto da loja patrocinada pela Câmara A, uma vez, com os 2 selos.
    let mut tx = open(&w.app, &w.ca).await?;
    let page = tx.products_page(&all, None, 24).await?;
    assert_eq!(ids(&page.items), vec![p1]);
    assert_eq!(page.next, None);
    let badges: Vec<Uuid> = page.items[0]
        .store
        .badges
        .iter()
        .map(|b| b.sponsor_entity_id)
        .collect();
    assert_eq!(badges, vec![w.camara_a, w.junta_j]);
    // Produto só do canal B (ou rascunho, ou sem variante ativa): invisível, sem erro.
    for id in [p2, p3, draft, inactive, Uuid::now_v7()] {
        assert_eq!(tx.product_by_id(id).await?, None, "{id}");
    }
    assert_eq!(
        ids(&tx.products_by_ids(&[p2, p1, p3, draft]).await?),
        vec![p1]
    );
    assert!(tx.products_by_ids(&[p2]).await?.is_empty());
    let p = tx
        .product_by_id(p1)
        .await?
        .ok_or_else(|| anyhow::anyhow!("p1 fora do canal A"))?;
    assert_eq!(p.store.id, w.s[0].store_id());
    assert_eq!(p.variants.len(), 1);
    // Filtros: loja de outro canal → vazio; entidade.
    let other_store = ProductFilter {
        store_id: Some(w.s[1].store_id()),
        ..ProductFilter::default()
    };
    assert!(page_ids(&mut tx, &other_store).await?.is_empty());
    let by_junta = ProductFilter {
        entity_slug: Some("junta-j".to_owned()),
        ..ProductFilter::default()
    };
    assert_eq!(page_ids(&mut tx, &by_junta).await?, vec![p1]);
    // Categorias: a folha e os ascendentes têm produtos neste canal; `outra` não (p2 é do B).
    let cats = tx.categories().await?;
    assert_eq!(
        has(&cats, &[raiz, meio, folha, outra, vazia]),
        [true, true, true, false, false]
    );
    // Por `sort_order` e depois `slug`.
    let ours: Vec<&str> = cats
        .iter()
        .filter(|c| w.cat.contains(&c.id))
        .map(|c| c.slug.as_str())
        .collect();
    assert_eq!(ours, ["t-raiz", "t-meio", "t-folha", "t-outra", "t-vazia"]);
    // As tabelas não dão nada em modo público (só as views).
    for q in [
        "SELECT count(*) FROM products",
        "SELECT count(*) FROM product_variants",
        "SELECT count(*) FROM product_price_history",
    ] {
        let n: i64 = sqlx::query_scalar(q).fetch_one(tx.conn_for_tests()).await?;
        assert_eq!(n, 0, "{q}");
    }
    tx.finish().await?;

    // Canal B: só p2; p1 não existe aqui.
    let mut tx = open(&w.app, &w.cb).await?;
    assert_eq!(page_ids(&mut tx, &all).await?, vec![p2]);
    assert_eq!(tx.product_by_id(p1).await?, None);
    assert!(tx.products_by_ids(&[p1]).await?.is_empty());
    assert!(page_ids(&mut tx, &by_junta).await?.is_empty());
    let cats = tx.categories().await?;
    assert_eq!(
        has(&cats, &[raiz, meio, folha, outra, vazia]),
        [false, false, false, true, false]
    );
    tx.finish().await?;

    // Nacional: todos os publicados com variante ativa, mais recentes primeiro.
    let mut tx = open(&w.app, &w.np).await?;
    assert_eq!(page_ids(&mut tx, &all).await?, vec![p3, p2, p1]);
    assert_eq!(page_ids(&mut tx, &by_junta).await?, vec![p1]);
    let by_tree = ProductFilter {
        category_ids: Some(vec![raiz, meio, folha]),
        ..ProductFilter::default()
    };
    assert_eq!(page_ids(&mut tx, &by_tree).await?, vec![p1]);
    let by_store_and_cat = ProductFilter {
        store_id: Some(w.s[0].store_id()),
        category_ids: Some(vec![outra]),
        ..ProductFilter::default()
    };
    assert!(page_ids(&mut tx, &by_store_and_cat).await?.is_empty());
    let none = ProductFilter {
        category_ids: Some(Vec::new()),
        ..ProductFilter::default()
    };
    assert!(page_ids(&mut tx, &none).await?.is_empty());
    assert_eq!(
        ids(&tx.products_by_ids(&[p1, p3, draft, p2, p1]).await?),
        vec![p1, p3, p2],
        "pela ordem de ids, sem repetidos nem invisíveis"
    );
    assert_eq!(tx.product_by_id(draft).await?, None);
    assert_eq!(tx.product_by_id(inactive).await?, None);
    let cats = tx.categories().await?;
    assert_eq!(
        has(&cats, &[raiz, meio, folha, outra, vazia]),
        [true, true, true, true, false]
    );

    // Nenhuma chave nem valor sensível sai.
    let page = tx.products_page(&all, None, 48).await?;
    let product = tx.product_by_id(p1).await?;
    let json = format!(
        "{}{}",
        serde_json::to_string(&page)?,
        serde_json::to_string(&product)?
    );
    for bad in [
        IBAN,
        SKU,
        "99999",
        "iban",
        "sku",
        "stock_qty",
        "compare_at",
        "commission",
        "catalog_item_id",
        "ai_enriched",
    ] {
        assert!(!json.contains(bad), "{bad}");
    }
    tx.finish().await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn cursor_pages_have_no_repeats_or_gaps_and_limits_are_enforced(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let s3 = &w.s[2];
    let mut created = vec![w.p[2]];
    for n in 0..59 {
        let (id, _) =
            seed_product(&w.app, s3, &format!("m{n}"), None, true, &[(100, 1, true)]).await?;
        created.push(id);
    }
    let only_s3 = ProductFilter {
        store_id: Some(s3.store_id()),
        ..ProductFilter::default()
    };

    let mut tx = open(&w.app, &w.np).await?;
    let mut seen = Vec::new();
    let mut after = None;
    let mut sizes = Vec::new();
    loop {
        let page = tx.products_page(&only_s3, after, 24).await?;
        sizes.push(page.items.len());
        seen.extend(ids(&page.items));
        match page.next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    assert_eq!(sizes, [24, 24, 12]);
    let mut expected = created.clone();
    expected.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(
        seen, expected,
        "60 produtos, por id DESC, sem repetidos nem saltos"
    );

    // Sem filtro: os 60 de s3 + p1 + p2.
    let mut total = 0;
    let mut after = None;
    loop {
        let page = tx
            .products_page(&ProductFilter::default(), after, 24)
            .await?;
        total += page.items.len();
        match page.next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    assert_eq!(total, 62);

    // Página exata: 24 de 24 num limite de 24 → `next` só se houver mais.
    let last = tx.products_page(&only_s3, Some(expected[35]), 24).await?;
    assert_eq!(last.items.len(), 24);
    assert_eq!(last.next, None);

    // Limites: 0 → 1, 49 → 48.
    let p = tx.products_page(&only_s3, None, 0).await?;
    assert_eq!(p.items.len(), 1);
    assert_eq!(p.next, Some(expected[0]));
    assert_eq!(tx.products_page(&only_s3, None, 49).await?.items.len(), 48);

    // Mais de 200 categorias ou 100 ids → Validation.
    let cats = ProductFilter {
        category_ids: Some((0..201).map(|_| Uuid::now_v7()).collect()),
        ..ProductFilter::default()
    };
    assert!(matches!(
        tx.products_page(&cats, None, 24).await,
        Err(AppError::Validation(_))
    ));
    let cats = ProductFilter {
        category_ids: Some((0..200).map(|_| Uuid::now_v7()).collect()),
        ..ProductFilter::default()
    };
    assert!(tx.products_page(&cats, None, 24).await?.items.is_empty());
    let many: Vec<Uuid> = (0..101).map(|_| Uuid::now_v7()).collect();
    assert!(matches!(
        tx.products_by_ids(&many).await,
        Err(AppError::Validation(_))
    ));
    let mut hundred = expected.clone();
    hundred.extend((0..40).map(|_| Uuid::now_v7()));
    assert_eq!(tx.products_by_ids(&hundred).await?.len(), 60);
    assert!(tx.products_by_ids(&[]).await?.is_empty());
    tx.finish().await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn omnibus_previous_lowest_and_art53_zero_vat(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let s1 = &w.s[0];
    // Descida depois de uma subida: o anterior é o MÍNIMO dos 30 dias (1000), não o último (1200).
    let (down, dv) = seed_product(&w.app, s1, "desce", None, true, &[(1000, 1, true)]).await?;
    set_price(&w.app, s1, dv[0], 1200).await?;
    set_price(&w.app, s1, dv[0], 900).await?;
    // Subida.
    let (up, uv) = seed_product(&w.app, s1, "sobe", None, true, &[(1000, 1, true)]).await?;
    set_price(&w.app, s1, uv[0], 1100).await?;
    // 2 variantes ativas (uma desceu) + 1 inativa barata (não conta): o cartão não mostra.
    let (two, tv) = seed_product(
        &w.app,
        s1,
        "duas",
        None,
        true,
        &[(2000, 0, true), (1500, 2, true), (10, 5, false)],
    )
    .await?;
    set_price(&w.app, s1, tv[0], 1800).await?;
    let p1 = w.p[0];
    let p3 = w.p[2];

    let mut tx = open(&w.app, &w.np).await?;
    let cards = tx.products_by_ids(&[down, up, two, p1, p3]).await?;
    let get = |id: Uuid| {
        cards
            .iter()
            .find(|c| c.id == id)
            .ok_or_else(|| anyhow::anyhow!("{id} em falta"))
    };
    let c = get(down)?;
    assert_eq!(
        (c.price_from_cents, c.previous_lowest_cents),
        (900, Some(1000))
    );
    assert_eq!(get(up)?.previous_lowest_cents, None, "subida");
    assert_eq!(get(p1)?.previous_lowest_cents, None, "nunca mudou");
    let c = get(two)?;
    assert_eq!(
        (
            c.price_from_cents,
            c.variants_count,
            c.in_stock,
            c.previous_lowest_cents
        ),
        (1500, 2, true, None),
        "2 variantes: sem Omnibus no cartão"
    );
    // Página de produto: por preço; o Omnibus fica na variante que desceu.
    let p = tx
        .product_by_id(two)
        .await?
        .ok_or_else(|| anyhow::anyhow!("duas em falta"))?;
    let v: Vec<(i64, bool, Option<i64>)> = p
        .variants
        .iter()
        .map(|v| (v.price_cents, v.in_stock, v.previous_lowest_cents))
        .collect();
    assert_eq!(v, [(1500, true, None), (1800, false, Some(2000))]);
    assert_eq!(p.previous_lowest_cents, None);
    let p = tx
        .product_by_id(down)
        .await?
        .ok_or_else(|| anyhow::anyhow!("desce em falta"))?;
    assert_eq!(p.previous_lowest_cents, Some(1000));
    assert_eq!(p.variants[0].previous_lowest_cents, Some(1000));

    // Art. 53.º: IVA efetivo 0 na loja isenta; 23% nas outras.
    assert_eq!(get(p3)?.vat_rate_bps, 0);
    assert!(get(p3)?.store.vat_exempt_art53);
    assert_eq!(get(p1)?.vat_rate_bps, 2300);
    let p = tx
        .product_by_id(p3)
        .await?
        .ok_or_else(|| anyhow::anyhow!("p3 em falta"))?;
    assert_eq!(p.vat_rate_bps, 0);
    // Stock só como booleano: p2 tem 0 unidades.
    let p2 = tx.products_by_ids(&[w.p[1]]).await?;
    assert_eq!(p2.first().map(|c| c.in_stock), Some(false));
    tx.finish().await?;
    Ok(())
}

/// Loja com nome próprio (o `seed_store` usa o slug como nome).
async fn seed_named_store(
    app: &PgPool,
    t: &ResolvedTenant,
    name: &str,
    slug: &str,
) -> anyhow::Result<StoreScope> {
    let scope = StoreScope::for_tests(t.id(), Uuid::now_v7());
    let mut tx = begin_store_tx(app, &scope, &merchant()).await?;
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email)
         VALUES ($1, $2, $3, $4, $3, '500000000', $5, 'loja@test.invalid')",
        scope.store_id(),
        t.id().as_uuid(),
        name,
        slug,
        IBAN
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(scope)
}

async fn statement_timeout(tx: &mut PortalReadTx) -> anyhow::Result<String> {
    Ok(
        sqlx::query_scalar("SELECT current_setting('statement_timeout')::text")
            .fetch_one(tx.conn_for_tests())
            .await?,
    )
}

#[sqlx::test(migrations = "../migrations")]
async fn search_finds_unaccented_titles_per_channel_with_cursor_and_limits(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let [s1, s2, s3] = &w.s;
    let (pao_a, _) = seed_product(&w.app, s1, "Pão caseiro", None, true, &[(300, 1, true)]).await?;
    let (pao_b, _) =
        seed_product(&w.app, s2, "Pão de Mafra", None, true, &[(400, 1, true)]).await?;
    let (_, _) = seed_product(&w.app, s1, "Pão rascunho", None, false, &[(1, 1, true)]).await?;
    let mut many = Vec::new();
    for n in 0..30 {
        let (id, _) = seed_product(
            &w.app,
            s3,
            &format!("Pão nº {n}"),
            None,
            true,
            &[(100, 1, true)],
        )
        .await?;
        many.push(id);
    }

    // Canal A: só o pão da loja patrocinada pela Câmara A; sem acentos encontra "Pão".
    let mut tx = open(&w.app, &w.ca).await?;
    // Só termos de 1 carácter: página vazia sem ir à BD (o timeout nem chega a ser posto).
    let before = statement_timeout(&mut tx).await?;
    assert_ne!(before, "2s");
    let page = tx.search_products("a b c", None, 24).await?;
    assert!(page.items.is_empty() && page.next.is_none());
    assert_eq!(statement_timeout(&mut tx).await?, before);
    let page = tx.search_products("  pao ", None, 24).await?;
    assert_eq!(ids(&page.items), vec![pao_a]);
    assert_eq!(page.next, None);
    // O timeout fica ativo nesta transação.
    assert_eq!(statement_timeout(&mut tx).await?, "2s");
    assert!(
        tx.search_products("mafra", None, 24)
            .await?
            .items
            .is_empty()
    );
    // Comprimentos: slug da entidade > 128 e nome do cursor > 255 → Validation.
    let long_slug = "e".repeat(129);
    assert!(matches!(
        tx.stores_page(Some(&long_slug), None, 24).await,
        Err(AppError::Validation(_))
    ));
    assert!(
        tx.stores_page(Some(&"e".repeat(128)), None, 24)
            .await?
            .items
            .is_empty()
    );
    assert!(matches!(
        tx.stores_page(None, Some(("n".repeat(256), Uuid::nil())), 24)
            .await,
        Err(AppError::Validation(_))
    ));
    // Nome de 255 (o máximo da coluna) é um cursor válido.
    tx.stores_page(None, Some(("n".repeat(255), Uuid::nil())), 24)
        .await?;
    // O timeout fica ativo nesta transação.
    assert_eq!(statement_timeout(&mut tx).await?, "2s");
    tx.finish().await?;

    // Canal B: só o de B.
    let mut tx = open(&w.app, &w.cb).await?;
    assert_eq!(
        ids(&tx.search_products("PÃO", None, 24).await?.items),
        vec![pao_b]
    );
    tx.finish().await?;

    // Nacional: 32 pães publicados, em páginas de 12, sem repetidos nem saltos.
    let mut tx = open(&w.app, &w.np).await?;
    let mut seen = Vec::new();
    let mut sizes = Vec::new();
    let mut after = None;
    loop {
        let page = tx.search_products("pao", after, 12).await?;
        sizes.push(page.items.len());
        seen.extend(ids(&page.items));
        match page.next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    assert_eq!(sizes, [12, 12, 8]);
    let mut expected = many.clone();
    expected.extend([pao_a, pao_b]);
    expected.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(seen, expected);
    // Limites: 0 → 1; 100 → 48 (há só 32).
    let p = tx.search_products("pao", None, 0).await?;
    assert_eq!((p.items.len(), p.next), (1, Some(expected[0])));
    assert_eq!(tx.search_products("pao", None, 100).await?.items.len(), 32);
    // Texto inválido → Validation: vazio, 201 caracteres (não bytes), 9 termos.
    for bad in [
        String::new(),
        "   ".to_owned(),
        "ã".repeat(201),
        "pao ".repeat(9),
        "pao\0".to_owned(),
        "pao\u{1b}[0m".to_owned(),
        "pao\r\ncaseiro".to_owned(),
    ] {
        assert!(
            matches!(
                tx.search_products(&bad, None, 24).await,
                Err(AppError::Validation(_))
            ),
            "{bad:?}"
        );
    }
    assert!(
        tx.search_products(&"ã".repeat(200), None, 24)
            .await?
            .items
            .is_empty()
    );
    // Aspas, operadores e pontuação: só texto, nunca erro.
    for q in [
        "\"pão caseiro\"",
        "pao -caseiro OR mafra",
        "'; DROP TABLE products; --",
        "&& || !! :: ** ((",
        "pão:* & !x",
    ] {
        tx.search_products(q, None, 24).await?;
    }
    assert_eq!(
        ids(&tx.search_products("\"pão caseiro\"", None, 24).await?.items),
        vec![pao_a]
    );
    tx.finish().await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn stores_page_by_name_and_id_with_entity_filter(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    // 3 do mundo + 57 = 60 lojas no nacional; duas com o mesmo nome.
    let mut all: Vec<Uuid> = w.s.iter().map(|s| s.store_id()).collect();
    let twin_a = seed_named_store(&w.app, &w.np, "Igual", "igual-1").await?;
    let twin_b = seed_named_store(&w.app, &w.np, "Igual", "igual-2").await?;
    all.extend([twin_a.store_id(), twin_b.store_id()]);
    for n in 0..55 {
        let s = seed_named_store(&w.app, &w.np, &format!("Loja {n:02}"), &format!("l{n}")).await?;
        all.push(s.store_id());
    }

    let mut tx = open(&w.app, &w.np).await?;
    let mut seen = Vec::new();
    let mut sizes = Vec::new();
    let mut after = None;
    loop {
        let page = tx.stores_page(None, after, 24).await?;
        sizes.push(page.items.len());
        seen.extend(page.items.iter().map(|s| s.id));
        match page.next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    assert_eq!(sizes, [24, 24, 12]);
    let mut unique = seen.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 60, "sem repetidos");
    all.sort_unstable();
    assert_eq!(unique, all, "sem saltos");
    // As duas "Igual" seguidas, por id; o cursor parte entre elas sem perder nenhuma.
    let first = tx.stores_page(None, None, 1).await?;
    let mut cursor = first.next;
    let mut names = vec![first.items[0].name.clone()];
    while let Some(c) = cursor {
        let page = tx.stores_page(None, Some(c), 1).await?;
        names.extend(page.items.iter().map(|s| s.name.clone()));
        cursor = page.next;
    }
    assert_eq!(names.len(), 60);
    assert_eq!(names.iter().filter(|n| *n == "Igual").count(), 2);
    // Cursor no meio das gémeas (nome igual, id da primeira) → a segunda vem a seguir.
    let (lo, hi) = if twin_a.store_id() < twin_b.store_id() {
        (twin_a.store_id(), twin_b.store_id())
    } else {
        (twin_b.store_id(), twin_a.store_id())
    };
    let page = tx
        .stores_page(None, Some(("Igual".to_owned(), lo)), 1)
        .await?;
    assert_eq!(page.items.first().map(|s| s.id), Some(hi));
    // Limites: 0 → 1; 100 → 48.
    assert_eq!(tx.stores_page(None, None, 0).await?.items.len(), 1);
    assert_eq!(tx.stores_page(None, None, 100).await?.items.len(), 48);
    // Por entidade: só s1, uma vez, com os 2 selos pela ordem fixa.
    for slug in ["junta-j", "camara-a"] {
        let page = tx.stores_page(Some(slug), None, 48).await?;
        assert_eq!(
            page.items.iter().map(|s| s.id).collect::<Vec<_>>(),
            vec![w.s[0].store_id()],
            "{slug}"
        );
        let badges: Vec<Uuid> = page.items[0]
            .badges
            .iter()
            .map(|b| b.sponsor_entity_id)
            .collect();
        assert_eq!(badges, vec![w.camara_a, w.junta_j]);
        assert_eq!(page.next, None);
    }
    assert!(
        tx.stores_page(Some("nao-existe"), None, 48)
            .await?
            .items
            .is_empty()
    );
    tx.finish().await?;

    // Canal A: só s1 (co-patrocinada sai uma vez); entidade do canal B → vazio.
    let mut tx = open(&w.app, &w.ca).await?;
    let page = tx.stores_page(None, None, 48).await?;
    assert_eq!(
        page.items.iter().map(|s| s.id).collect::<Vec<_>>(),
        vec![w.s[0].store_id()]
    );
    assert!(
        tx.stores_page(Some("camara-b"), None, 48)
            .await?
            .items
            .is_empty()
    );
    tx.finish().await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn store_profile_only_in_its_channel_with_exactly_the_public_keys(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let s1 = &w.s[0];
    let mut tx = begin_store_tx(&w.app, s1, &merchant()).await?;
    sqlx::query!(
        "UPDATE stores SET phone = '+351210000000', geo_lat = 38.7223, geo_lng = -9.1393,
                           vacation_message = 'Voltamos já'
         WHERE id = $1",
        s1.store_id()
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // s2: sem loja física (sem morada de loja nem click & collect) → sem coordenadas.
    // s3: com morada de loja e sem click & collect → coordenadas arredondadas.
    for (scope, storefront, click_collect) in [
        (&w.s[1], json!({}), false),
        (
            &w.s[2],
            json!({"street": "Rua A, 1", "postal_code": "1000-001"}),
            false,
        ),
    ] {
        let mut tx = begin_store_tx(&w.app, scope, &merchant()).await?;
        let r = sqlx::query!(
            "UPDATE stores SET geo_lat = 41.14961, geo_lng = -8.61099, storefront_address = $2,
                               supports_click_collect = $3
             WHERE id = $1",
            scope.store_id(),
            storefront,
            click_collect
        )
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(r.rows_affected() == 1, "loja não mudou");
        tx.commit().await?;
    }

    // Canal B: s1 só é visível no A → None; inexistente → None; slug > 128 → Validation.
    let mut tx = open(&w.app, &w.cb).await?;
    assert_eq!(tx.store_profile_by_slug("s1").await?, None);
    assert_eq!(tx.store_profile_by_slug("nao-existe").await?, None);
    assert_eq!(tx.store_profile_by_slug(&"s".repeat(128)).await?, None);
    assert!(matches!(
        tx.store_profile_by_slug(&"s".repeat(129)).await,
        Err(AppError::Validation(_))
    ));
    let p2 = tx
        .store_profile_by_slug("s2")
        .await?
        .ok_or_else(|| anyhow::anyhow!("s2 fora do canal B"))?;
    assert_eq!((p2.geo_lat, p2.geo_lng), (None, None), "sem loja física");
    tx.finish().await?;
    let mut tx = open(&w.app, &w.np).await?;
    let p3 = tx
        .store_profile_by_slug("s3")
        .await?
        .ok_or_else(|| anyhow::anyhow!("s3 fora do nacional"))?;
    tx.finish().await?;
    assert_eq!(
        (p3.geo_lat.as_deref(), p3.geo_lng.as_deref()),
        (Some("41.150"), Some("-8.611")),
        "morada de loja: 3 casas"
    );

    let mut tx = open(&w.app, &w.ca).await?;
    assert_eq!(tx.store_profile_by_slug("s2").await?, None);
    let p = tx
        .store_profile_by_slug("s1")
        .await?
        .ok_or_else(|| anyhow::anyhow!("s1 fora do canal A"))?;
    tx.finish().await?;
    assert_eq!(p.store.id, s1.store_id());
    assert_eq!(p.store.nif, "500000000");
    assert_eq!(p.email, "loja@test.invalid");
    assert_eq!(p.phone.as_deref(), Some("+351210000000"));
    assert_eq!(
        (p.geo_lat.as_deref(), p.geo_lng.as_deref()),
        (Some("38.722"), Some("-9.139"))
    );
    let badges: Vec<Uuid> = p.store.badges.iter().map(|b| b.sponsor_entity_id).collect();
    assert_eq!(badges, vec![w.camara_a, w.junta_j]);

    let json = serde_json::to_value(&p)?;
    let mut keys: Vec<&str> = json
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "address_json",
            "badges",
            "business_hours",
            "email",
            "geo_lat",
            "geo_lng",
            "id",
            "is_vacation_mode",
            "legal_name",
            "name",
            "nif",
            "phone",
            "shipping_scope",
            "slug",
            "storefront_address",
            "storefront_dicofre",
            "supports_click_collect",
            "supports_local_courier",
            "supports_national_shipping",
            "tenant_id",
            "vacation_message",
            "vat_exempt_art53",
        ]
    );
    let text = json.to_string();
    for bad in [
        "iban",
        "_enc",
        "commission",
        "kyc",
        "billing",
        "terms",
        IBAN,
    ] {
        assert!(!text.contains(bad), "{bad}");
    }
    Ok(())
}
