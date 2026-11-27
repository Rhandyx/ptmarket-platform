//! RBAC de backoffice (cartões 02/19 e 03/13): papéis com âmbito e extractores.
//!
//! - Papéis (`user_roles`, 0018/0028): `super_admin` (global), `tenant_admin` (tenant),
//!   `sponsor_admin` (entidade patrocinadora), `merchant_owner` / `merchant_staff` (tenant + loja). A
//!   app só LÊ os papéis do próprio (RLS `own_select`, ator fixado); nunca os escreve.
//! - Painel único (spec 14 §8): o staff só tem sessão no `PLATFORM_ADMIN_HOST`, onde valem TODOS os
//!   papéis do utilizador; num Host de canal não vale nenhum. O âmbito vem do papel (loja, entidade
//!   ou plataforma), NUNCA do Host.
//! - Cache por pedido: `authenticate` lê-os UMA vez por pedido com sessão `user` e põe
//!   `StaffRoles` nas extensões; os extractores só leem dali.
//! - Ator (`Actor`/`AuditCtx`): com `super_admin` → `Admin`; senão com `sponsor_admin` ou
//!   `tenant_admin` → `Municipal`; senão → `Merchant` (sem papel também: os extractores recusam).
//! - Recusas: sem sessão `user` → 401; papel em falta → 403 + `Denied("rbac")`; 2FA em falta →
//!   403 com `Denied("mfa_required")`; loja sem papel nela (ou inexistente) → 404 + `Denied("idor")`
//!   (não revela que existe). Todas ficam na caixa negra (middleware).
//! - `RequireSuperAdmin` (cartão 20): host = `PLATFORM_ADMIN_HOST` E `super_admin` E `totp_enabled`
//!   E sessão com `mfa_verified_at`; qualquer falha → 404 + `Denied("superadmin_gate")` (a consola
//!   não se anuncia). Aplicado ao grupo `/api/v1/superadmin/*` inteiro por `superadmin_gate`
//!   (route_layer); os handlers leem `Extension<RequireSuperAdmin>` (sem ela → 500, falha fechado).
//! - Âmbito na BD (cartão 03/14, policies RESTRICTIVE da 0035): `RequireStoreRole`/`RequireStoreOwner`
//!   expõem `scope(): StoreScope` (→ `begin_store_tx`, GUC `app.store_id`) e `RequireSponsorAdmin`
//!   expõe `scope(): SponsorScope` (→ `begin_sponsor_tx`, GUC `app.sponsor_entity_id`). Os dois tipos
//!   só nascem nestes extractores (campos privados; fora do módulo só com `test-support`): o âmbito
//!   da transação é sempre o que o papel provou.
//!
//! REGRA (spec 07 §1, decisão 1 do épico 03): `tenant_admin` não tem acesso a lojas.
//!
//! REGRA (spec 07 §1, também para `sponsor_admin`): nenhum papel de loja ou de entidade recebe
//! `iban`, `invoicing_credentials_enc`, `eupago_split_key`, `stripe_account_id` nem
//! `custom_commission_bps`: nenhum tipo de resposta deste módulo tem esses campos.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{FromRequestParts, Path, Request, State},
    http::request::Parts,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    audit::{Actor, ActorType, AuditCtx, Denied},
    error::AppError,
    identity::{
        http::{SessionInfo, no_store},
        session::SessionKind,
    },
    state::AppState,
    tenancy::{
        ResolvedHost, TenantId,
        db::{begin_platform_tx, db_error},
    },
};

/// Papel sem o mínimo exigido.
pub const DENIED_RBAC: Denied = Denied("rbac");
/// Papel certo, mas a sessão não passou o 2FA.
pub const DENIED_MFA: Denied = Denied("mfa_required");
/// Recurso de outro tenant/loja (resposta 404).
pub const DENIED_IDOR: Denied = Denied("idor");
/// Consola de plataforma fechada (resposta 404).
pub const DENIED_SUPERADMIN: Denied = Denied("superadmin_gate");

/// Papel de backoffice (`user_roles.role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    SuperAdmin,
    TenantAdmin,
    SponsorAdmin,
    MerchantOwner,
    MerchantStaff,
}

impl Role {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "super_admin" => Some(Self::SuperAdmin),
            "tenant_admin" => Some(Self::TenantAdmin),
            "sponsor_admin" => Some(Self::SponsorAdmin),
            "merchant_owner" => Some(Self::MerchantOwner),
            "merchant_staff" => Some(Self::MerchantStaff),
            _ => None,
        }
    }

    fn is_merchant(self) -> bool {
        matches!(self, Self::MerchantOwner | Self::MerchantStaff)
    }
}

/// Um papel com o seu âmbito (`tenant_id`/`store_id`/`sponsor_entity_id` NULL conforme o CHECK
/// `user_roles_scope` da 0028).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct RoleGrant {
    pub role: Role,
    #[schema(value_type = Option<String>, format = "uuid")]
    pub tenant_id: Option<Uuid>,
    #[schema(value_type = Option<String>, format = "uuid")]
    pub store_id: Option<Uuid>,
    #[schema(value_type = Option<String>, format = "uuid")]
    pub sponsor_entity_id: Option<Uuid>,
}

/// Papéis do utilizador da sessão (cache por pedido, posta por `authenticate`).
#[derive(Debug, Clone)]
pub struct StaffRoles {
    user_id: Uuid,
    /// Tenant do `Host` (`None` = plataforma). Só decide SE os papéis valem aqui, nunca o âmbito.
    host: Option<TenantId>,
    roles: Arc<[RoleGrant]>,
    totp_enabled: bool,
}

/// Papéis e `totp_enabled` do utilizador (uma só leitura).
#[derive(Debug, Clone, Default)]
pub(crate) struct UserAccess {
    pub roles: Vec<RoleGrant>,
    pub totp_enabled: bool,
}

impl StaffRoles {
    pub(crate) fn new(user_id: Uuid, host: Option<TenantId>, access: UserAccess) -> Self {
        Self {
            user_id,
            host,
            roles: access.roles.into(),
            totp_enabled: access.totp_enabled,
        }
    }

    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// Papéis que valem neste `Host`: na plataforma, todos os do utilizador; num canal, nenhum
    /// (painel único: o staff só trabalha em `PLATFORM_ADMIN_HOST`).
    pub fn here(&self) -> impl Iterator<Item = &RoleGrant> {
        let on_platform = self.host.is_none();
        self.roles.iter().filter(move |_| on_platform)
    }

    /// 2FA obrigatório: TOTP ligado OU `super_admin`/`tenant_admin`/`sponsor_admin`. Sem a sessão
    /// elevada, todos os extractores (salvo `RequireStaffPreMfa`) recusam com 403.
    pub fn needs_mfa(&self) -> bool {
        self.totp_enabled
            || self.roles.iter().any(|g| {
                matches!(
                    g.role,
                    Role::SuperAdmin | Role::TenantAdmin | Role::SponsorAdmin
                )
            })
    }

    fn has_here(&self, role: Role) -> bool {
        self.here().any(|g| g.role == role)
    }

    /// Tipo de ator (ver o cabeçalho do módulo). Num canal não há papéis: `Merchant` (e os
    /// extractores recusam).
    pub(crate) fn actor_type(&self) -> ActorType {
        if self.has_here(Role::SuperAdmin) {
            ActorType::Admin
        } else if self.has_here(Role::SponsorAdmin) || self.has_here(Role::TenantAdmin) {
            ActorType::Municipal
        } else {
            ActorType::Merchant
        }
    }

    /// Classe da sessão pelo papel (decisão 4 do owner), não pelo Host: com `super_admin` →
    /// plataforma; os outros → staff. Decide a inatividade (`SessionKind::idle`).
    pub(crate) fn session_kind(&self) -> SessionKind {
        if self.has_here(Role::SuperAdmin) {
            SessionKind::Platform
        } else {
            SessionKind::Staff
        }
    }

    /// Pode iniciar sessão neste host: só na plataforma e com PELO MENOS um papel.
    pub(crate) fn may_log_in_here(&self) -> bool {
        self.here().next().is_some()
    }

    /// Papel de loja (`merchant_*`) nesta loja.
    fn store_grant(&self, store: Uuid) -> Option<&RoleGrant> {
        self.here()
            .find(|g| g.role.is_merchant() && g.store_id == Some(store))
    }
}

/// Lê os papéis e o `totp_enabled` do próprio `user_id` numa só query (transação de plataforma,
/// só leitura). A RLS (`self_select`, `own_select`) só mostra as linhas do ator quando
/// `app.actor_type` ∈ {merchant, municipal, admin}: o ator desta leitura é `merchant` (o tipo real só
/// se decide com os papéis; nada é gravado nela). Conta inexistente/inativa (ou `Uuid::nil()`, usado
/// para igualar o trabalho do login que falha) → vazio.
pub(crate) async fn load_roles(
    db: &PgPool,
    user_id: Uuid,
    request_id: Uuid,
) -> Result<UserAccess, AppError> {
    let reader = AuditCtx::new(
        ActorType::Merchant,
        Some(user_id),
        None,
        None,
        request_id,
        None,
        None,
    );
    let mut tx = begin_platform_tx(db, &reader).await?;
    let rows = sqlx::query!(
        r#"SELECT u.totp_enabled, r.role AS "role?", r.tenant_id, r.store_id, r.sponsor_entity_id
           FROM users u
           LEFT JOIN user_roles r ON r.user_id = u.id
           WHERE u.id = $1
           ORDER BY r.role, r.tenant_id NULLS FIRST, r.store_id NULLS FIRST,
                    r.sponsor_entity_id NULLS FIRST"#,
        user_id
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(db_error)?;
    tx.rollback().await?;
    let totp_enabled = rows.iter().any(|r| r.totp_enabled);
    let roles = rows
        .into_iter()
        .filter_map(|r| {
            Some(RoleGrant {
                role: Role::parse(r.role.as_deref()?)?,
                tenant_id: r.tenant_id,
                store_id: r.store_id,
                sponsor_entity_id: r.sponsor_entity_id,
            })
        })
        .collect();
    Ok(UserAccess {
        roles,
        totp_enabled,
    })
}

// ---------------------------------------------------------------------------------------------
// Extractores
// ---------------------------------------------------------------------------------------------

/// Recusa dos extractores: o erro e, se for recusa de acesso, o motivo para a caixa negra.
#[derive(Debug)]
pub struct RbacRejection {
    err: AppError,
    denied: Option<Denied>,
}

impl From<AppError> for RbacRejection {
    fn from(err: AppError) -> Self {
        Self { err, denied: None }
    }
}

impl IntoResponse for RbacRejection {
    fn into_response(self) -> Response {
        match self.denied {
            Some(d) => (Extension(d), self.err).into_response(),
            None => self.err.into_response(),
        }
    }
}

fn unauthorized() -> RbacRejection {
    AppError::Unauthorized.into()
}

fn denied(reason: Denied, err: AppError) -> RbacRejection {
    RbacRejection {
        err,
        denied: Some(reason),
    }
}

/// Se o extractor exige a sessão elevada por 2FA (quando `needs_mfa`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mfa {
    Enforce,
    /// Só `/staff/me` e as rotas de 2FA (cartão 20).
    NotYet,
}

/// Sessão `user` válida neste host (papéis + sessão); senão 401. Com `Mfa::Enforce`, 2FA exigido
/// e por fazer → 403 `mfa_required` (antes de qualquer outra verificação: não depende do recurso).
fn staff_parts(parts: &Parts, mfa: Mfa) -> Result<(StaffRoles, SessionInfo), RbacRejection> {
    let is_user = parts.extensions.get::<Actor>().is_some_and(|a| {
        matches!(
            a.actor_type,
            ActorType::Merchant | ActorType::Municipal | ActorType::Admin
        )
    });
    match (
        is_user,
        parts.extensions.get::<StaffRoles>(),
        parts.extensions.get::<SessionInfo>(),
    ) {
        (true, Some(r), Some(i)) => {
            if mfa == Mfa::Enforce && r.needs_mfa() && i.mfa_verified_at.is_none() {
                return Err(denied(DENIED_MFA, AppError::Forbidden));
            }
            Ok((r.clone(), *i))
        }
        _ => Err(unauthorized()),
    }
}

/// Papéis que valem neste `Host` (vazio → 403 `rbac`).
fn staff_here(roles: &StaffRoles, info: &SessionInfo) -> Result<RequireStaff, RbacRejection> {
    let here: Vec<RoleGrant> = roles.here().copied().collect();
    if here.is_empty() {
        return Err(denied(DENIED_RBAC, AppError::Forbidden));
    }
    Ok(RequireStaff {
        user_id: roles.user_id(),
        roles: here,
        mfa_verified: info.mfa_verified_at.is_some(),
    })
}

/// Qualquer papel no `PLATFORM_ADMIN_HOST` (sem sessão `user` → 401; 2FA exigido e por fazer → 403
/// `mfa_required`; sem papel → 403 `rbac`).
#[derive(Debug, Clone)]
pub struct RequireStaff {
    pub user_id: Uuid,
    /// Todos os papéis do utilizador (só há sessão de staff na plataforma).
    pub roles: Vec<RoleGrant>,
    pub mfa_verified: bool,
}

impl<S: Send + Sync> FromRequestParts<S> for RequireStaff {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let (roles, info) = staff_parts(parts, Mfa::Enforce)?;
        staff_here(&roles, &info)
    }
}

/// Como `RequireStaff`, mas ANTES do 2FA: só para `GET /api/v1/staff/me` e as rotas de 2FA do
/// cartão 20 (verificar/ativar TOTP). Nunca em rotas que leiam ou mudem dados de negócio.
#[derive(Debug, Clone)]
pub struct RequireStaffPreMfa(pub RequireStaff);

impl<S: Send + Sync> FromRequestParts<S> for RequireStaffPreMfa {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let (roles, info) = staff_parts(parts, Mfa::NotYet)?;
        staff_here(&roles, &info).map(Self)
    }
}

/// Parâmetro `name` do caminho como UUID. Ausente da rota → 500 (erro de programação); inválido →
/// 404 + `idor`.
async fn path_uuid<S: Send + Sync>(
    parts: &mut Parts,
    state: &S,
    name: &str,
) -> Result<Uuid, RbacRejection> {
    let Path(params) =
        Path::<std::collections::HashMap<String, String>>::from_request_parts(parts, state)
            .await
            .map_err(|_| denied(DENIED_IDOR, AppError::NotFound))?;
    let Some(raw) = params.get(name) else {
        return Err(
            AppError::Internal(anyhow::anyhow!("extractor numa rota sem {{{name}}}")).into(),
        );
    };
    Uuid::parse_str(raw).map_err(|_| denied(DENIED_IDOR, AppError::NotFound))
}

/// `tenant_admin` do tenant `{tenant_id}` da rota, com a sessão já elevada por 2FA. Sem
/// `tenant_admin` nenhum → 403 `rbac`; `tenant_admin` de outro tenant (ou `{tenant_id}` inválido) →
/// 404 `idor`; sem 2FA → 403 `mfa_required`.
#[derive(Debug, Clone, Copy)]
pub struct RequireTenantAdmin {
    pub user_id: Uuid,
    pub tenant_id: TenantId,
}

impl<S: Send + Sync> FromRequestParts<S> for RequireTenantAdmin {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // `tenant_admin` exige sempre 2FA (`needs_mfa`): `staff_parts` já recusou sem ele.
        let (roles, _) = staff_parts(parts, Mfa::Enforce)?;
        if !roles.has_here(Role::TenantAdmin) {
            return Err(denied(DENIED_RBAC, AppError::Forbidden));
        }
        let tenant = path_uuid(parts, state, "tenant_id").await?;
        if !roles
            .here()
            .any(|g| g.role == Role::TenantAdmin && g.tenant_id == Some(tenant))
        {
            return Err(denied(DENIED_IDOR, AppError::NotFound));
        }
        Ok(Self {
            user_id: roles.user_id(),
            tenant_id: TenantId::new(tenant),
        })
    }
}

/// O `RoleGrant` de loja (`merchant_*`) para `{store_id}`: loja, papel e o tenant do pedido
/// (`grant.tenant_id`, nunca o do Host). Sem papel nela (ou loja inexistente) → 404 + `idor`.
async fn store_grant<S: Send + Sync>(
    parts: &mut Parts,
    state: &S,
    roles: &StaffRoles,
) -> Result<(Uuid, Role, TenantId), RbacRejection> {
    let store_id = path_uuid(parts, state, "store_id").await?;
    let idor = || denied(DENIED_IDOR, AppError::NotFound);
    let grant = roles.store_grant(store_id).ok_or_else(idor)?;
    // O CHECK `user_roles_scope` garante tenant_id nos papéis de loja; sem ele, falha fechado.
    let tenant = grant.tenant_id.ok_or_else(idor)?;
    Ok((store_id, grant.role, TenantId::new(tenant)))
}

/// Âmbito de loja provado por `RequireStoreRole`/`RequireStoreOwner`: a loja e o tenant do papel.
/// É o único argumento que abre `begin_store_tx` (GUC `app.store_id`). Campos privados e sem
/// construtor público (fora deste módulo, só `for_tests` com a feature `test-support`):
///
/// ```compile_fail,E0451
/// # fn f(t: ptmarket_api::tenancy::TenantId, id: uuid::Uuid) {
/// let _ = ptmarket_api::identity::rbac::StoreScope { tenant: t, store_id: id };
/// # }
/// ```
///
/// Nem pelo extractor montado à mão:
///
/// ```compile_fail,E0451
/// # fn f(r: ptmarket_api::identity::rbac::RequireStoreRole) {
/// let _ = ptmarket_api::identity::rbac::RequireStoreRole { scope: r.scope(), ..r };
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreScope {
    tenant: TenantId,
    store_id: Uuid,
}

impl StoreScope {
    /// Só os extractores de loja deste módulo.
    fn new(tenant: TenantId, store_id: Uuid) -> Self {
        Self { tenant, store_id }
    }

    /// Só para testes de integração (`tests/`); não existe em `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn for_tests(tenant: TenantId, store_id: Uuid) -> Self {
        Self::new(tenant, store_id)
    }

    /// Tenant do papel (`user_roles.tenant_id`): o canal nacional do país da loja.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn store_id(&self) -> Uuid {
        self.store_id
    }
}

/// Âmbito de entidade patrocinadora provado por `RequireSponsorAdmin`. É o único argumento que abre
/// `begin_sponsor_tx` (GUC `app.sponsor_entity_id`). Campos privados e sem construtor público (fora
/// deste módulo, só `for_tests` com a feature `test-support`):
///
/// ```compile_fail,E0451
/// # fn f(id: uuid::Uuid) {
/// let _ = ptmarket_api::identity::rbac::SponsorScope { entity_id: id };
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SponsorScope {
    entity_id: Uuid,
}

impl SponsorScope {
    /// Só `RequireSponsorAdmin`.
    fn new(entity_id: Uuid) -> Self {
        Self { entity_id }
    }

    /// Só para testes de integração (`tests/`); não existe em `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn for_tests(entity_id: Uuid) -> Self {
        Self::new(entity_id)
    }

    pub fn entity_id(&self) -> Uuid {
        self.entity_id
    }
}

/// `merchant_owner`/`merchant_staff` da loja `{store_id}`. Sem papel nela ou loja inexistente → 404
/// + `Denied("idor")` (sem ler `stores`: o papel é a prova).
#[derive(Debug, Clone, Copy)]
pub struct RequireStoreRole {
    pub user_id: Uuid,
    pub store_id: Uuid,
    /// Tenant do pedido: o do papel (`user_roles.tenant_id`).
    pub tenant_id: TenantId,
    pub role: Role,
    scope: StoreScope,
}

impl RequireStoreRole {
    /// Âmbito para `begin_store_tx`.
    pub fn scope(&self) -> StoreScope {
        self.scope
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequireStoreRole {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let (roles, _) = staff_parts(parts, Mfa::Enforce)?;
        let (store_id, role, tenant_id) = store_grant(parts, state, &roles).await?;
        Ok(Self {
            user_id: roles.user_id(),
            store_id,
            tenant_id,
            role,
            scope: StoreScope::new(tenant_id, store_id),
        })
    }
}

/// Só `merchant_owner` da loja `{store_id}` com a sessão elevada por 2FA, SEMPRE (ações de
/// dinheiro/IBAN, ASVS L3): sem 2FA → 403 `mfa_required`. `merchant_staff` da loja → 403 `rbac`;
/// sem papel nela → 404 `idor`.
#[derive(Debug, Clone, Copy)]
pub struct RequireStoreOwner {
    pub user_id: Uuid,
    pub store_id: Uuid,
    /// Tenant do pedido: o do papel (`user_roles.tenant_id`).
    pub tenant_id: TenantId,
    scope: StoreScope,
}

impl RequireStoreOwner {
    /// Âmbito para `begin_store_tx`.
    pub fn scope(&self) -> StoreScope {
        self.scope
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequireStoreOwner {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let (roles, info) = staff_parts(parts, Mfa::Enforce)?;
        let (store_id, role, tenant_id) = store_grant(parts, state, &roles).await?;
        match role {
            Role::MerchantOwner if info.mfa_verified_at.is_none() => {
                Err(denied(DENIED_MFA, AppError::Forbidden))
            }
            Role::MerchantOwner => Ok(Self {
                user_id: roles.user_id(),
                store_id,
                tenant_id,
                scope: StoreScope::new(tenant_id, store_id),
            }),
            _ => Err(denied(DENIED_RBAC, AppError::Forbidden)),
        }
    }
}

/// `sponsor_admin` da entidade `{entity_id}` (`RoleGrant.sponsor_entity_id`) com a sessão elevada por
/// 2FA, SEMPRE: sem 2FA → 403 `mfa_required` (antes de olhar para o recurso). Sem `sponsor_admin`
/// nenhum → 403 `rbac`; outra entidade, entidade inexistente ou `{entity_id}` inválido → 404 + `idor`.
/// O tenant da transação (canal nacional do país da entidade) é resolvido pelo módulo que o usa.
#[derive(Debug, Clone, Copy)]
pub struct RequireSponsorAdmin {
    pub user_id: Uuid,
    scope: SponsorScope,
}

impl RequireSponsorAdmin {
    /// Âmbito para `begin_sponsor_tx`.
    pub fn scope(&self) -> SponsorScope {
        self.scope
    }

    pub fn entity_id(&self) -> Uuid {
        self.scope.entity_id
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequireSponsorAdmin {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // `sponsor_admin` exige sempre 2FA (`needs_mfa`): `staff_parts` já recusa sem ele; a
        // verificação abaixo repete-a para falhar fechado se `needs_mfa` mudar.
        let (roles, info) = staff_parts(parts, Mfa::Enforce)?;
        if !roles.has_here(Role::SponsorAdmin) {
            return Err(denied(DENIED_RBAC, AppError::Forbidden));
        }
        if info.mfa_verified_at.is_none() {
            return Err(denied(DENIED_MFA, AppError::Forbidden));
        }
        let entity = path_uuid(parts, state, "entity_id").await?;
        if !roles
            .here()
            .any(|g| g.role == Role::SponsorAdmin && g.sponsor_entity_id == Some(entity))
        {
            return Err(denied(DENIED_IDOR, AppError::NotFound));
        }
        Ok(Self {
            user_id: roles.user_id(),
            scope: SponsorScope::new(entity),
        })
    }
}

/// `super_admin` no `PLATFORM_ADMIN_HOST`, com TOTP ativo e a sessão elevada por 2FA. Qualquer
/// falha (anónimo incluído) → 404 + `Denied("superadmin_gate")`.
#[derive(Debug, Clone, Copy)]
pub struct RequireSuperAdmin {
    pub user_id: Uuid,
}

impl<S: Send + Sync> FromRequestParts<S> for RequireSuperAdmin {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let gate = || denied(DENIED_SUPERADMIN, AppError::NotFound);
        if !matches!(
            parts.extensions.get::<ResolvedHost>(),
            Some(ResolvedHost::Platform)
        ) {
            return Err(gate());
        }
        let (roles, info) = staff_parts(parts, Mfa::NotYet).map_err(|_| gate())?;
        let ok = info.tenant().is_none()
            && roles.host.is_none()
            && roles.has_here(Role::SuperAdmin)
            && roles.totp_enabled
            && info.mfa_verified_at.is_some();
        if !ok {
            return Err(gate());
        }
        Ok(Self {
            user_id: roles.user_id(),
        })
    }
}

/// Layer (`route_layer` do grupo `/api/v1/superadmin/*`, por dentro da caixa negra): corre
/// `RequireSuperAdmin` e põe-no nas extensões do pedido; recusa → 404 + `superadmin_gate`.
pub async fn superadmin_gate(req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    match RequireSuperAdmin::from_request_parts(&mut parts, &()).await {
        Ok(sa) => {
            parts.extensions.insert(sa);
            next.run(Request::from_parts(parts, body)).await
        }
        Err(rej) => rej.into_response(),
    }
}

/// Catch-all do grupo `/api/v1/superadmin/*` (caminho desconhecido, já depois do gate): o mesmo 404
/// e o mesmo `superadmin_gate` de uma recusa (não revela que rotas existem).
pub async fn superadmin_not_found() -> Response {
    denied(DENIED_SUPERADMIN, AppError::NotFound).into_response()
}

/// Identidade do `super_admin` (prova do gate).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SuperAdminWhoami {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub full_name: String,
}

/// Quem é o `super_admin` da sessão (leitura síncrona na caixa negra; alerta
/// `audit.superadmin_action`).
#[utoipa::path(
    get,
    path = "/api/v1/superadmin/whoami",
    tag = "superadmin",
    responses(
        (status = 200, description = "super_admin com 2FA feito neste host", body = SuperAdminWhoami),
        (status = 404, description = "Não encontrado (qualquer falha de acesso à consola)"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn superadmin_whoami(
    State(st): State<AppState>,
    Extension(sa): Extension<RequireSuperAdmin>,
    ctx: AuditCtx,
) -> Result<Response, AppError> {
    let mut tx = begin_platform_tx(&st.db_primary, &ctx).await?;
    let full_name = sqlx::query_scalar!("SELECT full_name FROM users WHERE id = $1", sa.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.rollback().await?;
    let Some(full_name) = full_name else {
        return Err(AppError::NotFound);
    };
    let body = SuperAdminWhoami {
        id: sa.user_id,
        full_name,
    };
    Ok(no_store(Json(body).into_response()))
}

/// Rota de prova (só com a feature `test-support`): `GET /api/v1/_test/stores/{store_id}`. Lê o
/// nome da loja dentro de `begin_store_tx` (filtro pela loja do papel + RLS); sem linha → 404.
#[cfg(feature = "test-support")]
pub async fn test_store(
    State(st): State<AppState>,
    r: RequireStoreRole,
    ctx: AuditCtx,
) -> Result<Response, AppError> {
    let mut tx = crate::tenancy::db::begin_store_tx(&st.db_primary, &r.scope(), &ctx).await?;
    let name = sqlx::query_scalar!("SELECT name FROM stores WHERE id = $1", r.store_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.rollback().await?;
    let Some(name) = name else {
        return Err(AppError::NotFound);
    };
    let body = serde_json::json!({
        "store_id": r.store_id,
        "tenant_id": r.tenant_id.as_uuid(),
        "role": r.role,
        "name": name,
    });
    Ok(no_store(Json(body).into_response()))
}

/// Corpo de `PUT /api/v1/_test/stores/{store_id}/name` (só `test-support`).
#[cfg(feature = "test-support")]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestStoreName {
    pub name: String,
}

/// Rota de prova (só `test-support`): muda o nome da loja dentro de `begin_store_tx`. Nome vazio
/// ou com mais de 255 caracteres → 422; loja sem linha → 404.
#[cfg(feature = "test-support")]
pub async fn test_store_name(
    State(st): State<AppState>,
    r: RequireStoreRole,
    ctx: AuditCtx,
    Json(body): Json<TestStoreName>,
) -> Result<Response, AppError> {
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 255 {
        return Err(AppError::Validation(vec![crate::error::FieldError {
            field: "name".to_owned(),
            message: "1 a 255 caracteres".to_owned(),
        }]));
    }
    let mut tx = crate::tenancy::db::begin_store_tx(&st.db_primary, &r.scope(), &ctx).await?;
    let done = sqlx::query!(
        "UPDATE stores SET name = $2 WHERE id = $1",
        r.store_id,
        name
    )
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;
    if done.rows_affected() != 1 {
        tx.rollback().await?;
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(no_store(
        Json(serde_json::json!({ "store_id": r.store_id, "name": name })).into_response(),
    ))
}

/// Rota de prova do `RequireSponsorAdmin` (só `test-support`): `GET /api/v1/_test/sponsors/{entity_id}`.
#[cfg(feature = "test-support")]
pub async fn test_sponsor(r: RequireSponsorAdmin) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "entity_id": r.entity_id(), "user_id": r.user_id }))
}

/// Rota de prova do `RequireStoreOwner` (só `test-support`).
#[cfg(feature = "test-support")]
pub async fn test_store_owner(r: RequireStoreOwner) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "store_id": r.store_id, "tenant_id": r.tenant_id.as_uuid() }))
}

/// Rota de prova do `RequireTenantAdmin` (só `test-support`): `/api/v1/_test/tenants/{tenant_id}/admin`.
#[cfg(feature = "test-support")]
pub async fn test_tenant_admin(r: RequireTenantAdmin) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "tenant_id": r.tenant_id.as_uuid() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(role: Role, t: Option<Uuid>, s: Option<Uuid>, e: Option<Uuid>) -> RoleGrant {
        RoleGrant {
            role,
            tenant_id: t,
            store_id: s,
            sponsor_entity_id: e,
        }
    }

    fn staff(host: Option<Uuid>, roles: Vec<RoleGrant>, totp: bool) -> StaffRoles {
        StaffRoles::new(
            Uuid::now_v7(),
            host.map(TenantId::for_tests),
            UserAccess {
                roles,
                totp_enabled: totp,
            },
        )
    }

    #[test]
    fn roles_only_count_on_the_platform_and_actor_comes_from_the_role() {
        let (t, l, e) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let merchant = grant(Role::MerchantOwner, Some(t), Some(l), None);
        let sponsor = grant(Role::SponsorAdmin, None, None, Some(e));
        let tadmin = grant(Role::TenantAdmin, Some(t), None, None);
        let sup = grant(Role::SuperAdmin, None, None, None);

        let m = staff(None, vec![merchant], false);
        assert!(m.may_log_in_here() && !m.needs_mfa());
        assert_eq!(m.actor_type(), ActorType::Merchant);
        assert_eq!(m.session_kind(), SessionKind::Staff);
        assert_eq!(m.store_grant(l).map(|g| g.tenant_id), Some(Some(t)));
        assert!(m.store_grant(Uuid::now_v7()).is_none());

        let s = staff(None, vec![sponsor, merchant], false);
        assert!(s.needs_mfa());
        assert_eq!(s.actor_type(), ActorType::Municipal);
        assert_eq!(s.session_kind(), SessionKind::Staff);
        assert_eq!(
            staff(None, vec![tadmin], false).actor_type(),
            ActorType::Municipal
        );

        let a = staff(None, vec![sup, sponsor], false);
        assert_eq!(a.actor_type(), ActorType::Admin);
        assert_eq!(a.session_kind(), SessionKind::Platform);

        // Num Host de canal nenhum papel vale (nem o de super_admin).
        let channel = staff(Some(t), vec![sup, merchant, tadmin], false);
        assert!(!channel.may_log_in_here());
        assert_eq!(channel.actor_type(), ActorType::Merchant);
        assert!(channel.store_grant(l).is_none());

        // Sem papéis não entra; TOTP ligado exige 2FA.
        let none = staff(None, vec![], true);
        assert!(!none.may_log_in_here() && none.needs_mfa());
    }
}
