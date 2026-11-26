//! RBAC de backoffice (cartão 02/19): papéis com âmbito e extractores.
//!
//! - Papéis (`user_roles`, 0018): `super_admin` (global), `tenant_admin` (tenant), `merchant_owner`
//!   / `merchant_staff` (tenant + loja). A app só LÊ os papéis do próprio (RLS `own_select`, ator
//!   fixado); nunca os escreve.
//! - Cache por pedido: `authenticate` lê-os UMA vez por pedido com sessão `user` e põe
//!   `StaffRoles` nas extensões; os extractores só leem dali.
//! - Ator (`Actor`/`AuditCtx`): `super_admin` no host de plataforma → `Admin`; `tenant_admin` do
//!   tenant do `Host` → `Municipal`; senão → `Merchant` (sem papel aqui também: os extractores
//!   recusam). Um `super_admin` num host de tenant NUNCA é `Admin`.
//! - Recusas: sem sessão `user` → 401; papel em falta → 403 + `Denied("rbac")`; 2FA em falta →
//!   403 com `Denied("mfa_required")`; loja de outro tenant ou sem papel nela → 404 + `Denied("idor")`
//!   (não revela que existe). Todas ficam na caixa negra (middleware).
//! - `RequireSuperAdmin` é do cartão 20 (com 2FA): não criar aqui atalho nenhum.
//!
//! REGRA (spec 07 §1): `tenant_admin` NUNCA recebe `iban`, `invoicing_credentials_enc`,
//! `eupago_split_key` nem `stripe_account_id` de uma loja. Os handlers que mostram lojas a um
//! `tenant_admin` devolvem `StoreViewForTenantAdmin` (sem esses campos), nunca a linha inteira.

use std::sync::Arc;

use axum::{
    Extension,
    extract::{FromRequestParts, Path},
    http::request::Parts,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    audit::{Actor, ActorType, AuditCtx, Denied},
    error::AppError,
    identity::http::{SessionInfo, Sessions},
    tenancy::{
        TenantId, begin_tenant_tx,
        db::{begin_platform_tx, db_error},
    },
};

/// Papel sem o mínimo exigido.
pub const DENIED_RBAC: Denied = Denied("rbac");
/// Papel certo, mas a sessão não passou o 2FA.
pub const DENIED_MFA: Denied = Denied("mfa_required");
/// Recurso de outro tenant/loja (resposta 404).
pub const DENIED_IDOR: Denied = Denied("idor");

/// Papel de backoffice (`user_roles.role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    SuperAdmin,
    TenantAdmin,
    MerchantOwner,
    MerchantStaff,
}

impl Role {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "super_admin" => Some(Self::SuperAdmin),
            "tenant_admin" => Some(Self::TenantAdmin),
            "merchant_owner" => Some(Self::MerchantOwner),
            "merchant_staff" => Some(Self::MerchantStaff),
            _ => None,
        }
    }

    fn is_merchant(self) -> bool {
        matches!(self, Self::MerchantOwner | Self::MerchantStaff)
    }
}

/// Um papel com o seu âmbito (`tenant_id`/`store_id` NULL conforme o CHECK da 0018).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct RoleGrant {
    pub role: Role,
    #[schema(value_type = Option<String>, format = "uuid")]
    pub tenant_id: Option<Uuid>,
    #[schema(value_type = Option<String>, format = "uuid")]
    pub store_id: Option<Uuid>,
}

/// Papéis do utilizador da sessão (cache por pedido, posta por `authenticate`).
#[derive(Debug, Clone)]
pub struct StaffRoles {
    user_id: Uuid,
    /// Tenant do `Host` (`None` = plataforma).
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

    /// Papéis no âmbito do `Host`: no tenant, os desse tenant; na plataforma, só `super_admin`
    /// (o único com `tenant_id` NULL).
    pub fn here(&self) -> impl Iterator<Item = &RoleGrant> {
        let host = self.host.map(|t| t.as_uuid());
        self.roles.iter().filter(move |g| g.tenant_id == host)
    }

    /// 2FA obrigatório: TOTP ligado OU `super_admin`/`tenant_admin` em qualquer âmbito. Sem a
    /// sessão elevada, todos os extractores (salvo `RequireStaffPreMfa`) recusam com 403.
    pub fn needs_mfa(&self) -> bool {
        self.totp_enabled
            || self
                .roles
                .iter()
                .any(|g| matches!(g.role, Role::SuperAdmin | Role::TenantAdmin))
    }

    fn has_here(&self, role: Role) -> bool {
        self.here().any(|g| g.role == role)
    }

    /// Tipo de ator neste host (ver o cabeçalho do módulo).
    pub(crate) fn actor_type(&self) -> ActorType {
        match self.host {
            None if self.has_here(Role::SuperAdmin) => ActorType::Admin,
            Some(_) if self.has_here(Role::TenantAdmin) => ActorType::Municipal,
            _ => ActorType::Merchant,
        }
    }

    /// Pode iniciar sessão neste host: no tenant, qualquer papel dele; na plataforma, só
    /// `super_admin`.
    pub(crate) fn may_log_in_here(&self) -> bool {
        self.here().next().is_some()
    }

    /// Papel de loja (`merchant_*`) nesta loja do tenant do `Host`.
    fn store_role(&self, store: Uuid) -> Option<Role> {
        self.here()
            .find(|g| g.role.is_merchant() && g.store_id == Some(store))
            .map(|g| g.role)
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
        r#"SELECT u.totp_enabled, r.role AS "role?", r.tenant_id, r.store_id
           FROM users u
           LEFT JOIN user_roles r ON r.user_id = u.id
           WHERE u.id = $1
           ORDER BY r.role, r.tenant_id NULLS FIRST, r.store_id NULLS FIRST"#,
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

/// Papéis no âmbito do `Host` (vazio → 403 `rbac`).
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

/// Qualquer papel no âmbito do `Host` (sem sessão `user` → 401; 2FA exigido e por fazer → 403
/// `mfa_required`; sem papel aqui → 403 `rbac`).
#[derive(Debug, Clone)]
pub struct RequireStaff {
    pub user_id: Uuid,
    /// Papéis no âmbito do `Host`.
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

/// `tenant_admin` do tenant do `Host` com a sessão já elevada por 2FA (sem papel → 403 `rbac`;
/// sem 2FA → 403 `mfa_required`).
#[derive(Debug, Clone, Copy)]
pub struct RequireTenantAdmin {
    pub user_id: Uuid,
    pub tenant_id: TenantId,
}

impl<S: Send + Sync> FromRequestParts<S> for RequireTenantAdmin {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // `tenant_admin` exige sempre 2FA (`needs_mfa`): `staff_parts` já recusou sem ele.
        let (roles, info) = staff_parts(parts, Mfa::Enforce)?;
        let Some(tenant_id) = info.tenant() else {
            return Err(denied(DENIED_RBAC, AppError::Forbidden));
        };
        if !roles.has_here(Role::TenantAdmin) {
            return Err(denied(DENIED_RBAC, AppError::Forbidden));
        }
        Ok(Self {
            user_id: roles.user_id(),
            tenant_id,
        })
    }
}

/// Como o utilizador chega à loja.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreAccess {
    /// `merchant_owner`/`merchant_staff` desta loja.
    Merchant(Role),
    /// `tenant_admin` do tenant da loja (2FA verificado): só `StoreViewForTenantAdmin`.
    TenantAdmin,
}

/// `{store_id}` do caminho (outros parâmetros são ignorados). Inválido → 404 + `idor`.
async fn path_store<S: Send + Sync>(parts: &mut Parts, state: &S) -> Result<Uuid, RbacRejection> {
    let Path(params) =
        Path::<std::collections::HashMap<String, String>>::from_request_parts(parts, state)
            .await
            .map_err(|_| denied(DENIED_IDOR, AppError::NotFound))?;
    let Some(raw) = params.get("store_id") else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "RequireStoreRole numa rota sem {{store_id}}"
        ))
        .into());
    };
    Uuid::parse_str(raw).map_err(|_| denied(DENIED_IDOR, AppError::NotFound))
}

/// A loja existe no tenant do `Host` (transação do tenant: RLS + filtro explícito).
///
/// Leitura de `stores` a partir de `identity`: ainda não há API pública de lojas (épico de
/// catálogo/lojas); quando houver, trocar por ela.
async fn store_in_tenant(
    parts: &Parts,
    tenant: TenantId,
    store: Uuid,
) -> Result<bool, RbacRejection> {
    let sessions = parts.extensions.get::<Sessions>().cloned().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("Sessions em falta: rota sem authenticate"))
    })?;
    let ctx = parts.extensions.get::<AuditCtx>().cloned().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "AuditCtx em falta: rota fora da caixa negra"
        ))
    })?;
    let res = async {
        let mut tx = begin_tenant_tx(sessions.db(), tenant, &ctx).await?;
        let found = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM stores WHERE id = $1 AND tenant_id = $2) AS "found!""#,
            store,
            tenant.as_uuid()
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.rollback().await?;
        Ok::<bool, AppError>(found)
    }
    .await;
    res.map_err(RbacRejection::from)
}

/// `merchant_owner`/`merchant_staff` da loja `{store_id}` ou `tenant_admin` do tenant dela (com
/// 2FA). Loja de outro tenant, inexistente ou sem papel nela → 404 + `Denied("idor")`.
#[derive(Debug, Clone, Copy)]
pub struct RequireStoreRole {
    pub user_id: Uuid,
    pub store_id: Uuid,
    pub access: StoreAccess,
}

impl<S: Send + Sync> FromRequestParts<S> for RequireStoreRole {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let (roles, info) = staff_parts(parts, Mfa::Enforce)?;
        let store_id = path_store(parts, state).await?;
        let idor = || denied(DENIED_IDOR, AppError::NotFound);
        if let Some(role) = roles.store_role(store_id) {
            return Ok(Self {
                user_id: roles.user_id(),
                store_id,
                access: StoreAccess::Merchant(role),
            });
        }
        let Some(tenant) = info.tenant() else {
            return Err(idor());
        };
        if !roles.has_here(Role::TenantAdmin) {
            return Err(idor());
        }
        if !store_in_tenant(parts, tenant, store_id).await? {
            return Err(idor());
        }
        Ok(Self {
            user_id: roles.user_id(),
            store_id,
            access: StoreAccess::TenantAdmin,
        })
    }
}

/// Só `merchant_owner` da loja `{store_id}` com a sessão elevada por 2FA, SEMPRE (ações de
/// dinheiro/IBAN, ASVS L3): sem 2FA → 403 `mfa_required`. Outro papel na loja ou `tenant_admin` do
/// tenant → 403 `rbac`; sem papel nenhum → 404 `idor`.
#[derive(Debug, Clone, Copy)]
pub struct RequireStoreOwner {
    pub user_id: Uuid,
    pub store_id: Uuid,
}

impl<S: Send + Sync> FromRequestParts<S> for RequireStoreOwner {
    type Rejection = RbacRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let (roles, info) = staff_parts(parts, Mfa::Enforce)?;
        let store_id = path_store(parts, state).await?;
        match roles.store_role(store_id) {
            Some(Role::MerchantOwner) if info.mfa_verified_at.is_none() => {
                Err(denied(DENIED_MFA, AppError::Forbidden))
            }
            Some(Role::MerchantOwner) => Ok(Self {
                user_id: roles.user_id(),
                store_id,
            }),
            // Sem consulta à loja: o 403 não depende de ela existir.
            Some(_) => Err(denied(DENIED_RBAC, AppError::Forbidden)),
            None if roles.has_here(Role::TenantAdmin) => {
                Err(denied(DENIED_RBAC, AppError::Forbidden))
            }
            None => Err(denied(DENIED_IDOR, AppError::NotFound)),
        }
    }
}

/// Loja vista por um `tenant_admin`: SEM `iban`, `invoicing_credentials_enc`, `eupago_split_key` e
/// `stripe_account_id` (spec 07 §1). Não acrescentar esses campos.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StoreViewForTenantAdmin {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    #[schema(value_type = String, format = "uuid")]
    pub tenant_id: Uuid,
    pub name: String,
    pub slug: String,
    pub legal_name: String,
    pub nif: String,
    pub email: String,
    pub phone: Option<String>,
    pub kyc_verified: bool,
    pub publish_to_national_portal: bool,
    pub is_active: bool,
}

/// Rota de prova (só com a feature `test-support`): `GET /api/v1/_test/stores/{store_id}`.
#[cfg(feature = "test-support")]
pub async fn test_store(r: RequireStoreRole) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "store_id": r.store_id,
        "access": match r.access {
            StoreAccess::Merchant(_) => "merchant",
            StoreAccess::TenantAdmin => "tenant_admin",
        },
    }))
}

/// Rota de prova do `RequireStoreOwner` (só `test-support`).
#[cfg(feature = "test-support")]
pub async fn test_store_owner(r: RequireStoreOwner) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "store_id": r.store_id }))
}

/// Rota de prova do `RequireTenantAdmin` (só `test-support`).
#[cfg(feature = "test-support")]
pub async fn test_tenant_admin(r: RequireTenantAdmin) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "tenant_id": r.tenant_id.as_uuid() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(role: Role, t: Option<Uuid>, s: Option<Uuid>) -> RoleGrant {
        RoleGrant {
            role,
            tenant_id: t,
            store_id: s,
        }
    }

    fn access(roles: Vec<RoleGrant>) -> UserAccess {
        UserAccess {
            roles,
            totp_enabled: false,
        }
    }

    #[test]
    fn actor_type_depends_on_host() {
        let t = Uuid::now_v7();
        let l = Uuid::now_v7();
        let roles = vec![
            grant(Role::SuperAdmin, None, None),
            grant(Role::MerchantOwner, Some(t), Some(l)),
        ];
        let platform = StaffRoles::new(Uuid::now_v7(), None, access(roles.clone()));
        assert_eq!(platform.actor_type(), ActorType::Admin);
        let tenant = StaffRoles::new(Uuid::now_v7(), Some(TenantId::for_tests(t)), access(roles));
        assert_eq!(tenant.actor_type(), ActorType::Merchant);
        assert_eq!(tenant.store_role(l), Some(Role::MerchantOwner));
        let admin = StaffRoles::new(
            Uuid::now_v7(),
            Some(TenantId::for_tests(t)),
            access(vec![grant(Role::TenantAdmin, Some(t), None)]),
        );
        assert_eq!(admin.actor_type(), ActorType::Municipal);
        let other = StaffRoles::new(
            Uuid::now_v7(),
            Some(TenantId::for_tests(Uuid::now_v7())),
            access(vec![grant(Role::TenantAdmin, Some(t), None)]),
        );
        assert!(!other.may_log_in_here());
        assert!(other.needs_mfa());
        let totp = StaffRoles::new(
            Uuid::now_v7(),
            None,
            UserAccess {
                roles: vec![],
                totp_enabled: true,
            },
        );
        assert!(totp.needs_mfa() && !platform_merchant_only(t, l).needs_mfa());
    }

    fn platform_merchant_only(t: Uuid, l: Uuid) -> StaffRoles {
        StaffRoles::new(
            Uuid::now_v7(),
            None,
            access(vec![grant(Role::MerchantStaff, Some(t), Some(l))]),
        )
    }
}
