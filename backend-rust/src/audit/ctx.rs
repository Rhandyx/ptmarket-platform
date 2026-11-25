//! `AuditCtx`: quem faz o pedido (spec 13 §3.1). Sem ele não se abre transação nenhuma.
//!
//! Campos privados e sem `Default`: só nasce no extractor HTTP (cartão 07, `pub(crate)`), em
//! `AuditCtx::system` (jobs) ou, com a feature `test-support`, em `AuditCtx::for_tests`.
//! Não existe construtor, flag ou variável de ambiente que desligue a auditoria.

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use uuid::Uuid;

/// Tipo de ator. `'db'` não existe aqui: é exclusivo do trigger da BD (mutações fora da app).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorType {
    Customer,
    Merchant,
    Municipal,
    Admin,
    System,
    ApiKey,
    Anonymous,
}

impl ActorType {
    /// Valor gravado em `app.actor_type` (o mesmo do CHECK de `audit.audit_events.actor_type`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Customer => "customer",
            Self::Merchant => "merchant",
            Self::Municipal => "municipal",
            Self::Admin => "admin",
            Self::System => "system",
            Self::ApiKey => "api_key",
            Self::Anonymous => "anonymous",
        }
    }
}

/// Contexto de ator de um pedido ou job. Um `clone` partilha a marca `recorded`: o middleware
/// (cartão 07) guarda uma cópia e vê se `audit::record` foi chamado durante o pedido.
#[derive(Debug, Clone)]
pub struct AuditCtx {
    actor_type: ActorType,
    actor_id: Option<Uuid>,
    actor_label: Option<String>,
    impersonator_id: Option<Uuid>,
    request_id: Uuid,
    ip: Option<IpAddr>,
    user_agent_hash: Option<[u8; 32]>,
    recorded: Arc<AtomicBool>,
}

impl AuditCtx {
    /// Construtor do extractor HTTP (cartão 07).
    #[allow(
        dead_code,
        reason = "consumido pelo extractor HTTP do cartão 07 e por for_tests"
    )]
    #[allow(
        clippy::too_many_arguments,
        reason = "um argumento por campo do ator; só o extractor o chama"
    )]
    pub(crate) fn new(
        actor_type: ActorType,
        actor_id: Option<Uuid>,
        actor_label: Option<String>,
        impersonator_id: Option<Uuid>,
        request_id: Uuid,
        ip: Option<IpAddr>,
        user_agent_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            actor_type,
            actor_id,
            actor_label,
            impersonator_id,
            request_id,
            ip,
            user_agent_hash,
            recorded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Ator de um job/processo interno: `system` com o nome do job em `actor_label`.
    pub fn system(job: &'static str) -> Self {
        Self {
            actor_type: ActorType::System,
            actor_id: None,
            actor_label: Some(job.to_owned()),
            impersonator_id: None,
            request_id: Uuid::now_v7(),
            ip: None,
            user_agent_hash: None,
            recorded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Só para testes de integração (`tests/`); não existe em `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn for_tests(
        actor_type: ActorType,
        actor_id: Option<Uuid>,
        impersonator_id: Option<Uuid>,
        ip: Option<IpAddr>,
    ) -> Self {
        Self::new(
            actor_type,
            actor_id,
            None,
            impersonator_id,
            Uuid::now_v7(),
            ip,
            None,
        )
    }

    pub fn actor_type(&self) -> ActorType {
        self.actor_type
    }

    pub fn actor_id(&self) -> Option<Uuid> {
        self.actor_id
    }

    pub fn actor_label(&self) -> Option<&str> {
        self.actor_label.as_deref()
    }

    pub fn impersonator_id(&self) -> Option<Uuid> {
        self.impersonator_id
    }

    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    pub fn user_agent_hash(&self) -> Option<&[u8; 32]> {
        self.user_agent_hash.as_ref()
    }

    /// `true` depois de um `audit::record` bem-sucedido com este contexto (ou um clone dele).
    pub fn is_recorded(&self) -> bool {
        self.recorded.load(Ordering::Acquire)
    }

    pub(crate) fn mark_recorded(&self) {
        self.recorded.store(true, Ordering::Release);
    }

    /// `user_agent_hash` em hex minúsculo (o formato que `audit_append` descodifica); `""` se não houver.
    pub(crate) fn user_agent_hash_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let Some(h) = &self.user_agent_hash else {
            return String::new();
        };
        let mut s = String::with_capacity(64);
        for b in h {
            s.push(char::from(HEX[usize::from(b >> 4)]));
            s.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_type_never_db() {
        let all = [
            ActorType::Customer,
            ActorType::Merchant,
            ActorType::Municipal,
            ActorType::Admin,
            ActorType::System,
            ActorType::ApiKey,
            ActorType::Anonymous,
        ];
        assert!(all.iter().all(|a| a.as_str() != "db"));
    }

    #[test]
    fn system_ctx_has_job_label_and_fresh_flag() {
        let c = AuditCtx::system("outbox_relay");
        assert_eq!(c.actor_type(), ActorType::System);
        assert_eq!(c.actor_label(), Some("outbox_relay"));
        assert!(!c.is_recorded());
        let clone = c.clone();
        c.mark_recorded();
        assert!(clone.is_recorded(), "o clone partilha a marca");
    }

    #[test]
    fn user_agent_hash_hex_is_lowercase_64_chars() {
        let mut h = [0u8; 32];
        h[0] = 0xab;
        h[31] = 0x0f;
        let c = AuditCtx::new(
            ActorType::Customer,
            None,
            None,
            None,
            Uuid::nil(),
            None,
            Some(h),
        );
        let hex = c.user_agent_hash_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("ab00"));
        assert!(hex.ends_with("000f"));
        assert_eq!(AuditCtx::system("x").user_agent_hash_hex(), "");
    }
}
