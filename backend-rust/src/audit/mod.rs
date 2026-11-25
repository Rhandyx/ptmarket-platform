//! Caixa negra na app (spec 13): `AuditCtx` obrigatório em todas as transações e `record`,
//! a única função para eventos semânticos. As mutações já ficam no L1 pelo trigger da BD.

pub mod ctx;
pub mod record;

pub use ctx::{ActorType, AuditCtx};
pub use record::{AuditEvent, Outcome, record};
