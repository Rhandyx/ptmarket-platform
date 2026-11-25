//! Pesquisa: só o contrato, sem fornecedor.

use async_trait::async_trait;
use uuid::Uuid;

/// Contrato de pesquisa; devolve ids de documentos ordenados por relevância.
#[async_trait]
pub trait SearchBackend: Send + Sync {
    async fn search(&self, index: &str, query: &str, limit: u32) -> anyhow::Result<Vec<Uuid>>;
}

/// Implementação nula: devolve sempre erro.
pub struct NullSearch;

#[async_trait]
impl SearchBackend for NullSearch {
    async fn search(&self, _index: &str, _query: &str, _limit: u32) -> anyhow::Result<Vec<Uuid>> {
        anyhow::bail!("pesquisa não configurada")
    }
}
