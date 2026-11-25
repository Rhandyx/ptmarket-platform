//! Armazenamento de ficheiros: só o contrato, sem fornecedor.

use async_trait::async_trait;

/// Contrato de armazenamento de objetos.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> anyhow::Result<()>;
    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
}

/// Implementação nula: devolve sempre erro.
pub struct NullStorage;

#[async_trait]
impl StorageBackend for NullStorage {
    async fn put(&self, _key: &str, _bytes: Vec<u8>) -> anyhow::Result<()> {
        anyhow::bail!("storage não configurado")
    }
    async fn get(&self, _key: &str) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("storage não configurado")
    }
    async fn delete(&self, _key: &str) -> anyhow::Result<()> {
        anyhow::bail!("storage não configurado")
    }
}
