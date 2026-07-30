use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

pub mod mock;
#[cfg(feature = "s3")]
pub mod s3;
pub mod swift;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("{0}")]
    Other(String),
}

impl StorageError {
    pub fn other(e: impl ToString) -> Self {
        Self::Other(e.to_string())
    }
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn create_container(&self, container: &str) -> Result<(), StorageError>;
    async fn delete_container(&self, container: &str) -> Result<(), StorageError>;
    async fn put_object(&self, container: &str, object: &str, data: Bytes) -> Result<(), StorageError>;
    async fn get_object(
        &self,
        container: &str,
        object: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Bytes, StorageError>;
    async fn delete_object(&self, container: &str, object: &str) -> Result<(), StorageError>;
    async fn list_objects(&self, container: &str, prefix: &str) -> Result<Vec<String>, StorageError>;
}

pub use mock::MockStorage;
