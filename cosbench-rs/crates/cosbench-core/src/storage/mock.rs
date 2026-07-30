use super::{Storage, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Default)]
pub struct MockStorage {
    data: Arc<RwLock<HashMap<String, HashMap<String, Bytes>>>>,
    latency: Duration,
}

impl MockStorage {
    pub fn new(latency_us: u64) -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            latency: Duration::from_micros(latency_us),
        }
    }

    async fn delay(&self) {
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
    }
}

#[async_trait]
impl Storage for MockStorage {
    async fn create_container(&self, container: &str) -> Result<(), StorageError> {
        self.delay().await;
        self.data.write().entry(container.to_string()).or_default();
        Ok(())
    }

    async fn delete_container(&self, container: &str) -> Result<(), StorageError> {
        self.delay().await;
        self.data.write().remove(container);
        Ok(())
    }

    async fn put_object(
        &self,
        container: &str,
        object: &str,
        data: Bytes,
    ) -> Result<(), StorageError> {
        self.delay().await;
        let mut g = self.data.write();
        let bucket = g.entry(container.to_string()).or_default();
        bucket.insert(object.to_string(), data);
        Ok(())
    }

    async fn get_object(
        &self,
        container: &str,
        object: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Bytes, StorageError> {
        self.delay().await;
        let g = self.data.read();
        let bucket = g
            .get(container)
            .ok_or_else(|| StorageError::NotFound(container.into()))?;
        let obj = bucket
            .get(object)
            .ok_or_else(|| StorageError::NotFound(format!("{container}/{object}")))?;
        if let Some((start, end)) = range {
            let start = start as usize;
            let end = (end as usize).min(obj.len().saturating_sub(1));
            if start >= obj.len() || start > end {
                return Ok(Bytes::new());
            }
            Ok(obj.slice(start..=end))
        } else {
            Ok(obj.clone())
        }
    }

    async fn delete_object(&self, container: &str, object: &str) -> Result<(), StorageError> {
        self.delay().await;
        if let Some(bucket) = self.data.write().get_mut(container) {
            bucket.remove(object);
        }
        Ok(())
    }

    async fn list_objects(
        &self,
        container: &str,
        prefix: &str,
    ) -> Result<Vec<String>, StorageError> {
        self.delay().await;
        let g = self.data.read();
        let bucket = g
            .get(container)
            .ok_or_else(|| StorageError::NotFound(container.into()))?;
        let mut keys: Vec<String> = bucket
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        keys.sort();
        Ok(keys)
    }
}
