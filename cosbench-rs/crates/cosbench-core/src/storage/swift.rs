//! OpenStack Swift storage via REST + X-Auth-Token.

use super::{Storage, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use std::time::Duration;

pub struct SwiftStorage {
    client: reqwest::Client,
    base: String,
    token: String,
    #[allow(dead_code)]
    timeout: Duration,
}

impl SwiftStorage {
    pub fn new(base: String, token: String, timeout: Duration) -> Result<Self, StorageError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(StorageError::other)?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_string(),
            token,
            timeout,
        })
    }

    fn url(&self, container: &str, object: Option<&str>) -> String {
        match object {
            Some(o) => format!("{}/{}/{}", self.base, container, o),
            None => format!("{}/{}", self.base, container),
        }
    }
}

#[async_trait]
impl Storage for SwiftStorage {
    async fn create_container(&self, container: &str) -> Result<(), StorageError> {
        let resp = self
            .client
            .put(self.url(container, None))
            .header("X-Auth-Token", &self.token)
            .send()
            .await
            .map_err(StorageError::other)?;
        if resp.status().is_success() || resp.status().as_u16() == 202 {
            Ok(())
        } else {
            Err(StorageError::other(format!(
                "swift create container {}: {}",
                container,
                resp.status()
            )))
        }
    }

    async fn delete_container(&self, container: &str) -> Result<(), StorageError> {
        let resp = self
            .client
            .delete(self.url(container, None))
            .header("X-Auth-Token", &self.token)
            .send()
            .await
            .map_err(StorageError::other)?;
        if resp.status().is_success() || resp.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(StorageError::other(format!(
                "swift delete container {}: {}",
                container,
                resp.status()
            )))
        }
    }

    async fn put_object(
        &self,
        container: &str,
        object: &str,
        data: Bytes,
    ) -> Result<(), StorageError> {
        let len = data.len();
        let resp = self
            .client
            .put(self.url(container, Some(object)))
            .header("X-Auth-Token", &self.token)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", len.to_string())
            .body(data)
            .send()
            .await
            .map_err(StorageError::other)?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(StorageError::other(format!(
                "swift put {}/{}: {}",
                container,
                object,
                resp.status()
            )))
        }
    }

    async fn get_object(
        &self,
        container: &str,
        object: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Bytes, StorageError> {
        let mut req = self
            .client
            .get(self.url(container, Some(object)))
            .header("X-Auth-Token", &self.token);
        if let Some((a, b)) = range {
            req = req.header("Range", format!("bytes={a}-{b}"));
        }
        let resp = req.send().await.map_err(StorageError::other)?;
        if resp.status().as_u16() == 404 {
            return Err(StorageError::NotFound(format!("{container}/{object}")));
        }
        if !resp.status().is_success() {
            return Err(StorageError::other(format!(
                "swift get {}/{}: {}",
                container,
                object,
                resp.status()
            )));
        }
        let b = resp.bytes().await.map_err(StorageError::other)?;
        Ok(b)
    }

    async fn delete_object(&self, container: &str, object: &str) -> Result<(), StorageError> {
        let resp = self
            .client
            .delete(self.url(container, Some(object)))
            .header("X-Auth-Token", &self.token)
            .send()
            .await
            .map_err(StorageError::other)?;
        if resp.status().is_success() || resp.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(StorageError::other(format!(
                "swift delete {}/{}: {}",
                container,
                object,
                resp.status()
            )))
        }
    }

    async fn list_objects(
        &self,
        container: &str,
        prefix: &str,
    ) -> Result<Vec<String>, StorageError> {
        let url = format!("{}?prefix={}", self.url(container, None), prefix);
        let resp = self
            .client
            .get(url)
            .header("X-Auth-Token", &self.token)
            .send()
            .await
            .map_err(StorageError::other)?;
        if resp.status().as_u16() == 404 {
            return Err(StorageError::NotFound(container.into()));
        }
        if !resp.status().is_success() {
            return Err(StorageError::other(format!(
                "swift list {}: {}",
                container,
                resp.status()
            )));
        }
        let text = resp.text().await.map_err(StorageError::other)?;
        Ok(text.lines().filter(|l| !l.is_empty()).map(|s| s.to_string()).collect())
    }
}
