use super::{Storage, StorageError};
use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sdk_s3::config::{BehaviorVersion, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::Client;
use bytes::Bytes;
use std::time::Duration;
use tracing::debug;

pub struct S3Storage {
    client: Client,
    timeout: Duration,
    multipart_threshold: u64,
    multipart_part_size: u64,
}

pub struct S3Config {
    pub endpoint: Option<String>,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub path_style: bool,
    pub timeout: Duration,
    pub multipart_threshold: u64,
    pub multipart_part_size: u64,
}

impl S3Storage {
    pub async fn connect(cfg: S3Config) -> Result<Self, StorageError> {
        let creds = Credentials::new(
            cfg.access_key,
            cfg.secret_key,
            None,
            None,
            "cosbench-rs",
        );
        let mut b = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(cfg.region))
            .credentials_provider(creds)
            .force_path_style(cfg.path_style);
        if let Some(ep) = cfg.endpoint {
            b = b.endpoint_url(ep);
        }
        let client = Client::from_conf(b.build());
        let part = cfg.multipart_part_size.max(5 * 1024 * 1024); // S3 min part 5MiB (except last)
        Ok(Self {
            client,
            timeout: cfg.timeout,
            multipart_threshold: cfg.multipart_threshold,
            multipart_part_size: part,
        })
    }

    async fn with_timeout<T, E, F, Fut>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        match tokio::time::timeout(self.timeout, f()).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(StorageError::other(e)),
            Err(_) => Err(StorageError::Timeout(format!("exceeded {:?}", self.timeout))),
        }
    }

    async fn put_simple(
        &self,
        container: &str,
        object: &str,
        data: Bytes,
    ) -> Result<(), StorageError> {
        let c = container.to_string();
        let o = object.to_string();
        let len = data.len() as i64;
        self.with_timeout(|| async {
            self.client
                .put_object()
                .bucket(c)
                .key(o)
                .body(ByteStream::from(data))
                .content_length(len)
                .send()
                .await
        })
        .await
        .map(|_| ())
    }

    /// Multipart upload for large objects (addresses Java issues #389, #347, #379).
    async fn put_multipart(
        &self,
        container: &str,
        object: &str,
        data: Bytes,
    ) -> Result<(), StorageError> {
        let c = container.to_string();
        let o = object.to_string();
        let create = self
            .with_timeout(|| async {
                self.client
                    .create_multipart_upload()
                    .bucket(&c)
                    .key(&o)
                    .send()
                    .await
            })
            .await?;
        let upload_id = create
            .upload_id()
            .ok_or_else(|| StorageError::other("missing upload_id"))?
            .to_string();

        let part_size = self.multipart_part_size as usize;
        let mut parts: Vec<CompletedPart> = Vec::new();
        let mut part_number: i32 = 1;
        let mut offset = 0usize;

        let result: Result<(), StorageError> = async {
            while offset < data.len() {
                let end = (offset + part_size).min(data.len());
                let chunk = data.slice(offset..end);
                let c2 = c.clone();
                let o2 = o.clone();
                let uid = upload_id.clone();
                let pn = part_number;
                let uploaded = self
                    .with_timeout(|| async {
                        self.client
                            .upload_part()
                            .bucket(c2)
                            .key(o2)
                            .upload_id(uid)
                            .part_number(pn)
                            .body(ByteStream::from(chunk))
                            .send()
                            .await
                    })
                    .await?;
                let etag = uploaded
                    .e_tag()
                    .ok_or_else(|| StorageError::other("missing part etag"))?
                    .to_string();
                parts.push(
                    CompletedPart::builder()
                        .e_tag(etag)
                        .part_number(pn)
                        .build(),
                );
                debug!(part = pn, bytes = end - offset, "uploaded multipart part");
                part_number += 1;
                offset = end;
            }

            let completed = CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build();
            self.with_timeout(|| async {
                self.client
                    .complete_multipart_upload()
                    .bucket(&c)
                    .key(&o)
                    .upload_id(&upload_id)
                    .multipart_upload(completed)
                    .send()
                    .await
            })
            .await?;
            Ok(())
        }
        .await;

        if let Err(e) = result {
            let _ = self
                .with_timeout(|| async {
                    self.client
                        .abort_multipart_upload()
                        .bucket(&c)
                        .key(&o)
                        .upload_id(&upload_id)
                        .send()
                        .await
                })
                .await;
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn create_container(&self, container: &str) -> Result<(), StorageError> {
        let c = container.to_string();
        self.with_timeout(|| async { self.client.create_bucket().bucket(c).send().await })
            .await
            .map(|_| ())
            .or_else(|e| {
                let s = e.to_string();
                if s.contains("BucketAlreadyOwnedByYou")
                    || s.contains("BucketAlreadyExists")
                    || s.contains("bucket already")
                {
                    Ok(())
                } else {
                    Err(e)
                }
            })
    }

    async fn delete_container(&self, container: &str) -> Result<(), StorageError> {
        let c = container.to_string();
        self.with_timeout(|| async { self.client.delete_bucket().bucket(c).send().await })
            .await
            .map(|_| ())
    }

    async fn put_object(
        &self,
        container: &str,
        object: &str,
        data: Bytes,
    ) -> Result<(), StorageError> {
        let use_mp = self.multipart_threshold > 0 && (data.len() as u64) >= self.multipart_threshold;
        if use_mp {
            self.put_multipart(container, object, data).await
        } else {
            self.put_simple(container, object, data).await
        }
    }

    async fn get_object(
        &self,
        container: &str,
        object: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Bytes, StorageError> {
        let c = container.to_string();
        let o = object.to_string();
        let mut req = self.client.get_object().bucket(c).key(o);
        if let Some((start, end)) = range {
            req = req.range(format!("bytes={start}-{end}"));
        }
        let out = self.with_timeout(|| async { req.send().await }).await?;
        let collected = out.body.collect().await.map_err(StorageError::other)?;
        Ok(collected.into_bytes())
    }

    async fn delete_object(&self, container: &str, object: &str) -> Result<(), StorageError> {
        let c = container.to_string();
        let o = object.to_string();
        self.with_timeout(|| async {
            self.client.delete_object().bucket(c).key(o).send().await
        })
        .await
        .map(|_| ())
    }

    async fn list_objects(
        &self,
        container: &str,
        prefix: &str,
    ) -> Result<Vec<String>, StorageError> {
        let c = container.to_string();
        let p = prefix.to_string();
        let out = self
            .with_timeout(|| async {
                self.client
                    .list_objects_v2()
                    .bucket(c)
                    .prefix(p)
                    .send()
                    .await
            })
            .await?;
        let keys = out
            .contents
            .unwrap_or_default()
            .into_iter()
            .filter_map(|o| o.key)
            .collect();
        Ok(keys)
    }
}
