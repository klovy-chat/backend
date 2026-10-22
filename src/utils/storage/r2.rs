// r2.rs
// S3 API Cloudflare R2: put/get/delete, public URL, kwarantanna.
// Zakres:
//  - init na starcie
//  - put/get/delete S3; CDN_PUBLIC_BASE_URL = publiczny bucket
//  - kwarantanna (osobny bucket albo prefix quarantine/)
//  - Content-Disposition + metadata nosniff na obiekcie
// CDN_PUBLIC_BASE_URL musi wskazywać publiczny bucket, nie kwarantannę.
// Przy zmianach: keys.rs, images.rs, FE cdn.ts, scan/.

use std::env;
use std::sync::OnceLock;

use aws_credential_types::Credentials;
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;

use super::keys::attachment_prefers_download;

const QUARANTINE_PREFIX: &str = "quarantine/";

#[derive(Debug)]
pub enum StorageError {
    NotConfigured(String),
    InitFailed(String),
    DatabaseFailed(String),
    OperationFailed(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured(msg) => write!(f, "Storage not configured: {msg}"),
            Self::InitFailed(msg) => write!(f, "Storage init failed: {msg}"),
            Self::DatabaseFailed(msg) => write!(f, "Storage database operation failed: {msg}"),
            Self::OperationFailed(msg) => write!(f, "Storage operation failed: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}

pub struct R2Storage {
    client: Client,
    public_bucket: String,
    quarantine_bucket: String,
    quarantine_uses_prefix: bool,
}

static STORAGE: OnceLock<R2Storage> = OnceLock::new();

fn required_env(name: &str) -> Result<String, StorageError> {
    env::var(name)
        .map_err(|_| StorageError::NotConfigured(format!("missing environment variable {name}")))
}

fn build_client() -> Result<Client, StorageError> {
    let account_id = required_env("R2_ACCOUNT_ID")?;
    let access_key = required_env("R2_ACCESS_KEY_ID")?;
    let secret_key = required_env("R2_SECRET_ACCESS_KEY")?;

    let credentials = Credentials::new(access_key, secret_key, None, None, "r2");
    let endpoint = format!("https://{account_id}.r2.cloudflarestorage.com");

    let config = aws_sdk_s3::Config::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .credentials_provider(credentials)
        .region(aws_sdk_s3::config::Region::new("auto"))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .build();

    Ok(Client::from_conf(config))
}

fn safe_content_disposition_filename(key: &str) -> Option<String> {
    let name = key.rsplit('/').next()?.trim();
    if name.is_empty() || name.len() > 80 || name.contains("..") {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return None;
    }
    Some(name.to_string())
}

fn is_not_found(err: &str) -> bool {
    err.contains("NotFound") || err.contains("404") || err.contains("NoSuchKey")
}

/// AWS SDK Display for S3 404 is just `"service error"` — the real code is in Debug/metadata.
fn is_missing_object(err: &(impl ProvideErrorMetadata + std::fmt::Debug)) -> bool {
    match err.code() {
        Some(code)
            if code.eq_ignore_ascii_case("NotFound") || code.eq_ignore_ascii_case("NoSuchKey") =>
        {
            true
        }
        _ => is_not_found(&format!("{err:?}")),
    }
}

impl R2Storage {
    fn from_env() -> Result<Self, StorageError> {
        let client = build_client()?;
        let public_bucket = required_env("R2_PUBLIC_BUCKET")?;
        let quarantine_bucket = env::var("R2_QUARANTINE_BUCKET")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| public_bucket.clone());
        let quarantine_uses_prefix = quarantine_bucket == public_bucket;

        Ok(Self {
            client,
            public_bucket,
            quarantine_bucket,
            quarantine_uses_prefix,
        })
    }

    fn quarantine_object_key(&self, logical: &str) -> String {
        let logical = logical.trim_start_matches('/');
        if self.quarantine_uses_prefix {
            if logical.starts_with(QUARANTINE_PREFIX) {
                logical.to_string()
            } else {
                format!("{QUARANTINE_PREFIX}{logical}")
            }
        } else {
            logical.to_string()
        }
    }

    fn logical_from_quarantine_key(&self, object_key: &str) -> String {
        if self.quarantine_uses_prefix {
            object_key
                .strip_prefix(QUARANTINE_PREFIX)
                .unwrap_or(object_key)
                .to_string()
        } else {
            object_key.to_string()
        }
    }

    fn apply_object_headers(
        &self,
        mut request: aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder,
        key: &str,
        content_type: &str,
        public: bool,
    ) -> aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder {
        request = request.content_type(content_type).cache_control(if public {
            "public, max-age=31536000, immutable"
        } else {
            "private, no-store"
        });
        // R2/S3 cannot set X-Content-Type-Options (metadata is x-amz-meta-*, not an HTTP header).
        // Non-media: force download. Media: inline with a name taken only from the object key.
        if attachment_prefers_download(key) {
            request = request.content_disposition("attachment");
        } else if let Some(name) = safe_content_disposition_filename(key) {
            request = request.content_disposition(format!("inline; filename=\"{name}\""));
        }
        request
    }

    pub async fn put_public(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<(), StorageError> {
        let request = self
            .client
            .put_object()
            .bucket(&self.public_bucket)
            .key(key)
            .body(ByteStream::from(body));
        self.apply_object_headers(request, key, content_type, true)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed(format!("put_public {key}: {e}")))?;
        Ok(())
    }

    pub async fn put_quarantine(
        &self,
        logical_key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<(), StorageError> {
        let object_key = self.quarantine_object_key(logical_key);
        let request = self
            .client
            .put_object()
            .bucket(&self.quarantine_bucket)
            .key(&object_key)
            .body(ByteStream::from(body));
        self.apply_object_headers(request, logical_key, content_type, false)
            .send()
            .await
            .map_err(|e| {
                StorageError::OperationFailed(format!("put_quarantine {logical_key}: {e}"))
            })?;
        Ok(())
    }

    async fn get_bucket_bytes(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        match self
            .client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => {
                let aggregated =
                    output.body.collect().await.map_err(|e| {
                        StorageError::OperationFailed(format!("get body {key}: {e}"))
                    })?;
                Ok(Some(aggregated.into_bytes().to_vec()))
            }
            Err(err) => {
                if is_missing_object(&err) {
                    Ok(None)
                } else {
                    Err(StorageError::OperationFailed(format!("get {key}: {err:?}")))
                }
            }
        }
    }

    pub async fn get_quarantine(&self, logical_key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let object_key = self.quarantine_object_key(logical_key);
        self.get_bucket_bytes(&self.quarantine_bucket, &object_key)
            .await
    }

    pub async fn get_public(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.get_bucket_bytes(&self.public_bucket, key).await
    }

    pub async fn promote_quarantine_to_public(
        &self,
        logical_key: &str,
        content_type: &str,
    ) -> Result<(), StorageError> {
        let Some(body) = self.get_quarantine(logical_key).await? else {
            if self
                .head_public_content_length(logical_key)
                .await?
                .is_some()
            {
                return Ok(());
            }
            return Err(StorageError::OperationFailed(format!(
                "promote missing quarantine object {logical_key}"
            )));
        };
        self.publish_scanned(logical_key, body, content_type).await
    }

    pub async fn publish_scanned(
        &self,
        logical_key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<(), StorageError> {
        self.put_public(logical_key, body, content_type).await?;
        self.delete_quarantine(logical_key).await?;
        if let Some(thumb) = crate::utils::storage::attachment_thumb_key(logical_key) {
            if let Some(thumb_bytes) = self.get_quarantine(&thumb).await? {
                self.put_public(&thumb, thumb_bytes, "image/webp").await?;
                self.delete_quarantine(&thumb).await?;
            }
        }
        Ok(())
    }

    pub async fn delete_public(&self, key: &str) -> Result<(), StorageError> {
        self.delete_bucket_key(&self.public_bucket, key).await
    }

    pub async fn delete_quarantine(&self, logical_key: &str) -> Result<(), StorageError> {
        let object_key = self.quarantine_object_key(logical_key);
        self.delete_bucket_key(&self.quarantine_bucket, &object_key)
            .await
    }

    async fn delete_bucket_key(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
        match self
            .client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => {
                if is_missing_object(&err) {
                    Ok(())
                } else {
                    Err(StorageError::OperationFailed(format!(
                        "delete {key}: {err:?}"
                    )))
                }
            }
        }
    }

    pub async fn head_public_content_length(&self, key: &str) -> Result<Option<u64>, StorageError> {
        self.head_bucket_key(&self.public_bucket, key).await
    }

    pub async fn head_attachment_content_length(
        &self,
        logical_key: &str,
    ) -> Result<Option<u64>, StorageError> {
        match self.head_public_content_length(logical_key).await {
            Ok(Some(len)) => return Ok(Some(len)),
            Ok(None) => {}
            Err(err) => return Err(err),
        }
        let object_key = self.quarantine_object_key(logical_key);
        self.head_bucket_key(&self.quarantine_bucket, &object_key)
            .await
    }

    async fn head_bucket_key(&self, bucket: &str, key: &str) -> Result<Option<u64>, StorageError> {
        match self
            .client
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => Ok(output.content_length().map(|len| len as u64)),
            Err(err) => {
                if is_missing_object(&err) {
                    Ok(None)
                } else {
                    Err(StorageError::OperationFailed(format!(
                        "head {key}: {err:?}"
                    )))
                }
            }
        }
    }

    pub async fn delete_attachment_key(&self, key: &str) -> Result<(), StorageError> {
        if !crate::utils::storage::is_attachment_key(key) {
            return Ok(());
        }
        let mut first_error = None;
        for result in [
            self.delete_public(key).await,
            self.delete_quarantine(key).await,
        ] {
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        if let Some(thumb) = crate::utils::storage::attachment_thumb_key(key) {
            for result in [
                self.delete_public(&thumb).await,
                self.delete_quarantine(&thumb).await,
            ] {
                if let Err(error) = result {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub async fn delete_avatar_key(&self, key: &str) -> Result<(), StorageError> {
        if crate::utils::storage::is_avatar_key(key) {
            self.delete_public(key).await
        } else {
            Ok(())
        }
    }

    pub async fn delete_public_media_key(&self, key: &str) -> Result<(), StorageError> {
        if crate::utils::storage::is_public_media_key(key) {
            self.delete_public(key).await
        } else {
            Ok(())
        }
    }

    async fn list_prefix(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<(String, u64)>, StorageError> {
        let mut objects = Vec::new();
        let mut continuation: Option<String> = None;

        loop {
            let mut request = self.client.list_objects_v2().bucket(bucket).prefix(prefix);

            if let Some(token) = &continuation {
                request = request.continuation_token(token);
            }

            let output = request
                .send()
                .await
                .map_err(|e| StorageError::OperationFailed(format!("list {prefix}: {e}")))?;

            for object in output.contents() {
                let Some(key) = object.key() else {
                    continue;
                };
                objects.push((key.to_string(), object.size().unwrap_or(0) as u64));
            }

            continuation = output.next_continuation_token().map(str::to_string);
            if continuation.is_none() {
                break;
            }
        }

        Ok(objects)
    }

    pub async fn list_public_attachments(&self) -> Result<Vec<(String, u64)>, StorageError> {
        let objects = self
            .list_prefix(&self.public_bucket, "attachments/")
            .await?;
        Ok(objects
            .into_iter()
            .filter(|(key, _)| crate::utils::storage::is_attachment_key(key))
            .collect())
    }

    pub async fn list_quarantine_attachments(&self) -> Result<Vec<(String, u64)>, StorageError> {
        let prefix = if self.quarantine_uses_prefix {
            format!("{QUARANTINE_PREFIX}attachments/")
        } else {
            "attachments/".to_string()
        };
        let objects = self.list_prefix(&self.quarantine_bucket, &prefix).await?;
        Ok(objects
            .into_iter()
            .map(|(key, size)| (self.logical_from_quarantine_key(&key), size))
            .filter(|(key, _)| crate::utils::storage::is_attachment_key(key))
            .collect())
    }
}

pub fn init_storage() -> Result<(), StorageError> {
    let storage = R2Storage::from_env()?;
    let public_bucket = storage.public_bucket.clone();
    let quarantine_bucket = storage.quarantine_bucket.clone();
    let prefix = storage.quarantine_uses_prefix;
    STORAGE
        .set(storage)
        .map_err(|_| StorageError::InitFailed("storage already initialized".into()))?;
    log::info!(
        "R2 storage ready (public={public_bucket}, quarantine={quarantine_bucket}, prefix={prefix}, cdn={})",
        cdn_public_base_url()
    );
    Ok(())
}

pub fn storage() -> &'static R2Storage {
    STORAGE
        .get()
        .expect("R2 storage not initialized — call init_storage() at startup")
}

pub fn cdn_public_base_url() -> String {
    env::var("CDN_PUBLIC_BASE_URL").unwrap_or_else(|_| "https://cdn.klovy.chat".to_string())
}

pub fn public_media_url(key: &str) -> String {
    let base = cdn_public_base_url().trim_end_matches('/').to_string();
    let normalized = key.trim_start_matches('/');
    format!("{base}/{normalized}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_display_service_error_is_not_a_404() {
        assert!(!is_not_found("service error"));
        assert!(is_not_found("NotFound"));
        assert!(is_not_found("NoSuchKey"));
        assert!(is_not_found("code: NotFound, status: 404"));
    }

    #[test]
    fn disposition_filename_is_key_basename_only() {
        assert_eq!(
            safe_content_disposition_filename("attachments/dm/conv_a/abc.webp"),
            Some("abc.webp".into())
        );
        assert_eq!(
            safe_content_disposition_filename("attachments/dm/conv_a/..webp"),
            None
        );
        assert_eq!(
            safe_content_disposition_filename("x/foo\"; filename=evil.webp"),
            None
        );
    }
}
