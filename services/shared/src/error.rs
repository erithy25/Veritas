use thiserror::Error;
use tonic::Status;

/// Central error type for all Veritas services.
#[derive(Debug, Error)]
pub enum VeritasError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Rate limit exceeded for tenant {tenant_id}")]
    RateLimitExceeded { tenant_id: String },

    #[error("Upload too large: {size_bytes} bytes exceeds limit of {max_bytes} bytes")]
    UploadTooLarge { size_bytes: u64, max_bytes: u64 },

    #[error("Unsupported video format: {0}")]
    UnsupportedFormat(String),

    #[error("Duplicate upload: {upload_id}")]
    DuplicateUpload { upload_id: String },

    #[error("Kafka error: {0}")]
    Kafka(String),

    #[error("Redis error: {0}")]
    Redis(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("HSM error: {0}")]
    Hsm(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Model inference error: {0}")]
    Inference(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<VeritasError> for Status {
    fn from(err: VeritasError) -> Self {
        match &err {
            VeritasError::AuthenticationFailed(msg) => Status::unauthenticated(msg.clone()),
            VeritasError::PermissionDenied(msg) => Status::permission_denied(msg.clone()),
            VeritasError::NotFound(msg) => Status::not_found(msg.clone()),
            VeritasError::InvalidRequest(msg) => Status::invalid_argument(msg.clone()),
            VeritasError::RateLimitExceeded { .. } => {
                Status::resource_exhausted(err.to_string())
            }
            VeritasError::UploadTooLarge { .. } => {
                Status::invalid_argument(err.to_string())
            }
            VeritasError::UnsupportedFormat(msg) => Status::invalid_argument(msg.clone()),
            VeritasError::DuplicateUpload { .. } => {
                Status::already_exists(err.to_string())
            }
            VeritasError::Kafka(_)
            | VeritasError::Redis(_)
            | VeritasError::Database(_)
            | VeritasError::Hsm(_)
            | VeritasError::Signing(_)
            | VeritasError::Inference(_) => Status::internal(err.to_string()),
            VeritasError::ServiceUnavailable(msg) => Status::unavailable(msg.clone()),
            VeritasError::Internal(msg) => Status::internal(msg.clone()),
            VeritasError::Anyhow(e) => Status::internal(e.to_string()),
        }
    }
}

pub type VeritasResult<T> = Result<T, VeritasError>;
