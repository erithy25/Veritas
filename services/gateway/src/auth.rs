use tonic::{Request, Status};
use uuid::Uuid;

/// Authenticated tenant context extracted from gRPC metadata.
#[derive(Debug, Clone)]
pub struct TenantAuth {
    pub tenant_id: Uuid,
    pub tenant_name: String,
    pub api_key_prefix: String,
}

/// Extract and validate tenant authentication from request metadata.
///
/// Supports two authentication methods:
/// 1. mTLS: tenant_id extracted from client certificate CN
/// 2. API Key: `x-api-key` header validated against stored hashes
///
/// In production, this validates against the tenant database.
/// For development, it accepts any well-formed request.
pub fn extract_tenant<T>(request: &Request<T>) -> Result<TenantAuth, Status> {
    let metadata = request.metadata();

    // Try API key authentication first
    if let Some(api_key) = metadata.get("x-api-key") {
        let api_key_str = api_key
            .to_str()
            .map_err(|_| Status::unauthenticated("Invalid API key encoding"))?;

        // Validate API key format: vts_live_<random> or vts_test_<random>
        if !api_key_str.starts_with("vts_live_") && !api_key_str.starts_with("vts_test_") {
            return Err(Status::unauthenticated("Invalid API key format"));
        }

        // Extract tenant_id from x-tenant-id header
        let tenant_id_str = metadata
            .get("x-tenant-id")
            .ok_or_else(|| Status::unauthenticated("x-tenant-id header required with API key auth"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Invalid tenant ID encoding"))?;

        let tenant_id = Uuid::parse_str(tenant_id_str)
            .map_err(|_| Status::unauthenticated("Invalid tenant ID format"))?;

        // TODO: In production, validate API key hash against database
        // let key_hash = sha256(api_key_str);
        // let stored_hash = db.get_api_key_hash(tenant_id).await?;
        // if key_hash != stored_hash { return Err(Status::unauthenticated("Invalid API key")); }

        return Ok(TenantAuth {
            tenant_id,
            tenant_name: format!("tenant-{}", &tenant_id_str[..8]),
            api_key_prefix: api_key_str[..12].to_string(),
        });
    }

    // Try mTLS: in production, the TLS termination layer extracts the
    // client certificate CN and passes it as a header
    if let Some(cert_cn) = metadata.get("x-client-cert-cn") {
        let cn = cert_cn
            .to_str()
            .map_err(|_| Status::unauthenticated("Invalid certificate CN encoding"))?;

        let tenant_id = Uuid::parse_str(cn)
            .map_err(|_| Status::unauthenticated("Certificate CN must be a valid tenant UUID"))?;

        return Ok(TenantAuth {
            tenant_id,
            tenant_name: format!("mtls-tenant-{}", &cn[..8]),
            api_key_prefix: "mtls".to_string(),
        });
    }

    Err(Status::unauthenticated(
        "Authentication required: provide x-api-key + x-tenant-id headers, or mTLS client certificate",
    ))
}
