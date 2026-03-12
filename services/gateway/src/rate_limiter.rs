use anyhow::Result;
use redis::AsyncCommands;
use tracing::warn;
use veritas_shared::error::VeritasError;

/// Token-bucket rate limiter backed by Redis.
///
/// Uses Redis INCR with TTL to enforce per-tenant request limits.
/// In production, limits are loaded from the tenant configuration database.
#[derive(Clone)]
pub struct RateLimiter {
    client: redis::Client,
    default_rps: u64,
}

impl RateLimiter {
    pub fn new(client: redis::Client) -> Self {
        Self {
            client,
            default_rps: 1000, // Default: 1000 requests/second per tenant
        }
    }

    /// Check if the tenant has remaining capacity.
    /// Returns Ok(()) if allowed, or VeritasError::RateLimitExceeded if over limit.
    pub async fn check(&self, tenant_id: &str) -> Result<(), VeritasError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| VeritasError::Redis(format!("Connection failed: {e}")))?;

        let now_secs = chrono::Utc::now().timestamp();
        let key = format!("rl:sec:{tenant_id}:{now_secs}");

        // Atomic increment + set TTL if key is new
        let count: u64 = redis::pipe()
            .atomic()
            .incr(&key, 1u64)
            .expire(&key, 2) // 2-second TTL to handle clock skew
            .ignore()
            .query_async(&mut conn)
            .await
            .map_err(|e| VeritasError::Redis(format!("Rate limit check failed: {e}")))?;

        // TODO: Load tenant-specific limit from config/cache
        let limit = self.default_rps;

        if count > limit {
            warn!(
                tenant_id = tenant_id,
                current_rate = count,
                limit = limit,
                "Rate limit exceeded"
            );
            return Err(VeritasError::RateLimitExceeded {
                tenant_id: tenant_id.to_string(),
            });
        }

        Ok(())
    }
}
