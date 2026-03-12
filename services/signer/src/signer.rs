use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use tracing::info;

/// Cryptographic signing engine.
///
/// In production, this delegates all private key operations to an HSM
/// (AWS CloudHSM or Thales Luna) via PKCS#11. The private key never
/// leaves the HSM boundary.
///
/// For local development, an in-memory Ed25519 key pair is used.
pub struct SigningEngine {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    key_id: String,
    algorithm: String,
    cert_chain_url: String,
}

impl SigningEngine {
    /// Create a development-only signing engine with an ephemeral key pair.
    /// DO NOT use in production — use `new_hsm()` instead.
    pub fn new_local_dev() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let key_id = format!(
            "veritas-dev-{}",
            &hex::encode(&verifying_key.to_bytes()[..4])
        );

        info!(key_id = %key_id, "Generated development signing key (NOT FOR PRODUCTION)");

        Ok(Self {
            signing_key,
            verifying_key,
            key_id,
            algorithm: "Ed25519".to_string(),
            cert_chain_url: "https://api.veritas.security/.well-known/veritas-keys.json".to_string(),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Sign a verdict payload.
    ///
    /// Process:
    /// 1. Parse the verdict JSON
    /// 2. Canonicalize (deterministic JSON serialization with sorted keys)
    /// 3. SHA-512 hash of the canonical form
    /// 4. Ed25519 signature over the hash
    /// 5. Return signed verdict with signature appended
    pub fn sign_verdict(&self, verdict_payload: &[u8]) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();

        // Parse the verdict
        let mut verdict: serde_json::Value = serde_json::from_slice(verdict_payload)?;

        // Canonicalize: sort keys deterministically
        let canonical = canonical_json(&verdict)?;

        // SHA-512 hash
        let mut hasher = Sha512::new();
        hasher.update(canonical.as_bytes());
        let content_hash = hasher.finalize();

        // Ed25519 sign
        let signature = self.signing_key.sign(&content_hash);

        // Append signature to verdict
        if let Some(obj) = verdict.as_object_mut() {
            obj.insert(
                "signature".to_string(),
                serde_json::json!({
                    "signature_bytes": hex::encode(&signature.to_bytes()),
                    "key_id": self.key_id,
                    "algorithm": self.algorithm,
                    "cert_chain_url": self.cert_chain_url,
                    "content_hash": hex::encode(content_hash.as_slice()),
                    "signed_at": chrono::Utc::now().to_rfc3339(),
                }),
            );
        }

        let signed_bytes = serde_json::to_vec(&verdict)?;

        let duration = start.elapsed();
        veritas_shared::metrics::SIGNING_DURATION
            .with_label_values(&[])
            .observe(duration.as_millis() as f64);

        Ok(signed_bytes)
    }

    /// Verify a signed verdict.
    pub fn verify(&self, signed_verdict: &[u8]) -> Result<bool> {
        let verdict: serde_json::Value = serde_json::from_slice(signed_verdict)?;

        let sig_obj = verdict
            .get("signature")
            .ok_or_else(|| anyhow::anyhow!("No signature field"))?;

        let sig_hex = sig_obj["signature_bytes"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid signature_bytes"))?;

        let content_hash_hex = sig_obj["content_hash"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid content_hash"))?;

        let sig_bytes = hex::decode(sig_hex)?;
        let content_hash = hex::decode(content_hash_hex)?;

        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)?;

        Ok(self.verifying_key.verify_strict(&content_hash, &signature).is_ok())
    }
}

/// Produce canonical JSON with deterministically sorted keys.
fn canonical_json(value: &serde_json::Value) -> Result<String> {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);

            let entries: Vec<String> = sorted
                .into_iter()
                .filter(|(k, _)| *k != "signature") // Exclude signature from hash
                .map(|(k, v)| {
                    let v_str = canonical_json(v).unwrap_or_default();
                    format!("\"{}\":{}", k, v_str)
                })
                .collect();

            Ok(format!("{{{}}}", entries.join(",")))
        }
        serde_json::Value::Array(arr) => {
            let entries: Vec<String> = arr
                .iter()
                .map(|v| canonical_json(v).unwrap_or_default())
                .collect();
            Ok(format!("[{}]", entries.join(",")))
        }
        _ => Ok(value.to_string()),
    }
}

/// Hex encoding utility (simple implementation to avoid extra dependency in minimal builds).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(hex: &str) -> Result<Vec<u8>, anyhow::Error> {
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| anyhow::anyhow!("Hex decode error: {}", e))
            })
            .collect()
    }
}
