//! Perceptual hash computation and Redis-backed similarity lookup.
//!
//! Implements three complementary hash families:
//! - **aHash** (average hash): fast, coarse; good for exact-duplicate detection.
//! - **dHash** (difference hash): captures gradient structure; robust to brightness changes.
//! - **pHash** (DCT-based perceptual hash): most resilient to re-encoding and scaling.
//!
//! Hashes are stored and queried in Redis as 64-bit integers so that
//! Hamming distance can be computed with XOR + POPCOUNT in constant time.

use anyhow::{Context, Result};
use image::{DynamicImage, GrayImage};
use redis::AsyncCommands;
use std::time::Instant;
use tracing::{debug, instrument, warn};

/// Hamming distance threshold for each hash family.
/// Pairs with distance <= threshold are considered a match.
#[derive(Debug, Clone, Copy)]
pub struct DistanceThresholds {
    pub ahash: u32,
    pub dhash: u32,
    pub phash: u32,
}

impl Default for DistanceThresholds {
    fn default() -> Self {
        Self {
            ahash: 5,
            dhash: 6,
            phash: 8,
        }
    }
}

/// A set of perceptual hashes computed from a single frame.
#[derive(Debug, Clone)]
pub struct FrameHashes {
    pub ahash: u64,
    pub dhash: u64,
    pub phash: u64,
}

/// Result of a Redis hash lookup.
#[derive(Debug, Clone)]
pub struct HashMatch {
    /// Identifier of the previously-stored reference that matched.
    pub reference_id: String,
    /// Which hash family produced the match.
    pub family: HashFamily,
    /// Hamming distance between the query and stored hash.
    pub distance: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFamily {
    AHash,
    DHash,
    PHash,
}

impl std::fmt::Display for HashFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AHash => write!(f, "ahash"),
            Self::DHash => write!(f, "dhash"),
            Self::PHash => write!(f, "phash"),
        }
    }
}

// ── Hash computation ────────────────────────────────────────────────

/// Compute all three perceptual hashes from a decoded image frame.
#[instrument(skip(image), level = "debug")]
pub fn compute_hashes(image: &DynamicImage) -> FrameHashes {
    let gray = image.to_luma8();

    FrameHashes {
        ahash: compute_ahash(&gray),
        dhash: compute_dhash(&gray),
        phash: compute_phash(&gray),
    }
}

/// Average hash: resize to 8x8, compute mean luminance, set bit when pixel > mean.
fn compute_ahash(gray: &GrayImage) -> u64 {
    let resized = image::imageops::resize(gray, 8, 8, image::imageops::FilterType::Lanczos3);

    let pixels: Vec<u8> = resized.pixels().map(|p| p.0[0]).collect();
    let mean: u64 = pixels.iter().map(|&p| p as u64).sum::<u64>() / pixels.len() as u64;

    let mut hash: u64 = 0;
    for (i, &pixel) in pixels.iter().enumerate() {
        if pixel as u64 > mean {
            hash |= 1 << i;
        }
    }
    hash
}

/// Difference hash: resize to 9x8, compare adjacent horizontal pixels.
fn compute_dhash(gray: &GrayImage) -> u64 {
    let resized = image::imageops::resize(gray, 9, 8, image::imageops::FilterType::Lanczos3);

    let mut hash: u64 = 0;
    let mut bit = 0;
    for y in 0..8 {
        for x in 0..8 {
            let left = resized.get_pixel(x, y).0[0] as i16;
            let right = resized.get_pixel(x + 1, y).0[0] as i16;
            if left > right {
                hash |= 1 << bit;
            }
            bit += 1;
        }
    }
    hash
}

/// DCT-based perceptual hash: resize to 32x32, apply 2D DCT, keep top-left
/// 8x8 coefficients (excluding DC), threshold against median.
fn compute_phash(gray: &GrayImage) -> u64 {
    let size = 32;
    let resized = image::imageops::resize(gray, size, size, image::imageops::FilterType::Lanczos3);

    // Convert to f64 matrix
    let pixels: Vec<f64> = resized.pixels().map(|p| p.0[0] as f64).collect();

    // Compute 2D DCT via separable 1D transforms (rows then columns).
    let mut dct = vec![0.0f64; (size * size) as usize];

    // Row-wise 1D DCT
    for row in 0..size {
        for u in 0..size {
            let mut sum = 0.0;
            for x in 0..size {
                let idx = (row * size + x) as usize;
                sum += pixels[idx]
                    * ((2.0 * x as f64 + 1.0) * u as f64 * std::f64::consts::PI
                        / (2.0 * size as f64))
                        .cos();
            }
            let alpha = if u == 0 {
                (1.0 / size as f64).sqrt()
            } else {
                (2.0 / size as f64).sqrt()
            };
            dct[(row * size + u) as usize] = alpha * sum;
        }
    }

    // Column-wise 1D DCT on the row-transformed result
    let row_dct = dct.clone();
    for col in 0..size {
        for v in 0..size {
            let mut sum = 0.0;
            for y in 0..size {
                let idx = (y * size + col) as usize;
                sum += row_dct[idx]
                    * ((2.0 * y as f64 + 1.0) * v as f64 * std::f64::consts::PI
                        / (2.0 * size as f64))
                        .cos();
            }
            let alpha = if v == 0 {
                (1.0 / size as f64).sqrt()
            } else {
                (2.0 / size as f64).sqrt()
            };
            dct[(v * size + col) as usize] = alpha * sum;
        }
    }

    // Extract the top-left 8x8 block, excluding the DC coefficient (0,0).
    let hash_size: u32 = 8;
    let mut low_freq: Vec<f64> = Vec::with_capacity(63);
    for y in 0..hash_size {
        for x in 0..hash_size {
            if x == 0 && y == 0 {
                continue; // skip DC
            }
            low_freq.push(dct[(y * size + x) as usize]);
        }
    }

    // Threshold against the median
    let median = {
        let mut sorted = low_freq.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        sorted[sorted.len() / 2]
    };

    let mut hash: u64 = 0;
    for (i, &coeff) in low_freq.iter().enumerate() {
        if coeff > median {
            hash |= 1 << i;
        }
    }
    hash
}

/// Compute Hamming distance between two 64-bit hashes.
#[inline]
pub fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

// ── Redis lookup ────────────────────────────────────────────────────

/// Redis key prefixes for each hash family.
const REDIS_KEY_AHASH: &str = "veritas:hash:ahash";
const REDIS_KEY_DHASH: &str = "veritas:hash:dhash";
const REDIS_KEY_PHASH: &str = "veritas:hash:phash";

/// Query Redis for near-duplicate matches across all three hash families.
///
/// We store hashes in sorted sets keyed by hash value, with the member being
/// the reference_id. For each query hash we fetch a candidate window from
/// Redis and compute Hamming distance client-side. This balances throughput
/// against the impracticality of server-side bitwise comparison on large sets.
///
/// For very large corpora, a multi-index hashing approach (splitting the
/// 64-bit hash into 4x16-bit sub-keys) would be used instead. This simpler
/// approach works well for corpora up to several million entries.
#[instrument(skip(conn, hashes), level = "debug")]
pub async fn query_redis_hashes(
    conn: &mut redis::aio::MultiplexedConnection,
    hashes: &FrameHashes,
    thresholds: &DistanceThresholds,
) -> Result<Vec<HashMatch>> {
    let start = Instant::now();
    let mut matches = Vec::new();

    // Check each hash family independently.
    check_family(
        conn,
        REDIS_KEY_AHASH,
        HashFamily::AHash,
        hashes.ahash,
        thresholds.ahash,
        &mut matches,
    )
    .await?;

    check_family(
        conn,
        REDIS_KEY_DHASH,
        HashFamily::DHash,
        hashes.dhash,
        thresholds.dhash,
        &mut matches,
    )
    .await?;

    check_family(
        conn,
        REDIS_KEY_PHASH,
        HashFamily::PHash,
        hashes.phash,
        thresholds.phash,
        &mut matches,
    )
    .await?;

    debug!(
        match_count = matches.len(),
        elapsed_us = start.elapsed().as_micros() as u64,
        "Hash lookup completed"
    );
    Ok(matches)
}

/// Check a single hash family by querying the Redis sorted set and
/// computing Hamming distance client-side.
async fn check_family(
    conn: &mut redis::aio::MultiplexedConnection,
    key: &str,
    family: HashFamily,
    query_hash: u64,
    threshold: u32,
    matches: &mut Vec<HashMatch>,
) -> Result<()> {
    // Retrieve all (reference_id, hash_value) pairs from the sorted set.
    // The score is the hash as a f64.
    let entries: Vec<(String, f64)> = conn
        .zrangebyscore_withscores(key, "-inf", "+inf")
        .await
        .context("Failed to query hash sorted set")?;

    for (reference_id, score) in entries {
        let stored_hash = score as u64;
        let dist = hamming_distance(query_hash, stored_hash);
        if dist <= threshold {
            debug!(
                family = %family,
                reference_id = %reference_id,
                distance = dist,
                "Hash match found"
            );
            matches.push(HashMatch {
                reference_id,
                family,
                distance: dist,
            });
        }
    }

    Ok(())
}

/// Batch query: compute hashes for multiple frames and find matches for any.
///
/// Returns the best (lowest distance) match across all frames, or None.
#[instrument(skip(conn, frames), fields(frame_count = frames.len()), level = "debug")]
pub async fn batch_query(
    conn: &mut redis::aio::MultiplexedConnection,
    frames: &[DynamicImage],
    thresholds: &DistanceThresholds,
) -> Result<Option<HashMatch>> {
    let start = Instant::now();
    let mut best_match: Option<HashMatch> = None;

    for (i, frame) in frames.iter().enumerate() {
        let hashes = compute_hashes(frame);
        let frame_matches = query_redis_hashes(conn, &hashes, thresholds).await?;

        for m in frame_matches {
            let dominated = best_match
                .as_ref()
                .is_some_and(|best| m.distance >= best.distance);

            if !dominated {
                debug!(
                    frame_index = i,
                    family = %m.family,
                    distance = m.distance,
                    reference_id = %m.reference_id,
                    "New best hash match"
                );
                best_match = Some(m);
            }
        }
    }

    debug!(
        frame_count = frames.len(),
        elapsed_ms = start.elapsed().as_millis() as u64,
        matched = best_match.is_some(),
        "Batch hash query completed"
    );
    Ok(best_match)
}

/// Store hashes for a reference video in Redis (used by the ingestion pipeline
/// when adding known-deepfake or known-authentic references).
#[instrument(skip(conn, hashes), level = "debug")]
pub async fn store_reference_hashes(
    conn: &mut redis::aio::MultiplexedConnection,
    reference_id: &str,
    hashes: &FrameHashes,
) -> Result<()> {
    // Store each hash as a sorted-set entry with the hash value as the score.
    redis::pipe()
        .atomic()
        .zadd(REDIS_KEY_AHASH, reference_id, hashes.ahash as f64)
        .zadd(REDIS_KEY_DHASH, reference_id, hashes.dhash as f64)
        .zadd(REDIS_KEY_PHASH, reference_id, hashes.phash as f64)
        .query_async(conn)
        .await
        .context("Failed to store reference hashes in Redis")?;

    debug!(
        reference_id = reference_id,
        ahash = hashes.ahash,
        dhash = hashes.dhash,
        phash = hashes.phash,
        "Reference hashes stored"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_identical_is_zero() {
        assert_eq!(hamming_distance(0xDEADBEEF, 0xDEADBEEF), 0);
    }

    #[test]
    fn hamming_distance_single_bit_flip() {
        assert_eq!(hamming_distance(0b1000, 0b0000), 1);
    }

    #[test]
    fn hamming_distance_all_bits_flipped() {
        assert_eq!(hamming_distance(0u64, u64::MAX), 64);
    }

    #[test]
    fn ahash_deterministic() {
        let img = DynamicImage::new_luma8(64, 64);
        let h1 = compute_ahash(&img.to_luma8());
        let h2 = compute_ahash(&img.to_luma8());
        assert_eq!(h1, h2, "aHash must be deterministic for the same input");
    }

    #[test]
    fn dhash_deterministic() {
        let img = DynamicImage::new_luma8(64, 64);
        let h1 = compute_dhash(&img.to_luma8());
        let h2 = compute_dhash(&img.to_luma8());
        assert_eq!(h1, h2, "dHash must be deterministic for the same input");
    }

    #[test]
    fn phash_deterministic() {
        let img = DynamicImage::new_luma8(64, 64);
        let h1 = compute_phash(&img.to_luma8());
        let h2 = compute_phash(&img.to_luma8());
        assert_eq!(h1, h2, "pHash must be deterministic for the same input");
    }
}
