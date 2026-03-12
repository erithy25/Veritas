use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::LazyLock;

/// Global Prometheus metrics registry for all Veritas services.
pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

// ── Request metrics ──────────────────────────────────────────

pub static REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let opts = HistogramOpts::new("veritas_request_duration_seconds", "Request latency in seconds")
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ]);
    let histogram = HistogramVec::new(opts, &["service", "method", "status"]).unwrap();
    REGISTRY.register(Box::new(histogram.clone())).unwrap();
    histogram
});

pub static REQUEST_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let opts = Opts::new("veritas_request_total", "Total number of requests");
    let counter = IntCounterVec::new(opts, &["service", "method", "status"]).unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

pub static ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    let gauge = IntGauge::new("veritas_active_requests", "Currently processing requests").unwrap();
    REGISTRY.register(Box::new(gauge.clone())).unwrap();
    gauge
});

// ── Detection metrics ────────────────────────────────────────

pub static DETECTION_RESULT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let opts = Opts::new("veritas_detection_result_total", "Detection outcomes by tier and action");
    let counter = IntCounterVec::new(opts, &["tier", "action", "tenant"]).unwrap();
    REGISTRY.register(Box::new(counter.clone())).unwrap();
    counter
});

pub static L1_SCAN_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let opts = HistogramOpts::new("veritas_l1_scan_duration_ms", "L1 scan latency in milliseconds")
        .buckets(vec![0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 50.0]);
    let histogram = HistogramVec::new(opts, &["result"]).unwrap();
    REGISTRY.register(Box::new(histogram.clone())).unwrap();
    histogram
});

pub static L2_SCAN_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let opts = HistogramOpts::new("veritas_l2_scan_duration_ms", "L2 scan latency in milliseconds")
        .buckets(vec![10.0, 25.0, 50.0, 75.0, 100.0, 150.0, 200.0, 500.0]);
    let histogram = HistogramVec::new(opts, &["result"]).unwrap();
    REGISTRY.register(Box::new(histogram.clone())).unwrap();
    histogram
});

pub static L3_INFERENCE_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let opts = HistogramOpts::new(
        "veritas_l3_inference_duration_ms",
        "L3 per-model inference latency in milliseconds",
    )
    .buckets(vec![50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0]);
    let histogram = HistogramVec::new(opts, &["model"]).unwrap();
    REGISTRY.register(Box::new(histogram.clone())).unwrap();
    histogram
});

pub static SIGNING_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let opts =
        HistogramOpts::new("veritas_signing_duration_ms", "Cryptographic signing latency in ms")
            .buckets(vec![1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0]);
    let histogram = HistogramVec::new(opts, &[]).unwrap();
    REGISTRY.register(Box::new(histogram.clone())).unwrap();
    histogram
});

// ── Kafka metrics ────────────────────────────────────────────

pub static KAFKA_CONSUMER_LAG: LazyLock<IntGauge> = LazyLock::new(|| {
    let gauge = IntGauge::new("veritas_kafka_consumer_lag", "Kafka consumer lag in messages").unwrap();
    REGISTRY.register(Box::new(gauge.clone())).unwrap();
    gauge
});

/// Render all registered metrics as Prometheus text format.
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
