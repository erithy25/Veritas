use anyhow::Result;
use chrono::Utc;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;
use tonic::{Request, Response, Status};
use tracing::{info, instrument, warn};
use uuid::Uuid;

use veritas_shared::config::AppConfig;
use veritas_shared::error::VeritasError;
use veritas_shared::kafka::topics;
use veritas_shared::metrics::{ACTIVE_REQUESTS, REQUEST_DURATION, REQUEST_TOTAL};
use veritas_shared::proto::veritas::api::v1::{
    veritas_analysis_server::{VeritasAnalysis, VeritasAnalysisServer},
    AnalysisStatus, AnalyzeVideoRequest, AnalyzeVideoResponse, AsyncAnalysisResponse,
    GetAnalysisStatusRequest, GetVerdictRequest, SignedVerdict, StreamVerdictsRequest, VideoChunk,
};
use veritas_shared::types::{KafkaEnvelope, ScanContext, ScanPriority};

use crate::auth;
use crate::rate_limiter::RateLimiter;

pub type AnalysisServer = VeritasAnalysisServer<AnalysisServiceImpl>;

pub struct AnalysisServiceImpl {
    kafka_producer: FutureProducer,
    redis_client: redis::Client,
    rate_limiter: RateLimiter,
    config: AppConfig,
}

impl AnalysisServiceImpl {
    pub fn new(
        kafka_producer: FutureProducer,
        redis_client: redis::Client,
        rate_limiter: RateLimiter,
        config: AppConfig,
    ) -> Self {
        Self {
            kafka_producer,
            redis_client,
            rate_limiter,
            config,
        }
    }

    /// Validate and extract tenant context from request metadata.
    fn authenticate(&self, request: &Request<impl std::any::Any>) -> Result<auth::TenantAuth, Status> {
        auth::extract_tenant(request)
    }

    /// Dispatch frames to the ingestion pipeline via Kafka.
    async fn dispatch_to_ingestion(
        &self,
        scan_context: &ScanContext,
        video_data: &[u8],
    ) -> Result<(), VeritasError> {
        let envelope = KafkaEnvelope::new(
            scan_context.tenant_id,
            scan_context.scan_id,
            IngestPayload {
                upload_id: scan_context.upload_id.clone(),
                video_size_bytes: video_data.len() as u64,
                max_tier: scan_context.max_tier,
                priority: scan_context.priority,
            },
        );

        let payload = serde_json::to_vec(&envelope)
            .map_err(|e| VeritasError::Internal(format!("Serialization error: {e}")))?;

        // Partition by tenant_id + upload_id for ordering guarantee
        let partition_key = format!("{}:{}", scan_context.tenant_id, scan_context.upload_id);

        let record = FutureRecord::to(topics::INGEST_RAW)
            .key(&partition_key)
            .payload(&payload);

        self.kafka_producer
            .send(record, Duration::from_secs(5))
            .await
            .map_err(|(err, _)| VeritasError::Kafka(format!("Failed to produce: {err}")))?;

        info!(
            scan_id = %scan_context.scan_id,
            upload_id = %scan_context.upload_id,
            size_bytes = video_data.len(),
            "Dispatched to ingestion pipeline"
        );

        Ok(())
    }
}

/// Payload sent to the ingestion topic.
#[derive(serde::Serialize, serde::Deserialize)]
struct IngestPayload {
    upload_id: String,
    video_size_bytes: u64,
    max_tier: u8,
    priority: ScanPriority,
}

#[tonic::async_trait]
impl VeritasAnalysis for AnalysisServiceImpl {
    #[instrument(skip_all, fields(upload_id))]
    async fn analyze_video(
        &self,
        request: Request<AnalyzeVideoRequest>,
    ) -> Result<Response<AnalyzeVideoResponse>, Status> {
        let timer = REQUEST_DURATION
            .with_label_values(&["gateway", "AnalyzeVideo", "ok"])
            .start_timer();
        ACTIVE_REQUESTS.inc();

        let tenant = self.authenticate(&request)?;

        let req = request.into_inner();
        tracing::Span::current().record("upload_id", &req.upload_id.as_str());

        // Validate request
        if req.upload_id.is_empty() {
            ACTIVE_REQUESTS.dec();
            return Err(Status::invalid_argument("upload_id is required"));
        }
        if req.video_data.is_empty() {
            ACTIVE_REQUESTS.dec();
            return Err(Status::invalid_argument("video_data is required"));
        }

        // Rate limit check
        self.rate_limiter
            .check(&tenant.tenant_id.to_string())
            .await
            .map_err(|e| -> Status { VeritasError::from(e).into() })?;

        let max_tier = req
            .config
            .as_ref()
            .and_then(|c| c.max_tier)
            .unwrap_or(3)
            .min(3) as u8;

        let priority = req
            .config
            .as_ref()
            .and_then(|c| c.priority)
            .map(|p| match p {
                1 => ScanPriority::Low,
                3 => ScanPriority::High,
                4 => ScanPriority::Critical,
                _ => ScanPriority::Normal,
            })
            .unwrap_or(ScanPriority::Normal);

        let scan_context = ScanContext {
            scan_id: Uuid::new_v4(),
            upload_id: req.upload_id.clone(),
            tenant_id: tenant.tenant_id,
            priority,
            max_tier,
            created_at: Utc::now(),
            processing_region: "eu-central-1".to_string(), // TODO: derive from tenant config
        };

        // Dispatch to ingestion pipeline
        self.dispatch_to_ingestion(&scan_context, &req.video_data)
            .await
            .map_err(Status::from)?;

        REQUEST_TOTAL
            .with_label_values(&["gateway", "AnalyzeVideo", "accepted"])
            .inc();
        ACTIVE_REQUESTS.dec();
        timer.observe_duration();

        // For synchronous mode, we would wait for the result via a response channel.
        // For now, return async-style response. Full sync implementation requires
        // a result-waiting mechanism (Redis pub/sub or dedicated response topic).
        let response = AnalyzeVideoResponse {
            verdict: None, // Will be populated when sync waiting is implemented
            c2pa_manifest: None,
            stats: None,
        };

        info!(
            scan_id = %scan_context.scan_id,
            upload_id = %req.upload_id,
            tenant_id = %tenant.tenant_id,
            "Video analysis request accepted"
        );

        Ok(Response::new(response))
    }

    async fn analyze_video_stream(
        &self,
        _request: Request<tonic::Streaming<VideoChunk>>,
    ) -> Result<Response<AnalyzeVideoResponse>, Status> {
        // Streaming upload implementation: collect chunks, reassemble, then
        // process as a single video.
        Err(Status::unimplemented(
            "Streaming upload will be implemented in Phase 2",
        ))
    }

    #[instrument(skip_all, fields(upload_id))]
    async fn analyze_video_async(
        &self,
        request: Request<AnalyzeVideoRequest>,
    ) -> Result<Response<AsyncAnalysisResponse>, Status> {
        let tenant = self.authenticate(&request)?;
        let req = request.into_inner();

        if req.upload_id.is_empty() {
            return Err(Status::invalid_argument("upload_id is required"));
        }

        self.rate_limiter
            .check(&tenant.tenant_id.to_string())
            .await
            .map_err(|e| -> Status { VeritasError::from(e).into() })?;

        let scan_id = Uuid::new_v4();

        let scan_context = ScanContext {
            scan_id,
            upload_id: req.upload_id.clone(),
            tenant_id: tenant.tenant_id,
            priority: ScanPriority::Normal,
            max_tier: 3,
            created_at: Utc::now(),
            processing_region: "eu-central-1".to_string(),
        };

        self.dispatch_to_ingestion(&scan_context, &req.video_data)
            .await
            .map_err(Status::from)?;

        let estimated_completion = Utc::now() + chrono::Duration::seconds(10);

        let response = AsyncAnalysisResponse {
            scan_id: scan_id.to_string(),
            estimated_completion: Some(prost_types::Timestamp {
                seconds: estimated_completion.timestamp(),
                nanos: 0,
            }),
            status_url: format!("/v1/analyze/{scan_id}/status"),
        };

        info!(
            scan_id = %scan_id,
            upload_id = %req.upload_id,
            "Async analysis request accepted"
        );

        Ok(Response::new(response))
    }

    async fn get_analysis_status(
        &self,
        request: Request<GetAnalysisStatusRequest>,
    ) -> Result<Response<AnalysisStatus>, Status> {
        let _tenant = self.authenticate(&request)?;
        let req = request.into_inner();

        // TODO: Look up scan status from Redis/PostgreSQL
        let status = AnalysisStatus {
            scan_id: req.scan_id,
            state: 1, // QUEUED
            progress: 0.0,
            current_stage: "QUEUED".to_string(),
            estimated_completion: None,
            verdict: None,
            error_message: None,
        };

        Ok(Response::new(status))
    }

    async fn get_verdict(
        &self,
        request: Request<GetVerdictRequest>,
    ) -> Result<Response<SignedVerdict>, Status> {
        let _tenant = self.authenticate(&request)?;
        // TODO: Look up verdict from PostgreSQL/ClickHouse
        Err(Status::not_found("Verdict not found"))
    }

    type StreamVerdictsStream =
        tokio_stream::wrappers::ReceiverStream<Result<SignedVerdict, Status>>;

    async fn stream_verdicts(
        &self,
        request: Request<StreamVerdictsRequest>,
    ) -> Result<Response<Self::StreamVerdictsStream>, Status> {
        let _tenant = self.authenticate(&request)?;
        let _req = request.into_inner();

        let (tx, rx) = tokio::sync::mpsc::channel(128);

        // TODO: Subscribe to Kafka verdicts topic filtered by tenant
        // and stream results back via the channel
        tokio::spawn(async move {
            // Placeholder: the real implementation subscribes to
            // veritas.verdicts topic filtered by tenant_id
            drop(tx);
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}
