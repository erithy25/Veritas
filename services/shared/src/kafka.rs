use crate::config::KafkaConfig;
use anyhow::Result;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::producer::FutureProducer;
use tracing::info;

/// Kafka topic constants.
pub mod topics {
    pub const INGEST_RAW: &str = "veritas.ingest.raw";
    pub const L1_RESULTS: &str = "veritas.l1.results";
    pub const L2_QUEUE: &str = "veritas.l2.queue";
    pub const L2_RESULTS: &str = "veritas.l2.results";
    pub const L3_QUEUE: &str = "veritas.l3.queue";
    pub const L3_RESULTS: &str = "veritas.l3.results";
    pub const VERDICTS: &str = "veritas.verdicts";
    pub const COMPLIANCE_EVENTS: &str = "veritas.compliance.events";
    pub const ALERTS: &str = "veritas.alerts";
}

/// Create a Kafka producer from config.
pub fn create_producer(config: &KafkaConfig) -> Result<FutureProducer> {
    let mut client_config = ClientConfig::new();
    client_config
        .set("bootstrap.servers", &config.brokers)
        .set("message.timeout.ms", "5000")
        .set("compression.type", "lz4")
        .set("linger.ms", "5")
        .set("batch.num.messages", "1000")
        .set("queue.buffering.max.messages", "100000")
        .set("security.protocol", &config.security_protocol);

    if let Some(mechanism) = &config.sasl_mechanism {
        client_config.set("sasl.mechanism", mechanism);
    }
    if let Some(username) = &config.sasl_username {
        client_config.set("sasl.username", username);
    }
    if let Some(password) = &config.sasl_password {
        client_config.set("sasl.password", password);
    }

    let producer: FutureProducer = client_config.create()?;
    info!(brokers = %config.brokers, "Kafka producer created");
    Ok(producer)
}

/// Create a Kafka consumer subscribed to the given topics.
pub fn create_consumer(config: &KafkaConfig, topics: &[&str]) -> Result<StreamConsumer> {
    let mut client_config = ClientConfig::new();
    client_config
        .set("bootstrap.servers", &config.brokers)
        .set("group.id", &config.consumer_group)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .set("max.poll.interval.ms", "300000")
        .set("session.timeout.ms", "30000")
        .set("security.protocol", &config.security_protocol);

    if let Some(mechanism) = &config.sasl_mechanism {
        client_config.set("sasl.mechanism", mechanism);
    }
    if let Some(username) = &config.sasl_username {
        client_config.set("sasl.username", username);
    }
    if let Some(password) = &config.sasl_password {
        client_config.set("sasl.password", password);
    }

    let consumer: StreamConsumer = client_config.create()?;
    consumer.subscribe(topics)?;

    info!(
        brokers = %config.brokers,
        group = %config.consumer_group,
        topics = ?topics,
        "Kafka consumer created and subscribed"
    );

    Ok(consumer)
}
