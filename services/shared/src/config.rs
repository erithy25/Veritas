use serde::Deserialize;

/// Top-level application configuration, loaded from environment variables
/// and optional TOML config files via the `config` crate.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub service_name: String,
    pub environment: Environment,
    pub server: ServerConfig,
    pub kafka: KafkaConfig,
    pub redis: RedisConfig,
    pub postgres: PostgresConfig,
    pub clickhouse: ClickhouseConfig,
    pub tracing: TracingConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Staging,
    Production,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub grpc_port: u16,
    pub metrics_port: u16,
    pub health_port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            grpc_port: 50051,
            metrics_port: 9090,
            health_port: 8080,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct KafkaConfig {
    pub brokers: String,
    pub consumer_group: String,
    pub security_protocol: String,
    pub sasl_mechanism: Option<String>,
    pub sasl_username: Option<String>,
    pub sasl_password: Option<String>,
}

impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            brokers: "localhost:9092".to_string(),
            consumer_group: "veritas-default".to_string(),
            security_protocol: "plaintext".to_string(),
            sasl_mechanism: None,
            sasl_username: None,
            sasl_password: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub cluster_mode: bool,
    pub pool_size: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            cluster_mode: false,
            pool_size: 16,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PostgresConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: "postgres://veritas:veritas@localhost:5432/veritas".to_string(),
            max_connections: 20,
            min_connections: 5,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClickhouseConfig {
    pub url: String,
    pub database: String,
}

impl Default for ClickhouseConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8123".to_string(),
            database: "veritas".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TracingConfig {
    pub otlp_endpoint: Option<String>,
    pub log_level: String,
    pub json_logs: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            log_level: "info".to_string(),
            json_logs: false,
        }
    }
}

impl AppConfig {
    /// Load configuration from environment variables with `VERITAS_` prefix.
    /// Falls back to defaults for development.
    pub fn load(service_name: &str) -> anyhow::Result<Self> {
        let config = config::Config::builder()
            .set_default("service_name", service_name)?
            .set_default("environment", "development")?
            .set_default("server.grpc_port", 50051)?
            .set_default("server.metrics_port", 9090)?
            .set_default("server.health_port", 8080)?
            .set_default("kafka.brokers", "localhost:9092")?
            .set_default("kafka.consumer_group", format!("veritas-{service_name}"))?
            .set_default("kafka.security_protocol", "plaintext")?
            .set_default("redis.url", "redis://localhost:6379")?
            .set_default("redis.cluster_mode", false)?
            .set_default("redis.pool_size", 16)?
            .set_default("postgres.url", "postgres://veritas:veritas@localhost:5432/veritas")?
            .set_default("postgres.max_connections", 20)?
            .set_default("postgres.min_connections", 5)?
            .set_default("clickhouse.url", "http://localhost:8123")?
            .set_default("clickhouse.database", "veritas")?
            .set_default("tracing.log_level", "info")?
            .set_default("tracing.json_logs", false)?
            .add_source(
                config::Environment::with_prefix("VERITAS")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        Ok(config.try_deserialize()?)
    }
}
