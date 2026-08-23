use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdaterError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("HTTP error while {context}: {source}")]
    Http {
        context: String,
        source: reqwest::Error,
    },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("remote API error: {0}")]
    Api(String),
    #[error("serialization error while {context}: {source}")]
    Serialization {
        context: String,
        source: serde_json::Error,
    },
    #[error("I/O error while {context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, UpdaterError>;

impl UpdaterError {
    /// Wraps an HTTP error with an operation that is safe to print without leaking request secrets.
    pub fn http(context: impl Into<String>, source: reqwest::Error) -> Self {
        Self::Http {
            context: context.into(),
            source,
        }
    }

    /// Wraps a JSON error with the parsing operation while excluding the secret-bearing payload.
    pub fn serialization(context: impl Into<String>, source: serde_json::Error) -> Self {
        Self::Serialization {
            context: context.into(),
            source,
        }
    }
}
