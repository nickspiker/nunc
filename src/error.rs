use thiserror::Error;

#[derive(Debug, Error)]
pub enum NuncError {
    #[error("not enough sources responded: got {got}, need {need}")]
    InsufficientSources { got: usize, need: usize },

    #[error("consensus failed: sources too spread ({spread_ms}ms) for confidence target")]
    NoConsensus { spread_ms: u64 },

    #[error("pool is empty for the requested protocol(s)")]
    EmptyPool,

    #[error("http error: {0}")]
    Http(String),

    #[error("ntp error: {0}")]
    Ntp(String),

    #[error("smtp error: {0}")]
    Smtp(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
