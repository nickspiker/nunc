use crate::types::{NuncTime, Protocol};
use crate::error::NuncError;
use crate::pool::{Pool, trng_nonce};
use crate::consensus::consensus;

/// Query mode — controls which protocols are used and how many sources.
#[derive(Debug, Clone)]
pub enum Mode {
    /// HTTPS only.  Fast (~1s wall clock), works everywhere, good enough for
    /// most uses.  The right starting point.
    Fast,

    /// All enabled protocols.  Slower but broader source diversity.
    Thorough,

    /// Full multi-path + cross-protocol with explicit diversity enforcement.
    /// Requires VPN/tunnel support in the caller's environment.
    Paranoid,

    /// Custom configuration.
    Custom(Config),
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Protocols to query.
    pub protocols:             Vec<Protocol>,
    /// Number of servers to query.
    pub server_count:          usize,
    /// Minimum sources that must agree before we return a result.
    pub min_sources:           usize,
    /// Outlier rejection threshold in milliseconds.
    /// Sources whose timestamp differs from the median by more than this
    /// are excluded.  Tune empirically by plotting `NuncTime::raw`.
    pub rejection_threshold_ms: u64,
    /// If true, populate `NuncTime::raw` with all observations.
    /// Useful for plotting the distribution to tune thresholds.
    pub instrument:            bool,
    /// Optional user-supplied pool (overrides bundled list).
    pub pool:                  Option<Pool>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            protocols:              vec![Protocol::Https],
            server_count:           32,
            min_sources:            8,
            rejection_threshold_ms: 5_000, // 5s — wide until we see real data
            instrument:             false,
            pool:                   None,
        }
    }
}

impl Config {
    pub fn from_mode(mode: Mode) -> Self {
        match mode {
            Mode::Fast      => Config::default(),
            Mode::Thorough  => Config {
                protocols:    vec![Protocol::Https, Protocol::Ntp],
                server_count: 64,
                ..Config::default()
            },
            Mode::Paranoid  => Config {
                protocols:    vec![Protocol::Https, Protocol::Ntp, Protocol::Smtp],
                server_count: 128,
                min_sources:  16,
                ..Config::default()
            },
            Mode::Custom(c) => c,
        }
    }
}

/// Top-level entry point.
///
/// ```rust
/// use nunc_time::{query, Mode};
///
/// #[tokio::main]
/// async fn main() {
///     let t = query(Mode::Fast).await.unwrap();
///     println!("time: {:?} ± {:?}", t.timestamp, t.confidence);
/// }
/// ```
pub async fn query(mode: Mode) -> Result<NuncTime, NuncError> {
    let cfg = Config::from_mode(mode);
    query_with_config(cfg).await
}

pub async fn query_with_config(cfg: Config) -> Result<NuncTime, NuncError> {
    let pool = cfg.pool.unwrap_or_else(Pool::bundled);

    let nonce = trng_nonce();
    let servers = pool.select(cfg.server_count, &cfg.protocols, nonce);

    if servers.is_empty() {
        return Err(NuncError::EmptyPool);
    }

    let mut observations = Vec::new();

    // HTTPS queries
    #[cfg(feature = "https")]
    {
        let https_urls: Vec<String> = servers
            .iter()
            .filter(|s| s.protocol == Protocol::Https)
            .map(|s| format!("https://{}/", s.host))
            .collect();

        if !https_urls.is_empty() {
            let mut obs = crate::sources::https::https::query_many(&https_urls, nonce).await;
            observations.append(&mut obs);
        }
    }

    // NTP queries
    #[cfg(feature = "ntp")]
    {
        for s in servers.iter().filter(|s| s.protocol == Protocol::Ntp) {
            if let Some(obs) = crate::sources::ntp::ntp::query(&s.host).await {
                observations.push(obs);
            }
        }
    }

    // Consensus
    let mut result = consensus(observations, cfg.min_sources, cfg.rejection_threshold_ms)?;

    // Strip raw observations unless instrumentation is requested
    if !cfg.instrument {
        result.raw.clear();
    }

    Ok(result)
}
