use crate::types::{NuncTime, Observation, Protocol};
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
    pub protocols:              Vec<Protocol>,
    /// How many servers to fire queries at simultaneously.
    /// All are launched in parallel; only the fastest `target_sources`
    /// responses are used.  Larger values improve diversity at the cost
    /// of slightly more outbound traffic.
    pub batch_size:             usize,
    /// Stop collecting once this many sources have responded.
    /// The remaining in-flight queries are dropped (cancelled).
    /// Must be ≤ batch_size and ≥ min_sources.
    pub target_sources:         usize,
    /// Minimum sources that must agree before we return a result.
    pub min_sources:            usize,
    /// Outlier rejection threshold in milliseconds.
    /// Sources whose timestamp differs from the median by more than this
    /// are excluded.  Tune empirically by plotting `NuncTime::raw`.
    pub rejection_threshold_ms: u64,
    /// If true, populate `NuncTime::raw` with all observations.
    /// Useful for plotting the distribution to tune thresholds.
    pub instrument:             bool,
    /// Optional user-supplied pool (overrides bundled list).
    pub pool:                   Option<Pool>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            protocols:              vec![Protocol::Https],
            batch_size:             128,
            target_sources:         32,
            min_sources:            8,
            rejection_threshold_ms: 5_000,
            instrument:             false,
            pool:                   None,
        }
    }
}

impl Config {
    pub fn from_mode(mode: Mode) -> Self {
        match mode {
            Mode::Fast     => Config::default(),
            Mode::Thorough => Config {
                protocols:      vec![Protocol::Https, Protocol::Ntp, Protocol::Nts],
                batch_size:     350,
                target_sources: 64,
                ..Config::default()
            },
            Mode::Paranoid => Config {
                protocols:      vec![
                    Protocol::Https, Protocol::Ntp, Protocol::Nts,
                    Protocol::Smtp, Protocol::Roughtime, Protocol::Time,
                ],
                batch_size:     350,
                target_sources: 128,
                min_sources:    16,
                ..Config::default()
            },
            Mode::Custom(c) => c,
        }
    }
}

/// Top-level entry point.
///
/// ```rust,no_run
/// use nunc::{query, Mode};
///
/// #[tokio::main]
/// async fn main() {
///     let t = query(Mode::Fast).await.unwrap();
///     println!("time: {:?} ± {:?}ms", t.timestamp(), t.confidence().as_millis());
/// }
/// ```
pub async fn query(mode: Mode) -> Result<NuncTime, NuncError> {
    query_with_config(Config::from_mode(mode)).await
}

pub async fn query_with_config(cfg: Config) -> Result<NuncTime, NuncError> {
    use futures::stream::{FuturesUnordered, StreamExt};
    use std::pin::Pin;
    use std::future::Future;

    let pool = cfg.pool.unwrap_or_else(Pool::bundled);
    let nonce = trng_nonce();
    let servers = pool.select(cfg.batch_size, &cfg.protocols, nonce);

    if servers.is_empty() {
        return Err(NuncError::EmptyPool);
    }

    // Build one combined queue of all queries across all protocols.
    // Each future resolves to Option<Observation> — None means the server
    // failed or timed out and is silently dropped.
    let mut queue: FuturesUnordered<Pin<Box<dyn Future<Output = Option<Observation>> + Send>>>
        = FuturesUnordered::new();

    for s in &servers {
        #[allow(unreachable_patterns)] // `_` needed when not all protocol features are enabled
        match s.protocol {
            #[cfg(feature = "https")]
            Protocol::Https => {
                let host = s.host.clone();
                queue.push(Box::pin(async move {
                    crate::sources::https::https::query(&host, nonce).await
                }));
            }
            #[cfg(feature = "ntp")]
            Protocol::Ntp => {
                let host = s.host.clone();
                queue.push(Box::pin(async move {
                    crate::sources::ntp::ntp::query(&host).await
                }));
            }
            #[cfg(feature = "smtp")]
            Protocol::Smtp => {
                let host = s.host.clone();
                queue.push(Box::pin(async move {
                    crate::sources::smtp::smtp::query(&host).await
                }));
            }
            #[cfg(feature = "daytime")]
            Protocol::Daytime => {
                let host = s.host.clone();
                queue.push(Box::pin(async move {
                    crate::sources::daytime::daytime::query(&host).await
                }));
            }
            #[cfg(feature = "time")]
            Protocol::Time => {
                let host = s.host.clone();
                queue.push(Box::pin(async move {
                    crate::sources::time_prot::time_prot::query(&host).await
                }));
            }
            #[cfg(feature = "ftp")]
            Protocol::Ftp => {
                let host = s.host.clone();
                queue.push(Box::pin(async move {
                    crate::sources::ftp::ftp::query(&host).await
                }));
            }
            #[cfg(feature = "nts")]
            Protocol::Nts => {
                let host = s.host.clone();
                queue.push(Box::pin(async move {
                    crate::sources::nts::nts::query(&host).await
                }));
            }
            #[cfg(feature = "roughtime")]
            Protocol::Roughtime => {
                let host = s.host.clone();
                queue.push(Box::pin(async move {
                    crate::sources::roughtime::roughtime::query(&host).await
                }));
            }
            _ => {}
        }
    }

    // Drain the queue until target_sources respond or all futures finish.
    // Dropping `queue` here cancels everything still in flight.
    let mut observations: Vec<Observation> = Vec::with_capacity(cfg.target_sources);
    while let Some(result) = queue.next().await {
        if let Some(obs) = result {
            observations.push(obs);
            if observations.len() >= cfg.target_sources {
                break;
            }
        }
    }

    let mut result = consensus(observations, cfg.min_sources, cfg.rejection_threshold_ms)?;

    if !cfg.instrument {
        result.raw.clear();
    }

    Ok(result)
}
