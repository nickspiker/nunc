use crate::types::{NuncTime, Observation, Protocol};
use crate::error::NuncError;
use crate::pool::Pool;
use crate::consensus::consensus;

/// Query mode — controls which protocols are used and how many sources.
#[derive(Debug, Clone)]
pub enum Mode {
    /// HTTPS only.  Fast (~1s wall clock), works everywhere, good enough for most uses.  The right starting point.
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
    /// All are launched in parallel; the fastest `target_sources` responses are kept, capped per ASN and per country at an eighth of `target_sources` so no one operator can fill the set by being quick.
    /// Larger values improve diversity at the cost of slightly more outbound traffic.
    pub batch_size:             usize,
    /// Stop collecting once this many sources have responded.
    /// The remaining in-flight queries are dropped (cancelled).
    /// Must be ≤ batch_size and ≥ min_sources.
    pub target_sources:         usize,
    /// Minimum sources that must agree before we return a result.
    pub min_sources:            usize,
    /// Outlier rejection threshold in milliseconds.
    /// Sources whose timestamp differs from the median by more than this are excluded.  Tune empirically by plotting `NuncTime::raw`.
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
            protocols:              all_protocols(),
            batch_size:             84,
            target_sources:         42,
            min_sources:            8,
            rejection_threshold_ms: 1_000,
            instrument:             false,
            pool:                   None,
        }
    }
}

/// All protocols enabled at compile time.
/// Modes differ only in how many sources they query, not which protocols.
fn all_protocols() -> Vec<Protocol> {
    let mut v = Vec::new();
    #[cfg(feature = "https")]     v.push(Protocol::Https);
    #[cfg(feature = "ntp")]       v.push(Protocol::Ntp);
    #[cfg(feature = "nts")]       v.push(Protocol::Nts);
    #[cfg(feature = "smtp")]      v.push(Protocol::Smtp);
    #[cfg(feature = "roughtime")] v.push(Protocol::Roughtime);
    #[cfg(feature = "daytime")]   v.push(Protocol::Daytime);
    #[cfg(feature = "time")]      v.push(Protocol::Time);
    #[cfg(feature = "ftp")]       v.push(Protocol::Ftp);
    v
}

impl Config {
    pub fn from_mode(mode: Mode) -> Self {
        match mode {
            Mode::Fast     => Config::default(),
            Mode::Thorough => Config {
                batch_size:     350,
                target_sources: 64,
                ..Config::default()
            },
            Mode::Paranoid => Config {
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
    let servers = pool.select(cfg.batch_size, &cfg.protocols);

    if servers.is_empty() {
        return Err(NuncError::EmptyPool);
    }

    // Build one combined queue of all queries across all protocols.
    // Each future resolves to Option<Observation> — None means the server failed or timed out and is silently dropped.
    let mut queue: FuturesUnordered<Pin<Box<dyn Future<Output = Option<Observation>> + Send>>>
        = FuturesUnordered::new();

    for s in &servers {
        let host = s.host.clone();
        #[allow(unreachable_patterns)] // `_` needed when not all protocol features are enabled
        let fut: Pin<Box<dyn Future<Output = Option<Observation>> + Send>> = match s.protocol {
            #[cfg(feature = "https")]
            Protocol::Https     => Box::pin(async move { crate::sources::https::https::query(&host).await }),
            #[cfg(feature = "ntp")]
            Protocol::Ntp       => Box::pin(async move { crate::sources::ntp::ntp::query(&host).await }),
            #[cfg(feature = "smtp")]
            Protocol::Smtp      => Box::pin(async move { crate::sources::smtp::smtp::query(&host).await }),
            #[cfg(feature = "daytime")]
            Protocol::Daytime   => Box::pin(async move { crate::sources::daytime::daytime::query(&host).await }),
            #[cfg(feature = "time")]
            Protocol::Time      => Box::pin(async move { crate::sources::time_prot::time_prot::query(&host).await }),
            #[cfg(feature = "ftp")]
            Protocol::Ftp       => Box::pin(async move { crate::sources::ftp::ftp::query(&host).await }),
            #[cfg(feature = "nts")]
            Protocol::Nts       => Box::pin(async move { crate::sources::nts::nts::query(&host).await }),
            #[cfg(feature = "roughtime")]
            Protocol::Roughtime => Box::pin(async move { crate::sources::roughtime::roughtime::query(&host).await }),
            _ => continue,
        };
        // The pool entry's origin rides along with its reply, so the drain can cap per ASN and country without matching a reply's label back to the table (roughtime labels itself host:port).
        let asn = s.asn;
        let country = s.country.clone();
        queue.push(Box::pin(async move {
            fut.await.map(|mut obs| { obs.asn = asn; obs.country = country; obs })
        }));
    }

    // Drain the queue until target_sources respond or all futures finish.
    // Dropping `queue` here cancels everything still in flight.
    // Fastest-first keeping would let a few low-latency servers of one operator sit in every round's set whatever the launch shuffle did, so the kept set is capped per ASN and per country (security audit LIB-03).
    let cap = origin_cap(cfg.target_sources);
    let mut observations: Vec<Observation> = Vec::with_capacity(cfg.target_sources);
    while let Some(result) = queue.next().await {
        if let Some(obs) = result {
            keep(&mut observations, obs, cap);
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

/// How many kept responders may share one ASN, and how many one country: an eighth of the target, so at least eight distinct origins stand behind a full round.
fn origin_cap(target_sources: usize) -> usize {
    // WHY the max: a target below 1 << 3 shifts to a cap of 0, under which no reply could ever be kept and every round would end empty.
    // PROOF: usize >> 3 is 0 for every value below 8, and keep() refuses a reply once its origin's count reaches the cap.
    (target_sources >> 3).max(1)
}

/// Keep `obs` unless its ASN or its country already has `cap` kept responders.
/// A reply past the cap is dropped, not held in reserve: a round that could only fill with it is short of diversity, and a short round is what min_sources is for.
/// A reply whose ASN or country is unknown cannot be shown to share an origin with anything, so it is not counted against either cap.
fn keep(kept: &mut Vec<Observation>, obs: Observation, cap: usize) {
    if let Some(asn) = obs.asn {
        if kept.iter().filter(|k| k.asn == Some(asn)).count() >= cap {
            return;
        }
    }
    if let Some(country) = &obs.country {
        if kept.iter().filter(|k| k.country.as_ref() == Some(country)).count() >= cap {
            return;
        }
    }
    kept.push(obs);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(source: &str, asn: Option<u32>, country: Option<&str>) -> Observation {
        Observation {
            source:       source.into(),
            protocol:     Protocol::Https,
            timestamp_et: 0,
            local_et:     0,
            rtt_ms:       0,
            asn,
            country:      country.map(str::to_string),
            sct_verified: false,
        }
    }

    /// The cap is an eighth of the target, never below one responder per origin.
    #[test]
    fn origin_cap_is_an_eighth_of_target() {
        assert_eq!(origin_cap(Config::default().target_sources), 42 >> 3);
        assert_eq!(origin_cap(64), 1 << 3);
        assert_eq!(origin_cap(128), 1 << 4);
        assert_eq!(origin_cap(1), 1);
        assert_eq!(origin_cap(7), 1);
    }

    /// LIB-03: a burst of fast replies from one ASN fills at most `cap` slots of the kept set, and the same for one country.
    #[test]
    fn kept_set_respects_asn_and_country_cap() {
        let cap = 2;
        let mut kept = Vec::new();
        // Six fast replies from ASN 64496 in three countries: only two survive, and the first two win.
        keep(&mut kept, obs("a1", Some(64496), Some("US")), cap);
        keep(&mut kept, obs("a2", Some(64496), Some("DE")), cap);
        keep(&mut kept, obs("a3", Some(64496), Some("GB")), cap);
        keep(&mut kept, obs("a4", Some(64496), Some("US")), cap);
        keep(&mut kept, obs("a5", Some(64496), Some("FR")), cap);
        keep(&mut kept, obs("a6", Some(64496), Some("JP")), cap);
        assert_eq!(kept.iter().filter(|k| k.asn == Some(64496)).count(), cap);
        assert_eq!(kept.iter().map(|k| k.source.as_str()).collect::<Vec<_>>(), ["a1", "a2"]);
        // A different ASN in a country already holding one keeps it; a second one in US hits the country cap.
        keep(&mut kept, obs("b1", Some(64497), Some("US")), cap);
        keep(&mut kept, obs("b2", Some(64498), Some("US")), cap);
        assert_eq!(kept.iter().filter(|k| k.country.as_deref() == Some("US")).count(), cap);
        assert!(kept.iter().any(|k| k.source == "b1"));
        assert!(!kept.iter().any(|k| k.source == "b2"));
        // Distinct origins keep flowing past the caps of others.
        keep(&mut kept, obs("c1", Some(64499), Some("NZ")), cap);
        keep(&mut kept, obs("c2", Some(64500), Some("BR")), cap);
        assert_eq!(kept.len(), 5);
        for k in &kept {
            assert!(kept.iter().filter(|o| o.asn == k.asn).count() <= cap);
            assert!(kept.iter().filter(|o| o.country == k.country).count() <= cap);
        }
    }

    /// An unknown origin cannot be shown to repeat, so it is never counted against a cap.
    #[test]
    fn unknown_origin_is_not_capped() {
        let cap = 1;
        let mut kept = Vec::new();
        keep(&mut kept, obs("u1", None, None), cap);
        keep(&mut kept, obs("u2", None, None), cap);
        keep(&mut kept, obs("u3", None, Some("US")), cap);
        keep(&mut kept, obs("u4", None, Some("US")), cap);
        assert_eq!(kept.len(), 3);
        assert!(!kept.iter().any(|k| k.source == "u4"));
    }
}
