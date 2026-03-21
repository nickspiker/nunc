use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

/// The output of a successful consensus query.
///
/// `confidence` is the half-width of the agreement interval — i.e. the true
/// time is `timestamp ± confidence` with high probability given the sources
/// that agreed.  Caller decides whether that's tight enough for their use case.
#[derive(Debug, Clone)]
pub struct NuncTime {
    pub timestamp:       SystemTime,
    /// Half-width of the consensus interval.
    pub confidence:      Duration,
    pub sources_queried: usize,
    /// Sources that fell within the consensus window (outliers excluded).
    pub sources_used:    usize,
    pub outliers:        Vec<OutlierReport>,
    /// Raw observations — populated when `Config::instrument` is true.
    /// Dump to CSV/JSON and plot to tune rejection thresholds empirically.
    pub raw:             Vec<Observation>,
}

/// One raw observation before any consensus logic is applied.
/// This is the instrumentation record — log everything, decide later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub source:    String,
    pub protocol:  Protocol,
    pub timestamp: u64,      // unix seconds
    pub rtt_ms:    u64,
    pub asn:       Option<u32>,
    pub country:   Option<String>,
}

/// A source whose reported time fell outside the consensus window.
#[derive(Debug, Clone)]
pub struct OutlierReport {
    pub source:    String,
    pub protocol:  Protocol,
    pub delta_ms:  i64,   // signed: positive = ahead of consensus
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Https,
    Ntp,
    Smtp,
    Roughtime,
}

/// A server entry from the pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub host:     String,
    pub protocol: Protocol,
    pub asn:      Option<u32>,
    pub country:  Option<String>,
}
