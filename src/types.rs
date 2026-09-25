use std::time::{Duration, SystemTime};

/// The output of a successful consensus query.
///
/// Primary representation is Eagle Time — 21 cm hydrogen-1 hyperfine oscillation counts since the Apollo 11 lunar landing (1969-07-20 20:17:40 UTC),
/// at 704 ps resolution.  Use `.timestamp()` / `.confidence()` for std types.
#[derive(Debug, Clone)]
pub struct NuncTime {
    /// Consensus midpoint in Eagle Time oscillation counts.
    pub timestamp_et:    i64,
    /// Confidence half-width in oscillation counts.
    /// True time lies within `timestamp_et ± confidence_et` with high probability.
    pub confidence_et:   i64,
    /// Consensus OFFSET: true time − local clock, in oscillations. THE primary result — the
    /// consensus is computed in this space (see `crate::consensus`), and `timestamp_et` is derived
    /// from it. A caller disciplining its own clock wants this and `local_et`, never the absolute
    /// timestamp: an absolute time says nothing about WHEN it was true, and a query runs for seconds.
    pub offset_et:       i64,
    /// The local clock reading (Eagle Time) that `offset_et` is anchored to — i.e.
    /// `timestamp_et == local_et + offset_et`, exactly, with no sampling on the caller's side.
    pub local_et:        i64,
    pub sources_queried: usize,
    /// Sources that fell within the consensus window (outliers excluded).
    pub sources_used:    usize,
    pub outliers:        Vec<OutlierReport>,
    /// KS p-value against a fitted normal distribution.
    /// High (→1): timestamp distribution looks honest/unimodal.
    /// Low (→0): bimodal or otherwise anomalous — manipulation signal.
    pub ks_p_value:      f64,
    /// Raw observations — populated when `Config::instrument` is true.
    /// Dump to CSV/JSON and plot to tune rejection thresholds empirically.
    pub raw:             Vec<Observation>,
}

impl NuncTime {
    /// Consensus timestamp as `std::time::SystemTime`.
    pub fn timestamp(&self) -> SystemTime {
        crate::eagle::to_system_time(self.timestamp_et)
    }
    /// Confidence half-width as `std::time::Duration`.
    pub fn confidence(&self) -> Duration {
        crate::eagle::to_duration(self.confidence_et.abs())
    }
    /// Consensus offset (true − local) as a signed `Duration`: `(ahead, magnitude)` where `ahead`
    /// is true when the local clock is BEHIND true time.
    pub fn offset(&self) -> (bool, Duration) {
        (self.offset_et >= 0, crate::eagle::to_duration(self.offset_et.abs()))
    }
}

/// One raw observation before any consensus logic is applied.
/// This is the instrumentation record — log everything, decide later.
#[derive(Debug, Clone)]
pub struct Observation {
    pub source:        String,
    pub protocol:      Protocol,
    pub timestamp_et:  i64,      // Eagle Time: the SOURCE's time at the MIDDLE of the round trip (consensus adds rtt/2 to reach receipt)
    pub rtt_ms:        u64,
    /// The LOCAL clock, in Eagle Time, read the moment this source's response arrived.
    /// Pairs with `timestamp_et` to make an OFFSET (`crate::consensus` works in offsets, not absolute
    /// times): sources answer at different instants spread over the whole query, so comparing their
    /// absolute timestamps to each other silently smears that spread into the result. An offset is
    /// anchored to the instant it was measured and stays valid however long the query runs.
    pub local_et:      i64,
    pub asn:           Option<u32>,
    pub country:       Option<String>,
    /// True if an SCT from a known CT log was successfully verified for this source's TLS certificate.  False if verification failed or was not attempted (e.g. non-HTTPS sources).
    pub sct_verified:  bool,
}

impl Observation {
    /// Serialize to a JSON object string.  No serde dependency.
    pub fn to_json(&self) -> String {
        let proto = match self.protocol {
            Protocol::Https     => "Https",
            Protocol::Ntp       => "Ntp",
            Protocol::Smtp      => "Smtp",
            Protocol::Roughtime => "Roughtime",
            Protocol::Daytime   => "Daytime",
            Protocol::Time      => "Time",
            Protocol::Ftp       => "Ftp",
            Protocol::Nts       => "Nts",
        };
        let asn = match self.asn {
            None    => "null".to_string(),
            Some(n) => n.to_string(),
        };
        let country = match &self.country {
            None    => "null".to_string(),
            Some(c) => format!("\"{}\"", c.replace('"', "\\\"")),
        };
        format!(
            "{{\"source\":\"{source}\",\"protocol\":\"{proto}\",\
             \"timestamp_et\":{ts},\"local_et\":{local},\"rtt_ms\":{rtt},\
             \"asn\":{asn},\"country\":{country},\
             \"sct_verified\":{sct}}}",
            source = self.source.replace('"', "\\\""),
            ts     = self.timestamp_et,
            local  = self.local_et,
            rtt    = self.rtt_ms,
            sct    = self.sct_verified,
        )
    }
}

/// A source whose reported time fell outside the consensus window.
#[derive(Debug, Clone)]
pub struct OutlierReport {
    pub source:    String,
    pub protocol:  Protocol,
    pub delta_ms:  i64,   // signed: positive = ahead of consensus
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Https,
    Ntp,
    Smtp,
    Roughtime,
    /// RFC 867 — port 13, returns human-readable ASCII date/time string.
    Daytime,
    /// RFC 868 — port 37, returns 4-byte big-endian seconds since 1900-01-01.
    Time,
    /// FTP 220 banner — many servers embed a date in the greeting line.
    Ftp,
    /// RFC 8915 — NTS-KE (TLS 1.3 on port 4460) + authenticated NTPv4 (UDP 123).
    /// Sub-millisecond precision with Ed25519/AEAD authentication.
    Nts,
}

/// A server entry from the pool.
#[derive(Debug, Clone)]
pub struct ServerEntry {
    pub host:     String,
    pub protocol: Protocol,
    pub asn:      Option<u32>,
    pub country:  Option<String>,
    /// Organizational category — used for cross-category diversity in selection.
    /// e.g. "central_bank", "metrology", "broadcaster", "university",
    ///      "government", "postal", "railway", "telco", "ntp_pool", "ntp_stratum1"
    pub category: Option<String>,
}
