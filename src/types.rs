use std::time::{Duration, SystemTime};

/// The output of a successful consensus query.
///
/// Primary representation is Eagle Time — 21 cm hydrogen-1 hyperfine
/// oscillation counts since the Apollo 11 lunar landing (1969-07-20 20:17:40 UTC),
/// at 704 ps resolution.  Use `.timestamp()` / `.confidence()` for std types.
#[derive(Debug, Clone)]
pub struct NuncTime {
    /// Consensus midpoint in Eagle Time oscillation counts.
    pub timestamp_et:    i64,
    /// Confidence half-width in oscillation counts.
    /// True time lies within `timestamp_et ± confidence_et` with high probability.
    pub confidence_et:   i64,
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
}

/// One raw observation before any consensus logic is applied.
/// This is the instrumentation record — log everything, decide later.
#[derive(Debug, Clone)]
pub struct Observation {
    pub source:        String,
    pub protocol:      Protocol,
    pub timestamp_et:  i64,      // Eagle Time oscillation count
    pub rtt_ms:        u64,
    pub asn:           Option<u32>,
    pub country:       Option<String>,
    /// True if an SCT from a known CT log was successfully verified for this
    /// source's TLS certificate.  False if verification failed or was not
    /// attempted (e.g. non-HTTPS sources).
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
             \"timestamp_et\":{ts},\"rtt_ms\":{rtt},\
             \"asn\":{asn},\"country\":{country},\
             \"sct_verified\":{sct}}}",
            source = self.source.replace('"', "\\\""),
            ts     = self.timestamp_et,
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
