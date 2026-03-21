#[cfg(feature = "smtp")]
pub mod smtp {
    use crate::types::{Observation, Protocol};
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    /// Connect to `host:25`, read the SMTP banner, extract the timestamp.
    ///
    /// The banner arrives before we send anything — the timestamp is fresh
    /// by definition, not a cached response.  Port 25 is blocked by most
    /// consumer ISPs outbound; this source is most useful in datacenter
    /// or server environments.
    ///
    /// Banner format (RFC 5321):
    ///   220 mail.example.com ESMTP Postfix (Ubuntu) -- Fri, 21 Mar 2025 12:00:00 +0000
    ///
    /// Timestamp position varies by MTA.  We scan tokens for a parseable date.
    pub fn query(host: &str) -> Option<Observation> {
        let addr = format!("{}:25", host);
        let t0 = Instant::now();

        let stream = TcpStream::connect_timeout(
            &addr.parse().ok()?,
            Duration::from_secs(3),
        ).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;

        let rtt_ms = t0.elapsed().as_millis() as u64;
        let reader = BufReader::new(stream);

        // Read lines until we see the "220 " greeting
        for line in reader.lines().flatten() {
            if line.starts_with("220 ") {
                if let Some(unix) = parse_smtp_date(&line) {
                    return Some(Observation {
                        source:    host.to_string(),
                        protocol:  Protocol::Smtp,
                        timestamp: unix,
                        rtt_ms,
                        asn:       None,
                        country:   None,
                    });
                }
                break; // 220 line found but no parseable date — give up
            }
        }

        None
    }

    /// Best-effort RFC 2822 date extraction from an SMTP banner line.
    /// Returns unix seconds or None.
    fn parse_smtp_date(banner: &str) -> Option<u64> {
        // TODO: implement RFC 2822 date scanning across banner tokens
        // For now: stub returning None until we validate real banner formats
        // against a sample of live mail servers.
        let _ = banner;
        None
    }
}
