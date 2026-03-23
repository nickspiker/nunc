/// FTP 220 banner — port 21.
///
/// Many FTP servers embed a date/time in their greeting line, especially
/// older vsftpd, wu-ftpd, and ProFTPD installs at universities and ISPs.
///
/// Examples:
///   "220 ftp.example.com FTP server ready Mon Mar 24 18:30:00 2026"
///   "220 ProFTPD Server (ftp.uni-example.de) [::ffff:1.2.3.4] Mon, 24 Mar 2026 18:30:00 +0000"
///   "220-FileZilla Server 1.8.0"   ← no date, will return None
///
/// We reuse the SMTP RFC 2822 scanner since the date format is the same.
/// Runs on spawn_blocking (blocking I/O, same as SMTP).
pub mod ftp {
    use crate::types::{Observation, Protocol};
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
    const READ_TIMEOUT:    Duration = Duration::from_secs(4);

    pub async fn query(host: &str) -> Option<Observation> {
        let host = host.to_string();
        tokio::task::spawn_blocking(move || query_blocking(&host))
            .await
            .ok()
            .flatten()
    }

    fn query_blocking(host: &str) -> Option<Observation> {
        let addr = format!("{host}:21");
        let t0 = Instant::now();

        let stream = TcpStream::connect_timeout(&addr.parse().ok()?, CONNECT_TIMEOUT).ok()?;
        stream.set_read_timeout(Some(READ_TIMEOUT)).ok()?;

        let rtt_ms = t0.elapsed().as_millis() as u64;
        let reader = BufReader::new(stream);

        for line in reader.lines().flatten() {
            // 220 or 220- (multi-line greeting)
            if line.starts_with("220") {
                if let Some(ts) = crate::sources::smtp::parse_smtp_date(&line) {
                    return Some(Observation {
                        source:       host.to_string(),
                        protocol:     Protocol::Ftp,
                        timestamp_et: ts,
                        rtt_ms,
                        asn:          None,
                        country:      None,
                        sct_verified: false,
                    });
                }
                // Keep reading multi-line greeting (220-) for a date
                if !line.starts_with("220-") { break; }
            } else {
                break;
            }
        }

        None
    }
}
