/// RFC 867 Daytime protocol — port 13.
///
/// Connect, read the ASCII response, parse the date.  No request is sent;
/// the server writes immediately on connect.
///
/// Two formats seen in the wild:
///
///   NIST:    "59535 26-083 18:30:00 00 0 0 914.8 UTC(NIST) *\r\n"
///            Fields: MJD YY-DDD HH:MM:SS TT L H msADV UTC(NIST) OTM
///
///   Generic: "Wednesday, March 21, 2026 18:30:00 UTC"
///            or any RFC 2822-ish string
///
/// We try NIST format first (field 2 = YY-DDD, field 3 = HH:MM:SS),
/// then fall back to the SMTP RFC 2822 scanner.
pub mod daytime {
    use crate::types::{Observation, Protocol};
    use std::time::Instant;

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    pub async fn query(host: &str) -> Option<Observation> {
        let host = host.to_string();
        tokio::time::timeout(TIMEOUT, query_inner(host))
            .await
            .ok()
            .flatten()
    }

    async fn query_inner(host: String) -> Option<Observation> {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        let t0 = Instant::now();
        let mut tcp = TcpStream::connect(format!("{host}:13")).await.ok()?;
        let rtt_ms = t0.elapsed().as_millis() as u64;

        let mut buf = vec![0u8; 256];
        let n = tcp.read(&mut buf).await.ok()?;
        let line = std::str::from_utf8(&buf[..n]).ok()?.trim().to_string();

        let timestamp_et = parse_daytime(&line)?;

        Some(Observation {
            source:       host,
            protocol:     Protocol::Daytime,
            timestamp_et,
            rtt_ms,
            asn:          None,
            country:      None,
            sct_verified: false,
        })
    }

    /// Try NIST format, then RFC 2822 fallback.
    fn parse_daytime(line: &str) -> Option<i64> {
        parse_nist(line).or_else(|| crate::sources::smtp::parse_smtp_date(line))
    }

    /// NIST daytime: "JJJJJ YY-DDD HH:MM:SS TT L H msADV UTC(NIST) OTM"
    /// We only need fields [1] (YY-DDD) and [2] (HH:MM:SS); everything is UTC.
    fn parse_nist(line: &str) -> Option<i64> {
        let mut parts = line.split_whitespace();
        let _mjd = parts.next()?;                  // JJJJJ — skip
        let yyddd = parts.next()?;                 // YY-DDD
        let hhmmss = parts.next()?;               // HH:MM:SS

        let mut ymd = yyddd.splitn(2, '-');
        let yy: u32 = ymd.next()?.parse().ok()?;
        let ddd: u32 = ymd.next()?.parse().ok()?;

        // Two-digit year: NIST started this service in 1990, so 00–89 = 2000–2089
        let year: i32 = if yy >= 90 { 1900 + yy as i32 } else { 2000 + yy as i32 };

        // Day-of-year → month + day (Gregorian)
        let (month, day) = doy_to_md(year, ddd)?;

        let mut t = hhmmss.splitn(3, ':');
        let hour: u64 = t.next()?.parse().ok()?;
        let min:  u64 = t.next()?.parse().ok()?;
        let sec:  u64 = t.next()?.parse().ok()?;

        let days = days_since_unix_epoch(year, month, day)?;
        let unix_secs = days + (hour * 3600 + min * 60 + sec) as i64;

        Some(crate::eagle::from_unix(unix_secs, 0))
    }

    fn is_leap(y: i32) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }

    fn doy_to_md(year: i32, doy: u32) -> Option<(u8, u8)> {
        let days_in = [31u32, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30,
                       31, 31, 30, 31, 30, 31];
        let mut rem = doy;
        for (i, &d) in days_in.iter().enumerate() {
            if rem <= d { return Some((i as u8 + 1, rem as u8)); }
            rem -= d;
        }
        None
    }

    fn days_since_unix_epoch(year: i32, month: u8, day: u8) -> Option<i64> {
        let m = month as i32;
        let d = day as i32;
        let y = if m <= 2 { year - 1 } else { year };
        let m2 = if m <= 2 { m + 9 } else { m - 3 };
        let c = y / 100;
        let r = y % 100;
        let jdn = (146097 * c) / 4 + (1461 * r) / 4 + (153 * m2 + 2) / 5 + d + 1721119;
        Some((jdn - 2440588) as i64)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn nist_format() {
            // 2026-03-24 18:30:00 UTC — day 083
            let line = "59997 26-083 18:30:00 00 0 0  50.0 UTC(NIST) *";
            assert!(parse_daytime(line).is_some());
        }

        #[test]
        fn rfc2822_fallback() {
            let line = "Monday, 24 Mar 2026 18:30:00 +0000";
            assert!(parse_daytime(line).is_some());
        }
    }
}
