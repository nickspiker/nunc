/// RFC 2822 date extraction from an SMTP/FTP/Daytime banner line.
///
/// Available unconditionally — used by the smtp, ftp, and daytime sources
/// all of which share the same date-string grammar.
pub(crate) fn parse_smtp_date(banner: &str) -> Option<i64> {
    let tokens: Vec<&str> = banner.split_whitespace().collect();
    let n = tokens.len();
    for i in 0..n {
        if let Some(et) = try_parse_at(&tokens[i..]) {
            return Some(et);
        }
    }
    None
}

/// Try to parse RFC 2822: [Dow,] DD Mon YYYY HH:MM:SS TZ  starting at tokens[0].
fn try_parse_at(tok: &[&str]) -> Option<i64> {
    if tok.len() < 5 { return None; }

    let (day_tok, month_tok, year_tok, time_tok, tz_tok) = if tok[0].ends_with(',') {
        if tok.len() < 6 { return None; }
        (tok[1], tok[2], tok[3], tok[4], tok[5])
    } else {
        (tok[0], tok[1], tok[2], tok[3], tok[4])
    };

    let day:  u8  = day_tok.trim_end_matches(',').parse().ok()?;
    let mon:  u8  = parse_month(month_tok)?;
    let year: i32 = year_tok.parse().ok().filter(|&y: &i32| y >= 1970 && y <= 2100)?;

    let mut time_parts = time_tok.splitn(3, ':');
    let hour: u8 = time_parts.next()?.parse().ok().filter(|&h: &u8| h < 24)?;
    let min:  u8 = time_parts.next()?.parse().ok().filter(|&m: &u8| m < 60)?;
    let sec:  u8 = time_parts.next()?.parse().ok().filter(|&s: &u8| s < 61)?;

    let tz_offset_secs: i64 = parse_tz(tz_tok)?;

    let days = days_since_unix_epoch(year, mon, day)?;
    let unix_secs = days * 86400
        + hour as i64 * 3600
        + min  as i64 * 60
        + sec  as i64
        - tz_offset_secs;

    Some(crate::eagle::from_unix(unix_secs, 0))
}

fn parse_month(s: &str) -> Option<u8> {
    match s.to_ascii_lowercase().as_str() {
        "jan" | "january"   => Some(1),
        "feb" | "february"  => Some(2),
        "mar" | "march"     => Some(3),
        "apr" | "april"     => Some(4),
        "may"               => Some(5),
        "jun" | "june"      => Some(6),
        "jul" | "july"      => Some(7),
        "aug" | "august"    => Some(8),
        "sep" | "september" => Some(9),
        "oct" | "october"   => Some(10),
        "nov" | "november"  => Some(11),
        "dec" | "december"  => Some(12),
        _ => None,
    }
}

/// Parse "+HHMM" / "-HHMM" / "GMT" / "UTC" / "UT" → seconds east of UTC.
fn parse_tz(s: &str) -> Option<i64> {
    let s = s.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '-');
    match s.to_ascii_uppercase().as_str() {
        "GMT" | "UTC" | "UT" | "Z" => return Some(0),
        "EST" => return Some(-5 * 3600),
        "EDT" => return Some(-4 * 3600),
        "CST" => return Some(-6 * 3600),
        "CDT" => return Some(-5 * 3600),
        "MST" => return Some(-7 * 3600),
        "MDT" => return Some(-6 * 3600),
        "PST" => return Some(-8 * 3600),
        "PDT" => return Some(-7 * 3600),
        _ => {}
    }
    if s.len() >= 5 && (s.starts_with('+') || s.starts_with('-')) {
        let sign: i64 = if s.starts_with('+') { 1 } else { -1 };
        let hh: i64 = s[1..3].parse().ok()?;
        let mm: i64 = s[3..5].parse().ok()?;
        return Some(sign * (hh * 3600 + mm * 60));
    }
    None
}

/// Days between 1970-01-01 and year-month-day (Gregorian).
fn days_since_unix_epoch(year: i32, month: u8, day: u8) -> Option<i64> {
    if month < 1 || month > 12 || day < 1 || day > 31 { return None; }
    let m = month as i32;
    let d = day as i32;
    let y = if m <= 2 { year - 1 } else { year };
    let m2 = if m <= 2 { m + 9 } else { m - 3 };
    let c = y / 100;
    let r = y % 100;
    let jdn = (146097 * c) / 4
        + (1461 * r) / 4
        + (153 * m2 + 2) / 5
        + d + 1721119;
    Some((jdn - 2440588) as i64)
}

// ──────────────────────────────────────────────────────────────────────────────
// SMTP query — gated behind the "smtp" feature (needs TcpStream to port 25)
// ──────────────────────────────────────────────────────────────────────────────

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
    /// Runs the blocking socket work on a `spawn_blocking` thread so it
    /// does not stall the async executor.
    pub async fn query(host: &str) -> Option<Observation> {
        let host = host.to_string();
        tokio::task::spawn_blocking(move || query_blocking(&host))
            .await
            .ok()
            .flatten()
    }

    fn query_blocking(host: &str) -> Option<Observation> {
        let addr = format!("{}:25", host);
        let t0 = Instant::now();

        let stream = TcpStream::connect_timeout(
            &addr.parse().ok()?,
            Duration::from_secs(3),
        ).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;

        let rtt_ms = t0.elapsed().as_millis() as u64;
        let reader = BufReader::new(stream);

        for line in reader.lines().flatten() {
            if line.starts_with("220 ") {
                if let Some(ts) = super::parse_smtp_date(&line) {
                    return Some(Observation {
                        source:       host.to_string(),
                        protocol:     Protocol::Smtp,
                        timestamp_et: ts,
                        rtt_ms,
                        asn:          None,
                        country:      None,
                        sct_verified: false,
                    });
                }
                break;
            }
        }

        None
    }

    #[cfg(test)]
    mod tests {
        use super::super::parse_smtp_date;

        #[test]
        fn parse_banner_with_dow() {
            let banner = "220 mail.example.com ESMTP Postfix; Fri, 21 Mar 2025 12:00:00 +0000";
            assert!(parse_smtp_date(banner).is_some());
        }

        #[test]
        fn parse_banner_without_dow() {
            let banner = "220 mx.example.org ESMTP ready 21 Mar 2025 12:00:00 GMT";
            assert!(parse_smtp_date(banner).is_some());
        }

        #[test]
        fn parse_negative_tz() {
            let banner = "220 smtp.example.com ESMTP Fri, 21 Mar 2025 08:00:00 -0400";
            let et = parse_smtp_date(banner).expect("should parse");
            let banner_utc = "220 smtp.example.com ESMTP Fri, 21 Mar 2025 12:00:00 +0000";
            let et_utc = parse_smtp_date(banner_utc).expect("should parse");
            assert_eq!(et, et_utc);
        }
    }
}
