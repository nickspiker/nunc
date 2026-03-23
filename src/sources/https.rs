#[cfg(feature = "https")]
pub mod https {
    use crate::ct;
    use crate::types::{Observation, Protocol};
    use rustls::pki_types::ServerName;
    use std::sync::{Arc, Mutex};
    use std::time::{Instant, SystemTime};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    /// Fire a HEAD request to `host` (port 443) using tokio-rustls directly so
    /// we can capture the server's certificate for SCT verification.
    ///
    /// The measured RTT covers TCP connect + TLS handshake + first response
    /// byte — consistent with how the interval intersection uses RTT as the
    /// uncertainty bound.
    /// Per-query wall-clock budget.  Covers TCP connect + TLS + response headers.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

    pub async fn query(host: &str, nonce: u64) -> Option<Observation> {
        tokio::time::timeout(TIMEOUT, query_inner(host, nonce))
            .await
            .ok()
            .flatten()
    }

    async fn query_inner(host: &str, nonce: u64) -> Option<Observation> {
        let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let config = ct::capturing_tls_config(captured.clone())?;
        let connector = TlsConnector::from(Arc::new(config));

        let t0 = Instant::now();

        let tcp = TcpStream::connect(format!("{host}:443"))
            .await
            .ok()?;

        let server_name = ServerName::try_from(host.to_string()).ok()?;
        let mut tls = connector.connect(server_name, tcp).await.ok()?;

        let rtt_ms = t0.elapsed().as_millis() as u64;

        // HEAD request with cache-busting headers
        let req = format!(
            "HEAD / HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             X-Nunc-Nonce: {nonce}\r\n\
             \r\n"
        );
        tls.write_all(req.as_bytes()).await.ok()?;

        // Read response headers (stop at \r\n\r\n or 8 KiB)
        let mut buf = vec![0u8; 8192];
        let mut total = 0usize;
        loop {
            let n = tls.read(&mut buf[total..]).await.ok()?;
            if n == 0 { break; }
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") { break; }
            if total >= buf.len() { break; }
        }

        let response = std::str::from_utf8(&buf[..total]).ok()?;

        // Reject CDN-stale responses inline: Age header reports how long ago
        // the CDN cached this response.  If > 5 s, the Date is already stale
        // and consensus would reject it anyway — drop it here instead.
        if let Some(age_s) = response.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("age:"))
            .and_then(|l| l.splitn(2, ':').nth(1))
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            if age_s > 5 { return None; }
        }

        // Parse the Date: header
        let date_str = response
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("date:"))?
            .splitn(2, ':')
            .nth(1)?
            .trim();
        let date: httpdate::HttpDate = date_str.parse().ok()?;
        let ts: SystemTime = date.into();
        let timestamp_et = crate::eagle::from_system_time(ts);

        let sct_verified = captured
            .lock()
            .unwrap()
            .as_deref()
            .map(|der| ct::verify_scts(der))
            .unwrap_or(false);

        Some(Observation {
            source:       host.to_string(),
            protocol:     Protocol::Https,
            timestamp_et,
            rtt_ms,
            asn:          None,
            country:      None,
            sct_verified,
        })
    }

    /// Query multiple hosts in parallel, each bounded by `TIMEOUT`.
    /// Returns only successful observations.
    pub async fn query_many(hosts: &[String], nonce: u64) -> Vec<Observation> {
        use futures::future::join_all;
        // The pool stores full URLs like "https://example.com/" — strip to hostname
        let futs: Vec<_> = hosts
            .iter()
            .map(|u| {
                let host = u
                    .trim_start_matches("https://")
                    .trim_end_matches('/')
                    .to_string();
                async move { query(&host, nonce).await }
            })
            .collect();
        join_all(futs).await.into_iter().flatten().collect()
    }
}
