#[cfg(feature = "https")]
pub mod https {
    use crate::types::{Observation, Protocol};

    /// Fire a HEAD request to `url`, extract the `Date:` header, and return
    /// an Observation.
    ///
    /// Stale CDN detection: if the returned Date is older than the measured
    /// RTT (i.e. the server sent a cached timestamp that predates our request),
    /// we still return the observation and let the consensus layer reject it as
    /// an outlier.  The caller can also inspect `raw` observations and filter
    /// on `rtt_ms > some_threshold` if needed.
    ///
    /// Cache-busting: we send `Cache-Control: no-cache` and a random
    /// `X-Nunc-Nonce` header to discourage CDN response reuse.
    pub async fn query(url: &str, nonce: u64) -> Option<Observation> {
        use reqwest::header::{CACHE_CONTROL, DATE};
        use std::time::Instant;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .ok()?;

        let t0 = Instant::now();
        let resp = client
            .head(url)
            .header(CACHE_CONTROL, "no-cache, no-store")
            .header("X-Nunc-Nonce", nonce.to_string())
            .send()
            .await
            .ok()?;
        let rtt_ms = t0.elapsed().as_millis() as u64;

        let date_str = resp.headers().get(DATE)?.to_str().ok()?;
        let date: httpdate::HttpDate = date_str.parse().ok()?;
        let ts: std::time::SystemTime = date.into();
        let unix = ts
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();

        Some(Observation {
            source:    url.to_string(),
            protocol:  Protocol::Https,
            timestamp: unix,
            rtt_ms,
            asn:       None, // TODO: MaxMind GeoLite2 lookup
            country:   None,
        })
    }

    /// Query multiple URLs in parallel.  Returns only successful observations.
    pub async fn query_many(urls: &[String], nonce: u64) -> Vec<Observation> {
        use futures::future::join_all;
        let futs: Vec<_> = urls.iter().map(|u| query(u, nonce)).collect();
        join_all(futs).await.into_iter().flatten().collect()
    }
}
