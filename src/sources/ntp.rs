#[cfg(feature = "ntp")]
pub mod ntp {
    use crate::types::{Observation, Protocol};

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    pub async fn query(host: &str) -> Option<Observation> {
        tokio::time::timeout(TIMEOUT, query_inner(host))
            .await
            .ok()
            .flatten()
    }

    async fn query_inner(host: &str) -> Option<Observation> {
        use rsntp::AsyncSntpClient;
        use std::time::Instant;

        let client = AsyncSntpClient::new();
        let t0 = Instant::now();
        let result = client.synchronize(host).await.ok()?;
        let rtt_ms = t0.elapsed().as_millis() as u64;

        let dt = result.datetime().into_chrono_datetime().ok()?;
        let timestamp_et = crate::eagle::from_unix(
            dt.timestamp(),
            dt.timestamp_subsec_nanos(),
        );

        Some(Observation {
            source:       host.to_string(),
            protocol:     Protocol::Ntp,
            timestamp_et,
            rtt_ms,
            asn:          None,
            country:      None,
            sct_verified: false,
        })
    }
}
