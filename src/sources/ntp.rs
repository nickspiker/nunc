#[cfg(feature = "ntp")]
pub mod ntp {
    use crate::types::{Observation, Protocol};

    pub async fn query(host: &str) -> Option<Observation> {
        use rsntp::AsyncSntpClient;
        use std::time::Instant;

        let client = AsyncSntpClient::new();
        let t0 = Instant::now();
        let result = client.synchronize(host).await.ok()?;
        let rtt_ms = t0.elapsed().as_millis() as u64;

        let unix = result
            .datetime()
            .into_chrono_datetime()
            .ok()?
            .timestamp() as u64;

        Some(Observation {
            source:    host.to_string(),
            protocol:  Protocol::Ntp,
            timestamp: unix,
            rtt_ms,
            asn:       None,
            country:   None,
        })
    }
}
