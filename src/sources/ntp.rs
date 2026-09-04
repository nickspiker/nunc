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
        let _ = t0; // NTP carries its own delay figure; the wall-clock timing below is not used.

        let dt = result.datetime().into_chrono_datetime().ok()?;
        let timestamp_et = crate::eagle::from_unix(
            dt.timestamp(),
            dt.timestamp_subsec_nanos(),
        );

        // NTP's OWN four-timestamp offset (t1..t4), not a reconstruction from the transmit stamp:
        // it cancels the symmetric part of the path delay, which a bare `server_time` + wall-clock
        // subtraction cannot. Measured against an independent reference, reconstructing left a
        // ~40 ms bias on this pool (servers are deliberately far away for anti-collusion, so the
        // one-way delay is large). `round_trip_delay` is likewise the protocol's own figure —
        // strictly better than timing the future, which also counts DNS and task scheduling.
        let offset_et = {
            let d = result.clock_offset().abs_as_std_duration().ok()?;
            let mag = crate::eagle::from_unix(d.as_secs() as i64, d.subsec_nanos())
                - crate::eagle::from_unix(0, 0);
            if result.clock_offset().signum() < 0 { -mag } else { mag }
        };
        let rtt_ms = result
            .round_trip_delay()
            .abs_as_std_duration()
            .ok()?
            .as_millis() as u64;
        // The anchor implied by that offset: true = local + offset, so local = server_time − offset.
        let local_et = timestamp_et - offset_et;

        Some(Observation {
            source:       host.to_string(),
            protocol:     Protocol::Ntp,
            timestamp_et,
            rtt_ms,
            local_et,
            asn:          None,
            country:      None,
            sct_verified: false,
        })
    }
}
