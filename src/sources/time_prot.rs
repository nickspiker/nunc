/// RFC 868 TIME protocol — port 37.
///
/// Connect, read exactly 4 bytes.  The server sends a big-endian unsigned
/// 32-bit integer: seconds elapsed since 1900-01-01 00:00:00 UTC.
///
/// Subtract the 70-year offset (2 208 988 800 s) to get Unix time.
/// Resolution is 1 second; RTT/2 is the uncertainty.
pub mod time_prot {
    use crate::types::{Observation, Protocol};
    use std::time::Instant;

    const TIMEOUT:          std::time::Duration = std::time::Duration::from_secs(5);
    const EPOCH_OFFSET:     i64                 = 2_208_988_800; // secs between 1900 and 1970

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
        let mut tcp = TcpStream::connect(format!("{host}:37")).await.ok()?;
        let rtt_ms = t0.elapsed().as_millis() as u64;

        let mut buf = [0u8; 4];
        tcp.read_exact(&mut buf).await.ok()?;

        let secs_since_1900 = u32::from_be_bytes(buf) as i64;

        // Sanity check: must be after 2000-01-01 in 1900-epoch terms
        if secs_since_1900 < 3_155_673_600 { return None; }

        let unix_secs = secs_since_1900 - EPOCH_OFFSET;

        Some(Observation {
            source:       host,
            protocol:     Protocol::Time,
            timestamp_et: crate::eagle::from_unix(unix_secs, 0),
            rtt_ms,
            asn:          None,
            country:      None,
            sct_verified: false,
        })
    }
}
