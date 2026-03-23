/// IETF Roughtime client — draft-ietf-ntp-roughtime (RFC Editor Queue 2026-03-22).
///
/// One UDP round-trip → Ed25519-signed timestamp from a trusted server.
/// No external PKI: server identity is pinned via hardcoded Ed25519 public keys.
///
/// Wire format: tagged message (little-endian TLV, tags in ascending u32 order).
/// Signing context strings per draft-ietf-ntp-roughtime §5:
///   CERT.SIG covers: CTX_DELE || DELE_value_bytes
///   resp.SIG covers:  CTX_SREP || SREP_value_bytes
#[cfg(feature = "roughtime")]
pub mod roughtime {
    use crate::types::{Observation, Protocol};
    use ring::signature::{self, UnparsedPublicKey};
    use std::collections::HashMap;
    use std::time::Instant;
    use tokio::net::UdpSocket;

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    // -----------------------------------------------------------------------
    // Tag constants — 4-byte ASCII identifiers interpreted as LE u32.
    // Tags within each message must appear in strictly ascending numerical order.
    // -----------------------------------------------------------------------
    const fn tag(b: &[u8; 4]) -> u32 { u32::from_le_bytes(*b) }

    const TAG_SIG:  u32 = tag(b"SIG\x00");
    const TAG_NONC: u32 = tag(b"NONC");
    const TAG_DELE: u32 = tag(b"DELE");
    const TAG_PUBK: u32 = tag(b"PUBK");
    const TAG_MIDP: u32 = tag(b"MIDP");
    const TAG_SREP: u32 = tag(b"SREP");
    const TAG_CERT: u32 = tag(b"CERT");
    const TAG_PAD:  u32 = tag(b"PAD\xff");

    // -----------------------------------------------------------------------
    // Signing context strings, per draft-ietf-ntp-roughtime §5.
    // -----------------------------------------------------------------------
    const CTX_SREP: &[u8] = b"RoughTime v1 response signature\x00";
    const CTX_DELE: &[u8] = b"RoughTime v1 delegation signature\x00";

    // -----------------------------------------------------------------------
    // Known server Ed25519 public keys (32 bytes each).
    // Source: https://github.com/cloudflare/roughtime/blob/master/ecosystem.json
    // -----------------------------------------------------------------------

    /// roughtime.cloudflare.com:2003
    /// b64: "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
    const CLOUDFLARE_PUBKEY: &[u8] = &[
        0xD0, 0x60, 0xFB, 0x73, 0x7C, 0x8F, 0xF3, 0x11,
        0x1C, 0xE1, 0x99, 0x76, 0xCD, 0xEB, 0x8D, 0xD9,
        0x29, 0x4B, 0xBC, 0x35, 0x55, 0xA1, 0xC8, 0xEC,
        0x3D, 0x22, 0xFC, 0xFD, 0x19, 0x7F, 0xEF, 0x38,
    ];

    /// roughtime.int08h.com:2002
    /// b64: "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE="
    const INT08H_PUBKEY: &[u8] = &[
        0x01, 0x6E, 0x6E, 0x02, 0x84, 0xD2, 0x4C, 0x37,
        0xC6, 0xE4, 0xD7, 0xD8, 0xD5, 0xB4, 0xE1, 0xD3,
        0xC1, 0x94, 0x9C, 0xEA, 0xA5, 0x45, 0xBF, 0x87,
        0x56, 0x16, 0xC9, 0xDC, 0xE0, 0xC9, 0xBE, 0xC1,
    ];

    /// roughtime.se:2002
    /// b64: "S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI="
    const ROUGHTIME_SE_PUBKEY: &[u8] = &[
        0x4B, 0x70, 0x33, 0x7D, 0x92, 0x79, 0x0A, 0x34,
        0x9D, 0x90, 0x9D, 0xB5, 0x64, 0x91, 0x9B, 0xC6,
        0xA7, 0x58, 0x3F, 0xF4, 0xA8, 0x13, 0xC7, 0xD7,
        0x29, 0x8D, 0x3E, 0x6A, 0x27, 0x2C, 0x7A, 0x12,
    ];

    /// Look up the pinned public key for a known host. Returns None for unknown hosts.
    fn pinned_key(host: &str) -> Option<&'static [u8]> {
        match host {
            "roughtime.cloudflare.com" => Some(CLOUDFLARE_PUBKEY),
            "roughtime.int08h.com"     => Some(INT08H_PUBKEY),
            "roughtime.se"             => Some(ROUGHTIME_SE_PUBKEY),
            _                          => None,
        }
    }

    /// UDP port for each known host.
    fn server_port(host: &str) -> u16 {
        match host {
            "roughtime.cloudflare.com" => 2003,
            _                          => 2002,
        }
    }

    // -----------------------------------------------------------------------
    // Tagged message codec
    //
    // Format (wire):
    //   [num_tags: u32 LE]
    //   [(num_tags − 1) × offset: u32 LE]   -- cumulative end-offsets of values
    //   [num_tags × tag_id: u32 LE]          -- in strictly ascending order
    //   [concatenated values]
    // -----------------------------------------------------------------------

    fn parse_message(data: &[u8]) -> Option<HashMap<u32, &[u8]>> {
        if data.len() < 4 { return None; }
        let num_tags = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if num_tags == 0 { return Some(HashMap::new()); }

        let offsets_end = 4 + (num_tags - 1) * 4;
        let tags_end    = offsets_end + num_tags * 4;
        if data.len() < tags_end { return None; }

        let offsets: Vec<usize> = (0..num_tags - 1)
            .map(|i| u32::from_le_bytes(
                data[4 + i*4 .. 4 + i*4 + 4].try_into().unwrap()
            ) as usize)
            .collect();

        let tags: Vec<u32> = (0..num_tags)
            .map(|i| u32::from_le_bytes(
                data[offsets_end + i*4 .. offsets_end + i*4 + 4].try_into().unwrap()
            ))
            .collect();

        let value_region = &data[tags_end..];
        let mut map = HashMap::with_capacity(num_tags);
        for (i, &tag) in tags.iter().enumerate() {
            let start = if i == 0 { 0 } else { offsets[i - 1] };
            let end   = if i + 1 < num_tags { offsets[i] } else { value_region.len() };
            if start > value_region.len() || end > value_region.len() || start > end {
                return None;
            }
            map.insert(tag, &value_region[start..end]);
        }
        Some(map)
    }

    fn build_request(nonce: &[u8; 64]) -> Vec<u8> {
        // 2 tags: NONC (sorted before PAD numerically — verified at compile time below)
        // Header: 4 (num_tags) + 4 (1 offset) + 8 (2 tag IDs) = 16 bytes
        // Values: 64 (NONC) + 944 (PAD zeros) = 1008 → total 1024 bytes
        const _: () = assert!(TAG_NONC < TAG_PAD, "tags must be in ascending order");

        let mut msg = Vec::with_capacity(1024);
        msg.extend_from_slice(&2u32.to_le_bytes());        // num_tags = 2
        msg.extend_from_slice(&64u32.to_le_bytes());       // offset: PAD values start at byte 64
        msg.extend_from_slice(&TAG_NONC.to_le_bytes());    // tag 0: NONC
        msg.extend_from_slice(&TAG_PAD.to_le_bytes());     // tag 1: PAD
        msg.extend_from_slice(nonce);                       // NONC value (64 bytes)
        msg.resize(1024, 0u8);                              // PAD zeros to 1024
        msg
    }

    // -----------------------------------------------------------------------
    // Response verification and timestamp extraction.
    //
    // Verification chain:
    //   1. CERT.SIG: server_long_term_pubkey signs (CTX_DELE || DELE_bytes)
    //   2. resp.SIG: delegation_pubkey signs (CTX_SREP || SREP_bytes)
    //   3. MIDP extracted from SREP (microseconds since Unix epoch)
    //
    // Merkle tree nonce inclusion (PATH/INDX/ROOT) is intentionally skipped
    // for the initial implementation; the two-layer Ed25519 chain is the
    // primary tamper-evidence mechanism.
    // -----------------------------------------------------------------------

    fn verify_and_extract(
        response: &[u8],
        server_pubkey: &[u8],
    ) -> Option<u64> {
        let resp      = parse_message(response)?;
        let sig_bytes = resp.get(&TAG_SIG)?;
        let srep_raw  = resp.get(&TAG_SREP)?;
        let cert_raw  = resp.get(&TAG_CERT)?;

        // Step 1: verify CERT — server long-term key signs delegation.
        let cert      = parse_message(cert_raw)?;
        let cert_sig  = cert.get(&TAG_SIG)?;
        let dele_raw  = cert.get(&TAG_DELE)?;

        let mut cert_signed = CTX_DELE.to_vec();
        cert_signed.extend_from_slice(dele_raw);
        UnparsedPublicKey::new(&signature::ED25519, server_pubkey)
            .verify(&cert_signed, cert_sig)
            .ok()?;

        // Step 2: verify response — delegation key signs SREP.
        let dele      = parse_message(dele_raw)?;
        let dele_pubk = dele.get(&TAG_PUBK)?;

        let mut srep_signed = CTX_SREP.to_vec();
        srep_signed.extend_from_slice(srep_raw);
        UnparsedPublicKey::new(&signature::ED25519, dele_pubk)
            .verify(&srep_signed, sig_bytes)
            .ok()?;

        // Step 3: extract MIDP (microseconds since Unix epoch, u64 LE).
        let srep = parse_message(srep_raw)?;
        let midp = srep.get(&TAG_MIDP)?;
        if midp.len() < 8 { return None; }
        Some(u64::from_le_bytes(midp[..8].try_into().ok()?))
    }

    // -----------------------------------------------------------------------
    // Public query entry point
    // -----------------------------------------------------------------------

    pub async fn query(host: &str) -> Option<Observation> {
        let pubkey = pinned_key(host)?;
        let port   = server_port(host);
        let host   = host.to_string();
        tokio::time::timeout(TIMEOUT, query_inner(host, port, pubkey))
            .await
            .ok()
            .flatten()
    }

    async fn query_inner(host: String, port: u16, pubkey: &'static [u8]) -> Option<Observation> {
        use rand::RngCore;

        let mut nonce = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut nonce);

        let request = build_request(&nonce);

        let addr = tokio::net::lookup_host(format!("{host}:{port}"))
            .await.ok()?.next()?;

        let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;

        let t0 = Instant::now();
        sock.send_to(&request, addr).await.ok()?;

        let mut buf = vec![0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf).await.ok()?;
        let rtt_ms = t0.elapsed().as_millis() as u64;
        buf.truncate(len);

        let midp_us  = verify_and_extract(&buf, pubkey)?;
        let unix_secs  = (midp_us / 1_000_000) as i64;
        let unix_nanos = ((midp_us % 1_000_000) * 1_000) as u32;

        Some(Observation {
            source:       format!("{host}:{port}"),
            protocol:     Protocol::Roughtime,
            timestamp_et: crate::eagle::from_unix(unix_secs, unix_nanos),
            rtt_ms,
            asn:          None,
            country:      None,
            sct_verified: false,
        })
    }
}
