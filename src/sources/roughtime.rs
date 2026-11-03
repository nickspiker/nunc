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
    const TAG_ROOT: u32 = tag(b"ROOT");
    const TAG_PATH: u32 = tag(b"PATH");
    const TAG_INDX: u32 = tag(b"INDX");
    const TAG_MINT: u32 = tag(b"MINT");
    const TAG_MAXT: u32 = tag(b"MAXT");

    // -----------------------------------------------------------------------
    // Signing context strings, per draft-ietf-ntp-roughtime §5.
    // -----------------------------------------------------------------------
    const CTX_SREP: &[u8] = b"RoughTime v1 response signature\x00";
    const CTX_DELE: &[u8] = b"RoughTime v1 delegation signature\x00";
    /// The pre-IETF (Google) delegation context, two dashes longer. Our request carries no VER tag, so every server answers in that format (a 64-byte ROOT, microsecond timestamps), and this is the context its CERT.SIG was made under; until 2026-11-03 only the IETF string was tried, so no reply ever verified and Roughtime contributed nothing to the consensus.
    const CTX_DELE_LEGACY: &[u8] = b"RoughTime v1 delegation signature--\x00";

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
    //   4. The response commits to OUR nonce: SREP.ROOT is the root of a Merkle tree whose leaf at INDX is HASH(0x00 || nonce), proved by the sibling hashes in PATH; without this, any signed reply the server ever sent verifies (security audit 2026-11-01, LIB-01: a recorded reply replayed to the client's port passed as fresh time).
    //   5. The delegation's window holds the timestamp: DELE.MINT <= MIDP <= DELE.MAXT, so an expired delegation key cannot vouch.
    // HASH is SHA-512 truncated to the root's length (32 bytes in the IETF version; 64 in the pre-IETF one), leaf prefix 0x00, node prefix 0x01, bit i of INDX saying which side the leaf's branch sits at level i.
    // -----------------------------------------------------------------------

    /// SHA-512 over `parts`, truncated to `len` bytes.
    fn hash_to(len: usize, parts: &[&[u8]]) -> Vec<u8> {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA512);
        for p in parts {
            ctx.update(p);
        }
        ctx.finish().as_ref()[..len].to_vec()
    }

    /// Walk the Merkle proof for `nonce` up to the root: true when `root` is what the proof reaches.
    /// `path` holds one sibling hash per level, each the root's length; `index` is the leaf's position, read bit by bit from the bottom.
    fn nonce_in_root(nonce: &[u8; 64], root: &[u8], path: &[u8], index: u32) -> bool {
        let len = root.len();
        // WHY: the root's length is peer-supplied; SHA-512 yields 64 bytes, so anything else cannot be a truncation of it, and a path not made of whole hashes is malformed.
        if !(len == 32 || len == 64) || path.len() % len != 0 {
            return false;
        }
        let levels = path.len() / len;
        // WHY: an index with bits beyond the path's levels names a leaf the proof cannot reach.
        if levels < 32 && index >> levels != 0 {
            return false;
        }
        let mut node = hash_to(len, &[&[0u8], nonce]);
        for (i, sibling) in path.chunks(len).enumerate() {
            node = if (index >> i) & 1 == 1 {
                hash_to(len, &[&[1u8], sibling, &node])
            } else {
                hash_to(len, &[&[1u8], &node, sibling])
            };
        }
        node == root
    }

    fn u64_at(v: &[u8]) -> Option<u64> {
        v.get(..8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes)
    }

    fn verify_and_extract(
        response: &[u8],
        server_pubkey: &[u8],
        nonce: &[u8; 64],
    ) -> Option<u64> {
        let resp      = parse_message(response)?;
        let sig_bytes = resp.get(&TAG_SIG)?;
        let srep_raw  = resp.get(&TAG_SREP)?;
        let cert_raw  = resp.get(&TAG_CERT)?;
        let path      = resp.get(&TAG_PATH).copied().unwrap_or(&[]);
        let index     = resp.get(&TAG_INDX).and_then(|v| v.get(..4)).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes).unwrap_or(0);

        // Step 1: verify CERT — server long-term key signs delegation.
        let cert      = parse_message(cert_raw)?;
        let cert_sig  = cert.get(&TAG_SIG)?;
        let dele_raw  = cert.get(&TAG_DELE)?;

        // Either delegation context: the IETF one, or the pre-IETF one the server uses to answer a request without a VER tag.
        let signed_under = |ctx: &[u8]| {
            let mut cert_signed = ctx.to_vec();
            cert_signed.extend_from_slice(dele_raw);
            UnparsedPublicKey::new(&signature::ED25519, server_pubkey).verify(&cert_signed, cert_sig).is_ok()
        };
        if !signed_under(CTX_DELE) && !signed_under(CTX_DELE_LEGACY) {
            return None;
        }

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
        let midp = u64_at(srep.get(&TAG_MIDP)?)?;

        // Step 4: the signed root must commit to the nonce this query sent — the reply is an answer to THIS request, not a recording.
        let root = srep.get(&TAG_ROOT)?;
        if !nonce_in_root(nonce, root, path, index) {
            return None;
        }

        // Step 5: the delegation that signed the reply must have been valid at the time it vouches for.
        let mint = u64_at(dele.get(&TAG_MINT)?)?;
        let maxt = u64_at(dele.get(&TAG_MAXT)?)?;
        if midp < mint || midp > maxt {
            return None;
        }
        Some(midp)
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

        // Connected, so only datagrams from the server's address are delivered: a reply from anyone else never reaches the verifier. Bound in the server's address family: a v4 socket cannot send to the v6 address the resolver hands back first for some servers.
        let sock = UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await.ok()?;
        sock.connect(addr).await.ok()?;

        let t0 = Instant::now();
        sock.send(&request).await.ok()?;

        let mut buf = vec![0u8; 4096];
        let len = sock.recv(&mut buf).await.ok()?;
        let rtt_ms = t0.elapsed().as_millis() as u64;
        // The local clock AT RECEIPT — half of the offset this observation contributes (see consensus).
        let local_et = crate::eagle::from_system_time(std::time::SystemTime::now());
        buf.truncate(len);

        let midp_us  = verify_and_extract(&buf, pubkey, &nonce)?;
        let unix_secs  = (midp_us / 1_000_000) as i64;
        let unix_nanos = ((midp_us % 1_000_000) * 1_000) as u32;

        Some(Observation {
            source:       format!("{host}:{port}"),
            protocol:     Protocol::Roughtime,
            timestamp_et: crate::eagle::from_unix(unix_secs, unix_nanos),
            rtt_ms,
            local_et,
            asn:          None,
            country:      None,
            sct_verified: false,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A two-leaf tree: the proof for our nonce reaches the root, a different nonce does not, and neither does a root of a length SHA-512 cannot be truncated to.
        #[test]
        fn nonce_proof_reaches_the_root_only_for_our_nonce() {
            let ours = [7u8; 64];
            let other = [9u8; 64];
            let leaf_ours = hash_to(32, &[&[0u8], &ours]);
            let leaf_other = hash_to(32, &[&[0u8], &other]);
            // Our leaf sits at index 1, so the other leaf is on the left.
            let root = hash_to(32, &[&[1u8], &leaf_other, &leaf_ours]);
            assert!(nonce_in_root(&ours, &root, &leaf_other, 1));
            assert!(!nonce_in_root(&ours, &root, &leaf_other, 0), "the wrong side must not reach the root");
            assert!(!nonce_in_root(&other, &root, &leaf_ours, 1), "another nonce must not reach the root");
            assert!(!nonce_in_root(&ours, &root[..31], &leaf_other, 1), "a 31-byte root is not a hash");
            // A single leaf is its own tree: an empty path, index 0.
            assert!(nonce_in_root(&ours, &leaf_ours, &[], 0));
            assert!(!nonce_in_root(&ours, &leaf_ours, &[], 1), "an index past the path's levels names no leaf");
        }

        /// Against the real server (network; `cargo test --all-features -- --ignored`): the reply verifies under the nonce that asked for it and under no other, which is the replay the audit found.
        #[tokio::test]
        #[ignore]
        async fn live_reply_is_bound_to_its_nonce() {
            use rand::RngCore;
            let host = "roughtime.cloudflare.com";
            let pubkey = pinned_key(host).expect("pinned");
            let mut ours = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut ours);
            let addr = tokio::net::lookup_host(format!("{host}:{}", server_port(host))).await.expect("resolve").next().expect("an address");
            let sock = UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await.expect("bind");
            sock.connect(addr).await.expect("connect");
            sock.send(&build_request(&ours)).await.expect("send");
            let mut buf = vec![0u8; 4096];
            let len = tokio::time::timeout(TIMEOUT, sock.recv(&mut buf)).await.expect("in time").expect("recv");
            buf.truncate(len);
            // What the reply holds, so a failing step names itself.
            let resp = parse_message(&buf).expect("a tagged message");
            let mut tags: Vec<String> = resp.keys().map(|t| String::from_utf8_lossy(&t.to_le_bytes()).into_owned()).collect();
            tags.sort();
            eprintln!("reply tags: {tags:?}");
            let srep = parse_message(resp.get(&TAG_SREP).expect("SREP")).expect("SREP parses");
            let root = srep.get(&TAG_ROOT).expect("ROOT");
            let path = resp.get(&TAG_PATH).copied().unwrap_or(&[]);
            let index = resp.get(&TAG_INDX).and_then(|v| v.get(..4)).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes).unwrap_or(0);
            eprintln!("root {} bytes, path {} bytes, index {index}, midp {:?}", root.len(), path.len(), srep.get(&TAG_MIDP).and_then(|m| u64_at(m)));
            eprintln!("nonce in root: {}", nonce_in_root(&ours, root, path, index));
            let cert = parse_message(resp.get(&TAG_CERT).expect("CERT")).expect("CERT parses");
            let dele = parse_message(cert.get(&TAG_DELE).expect("DELE")).expect("DELE parses");
            eprintln!("mint {:?} maxt {:?}", dele.get(&TAG_MINT).and_then(|m| u64_at(m)), dele.get(&TAG_MAXT).and_then(|m| u64_at(m)));
            let midp = verify_and_extract(&buf, pubkey, &ours).expect("the reply to our own nonce verifies");
            assert!(midp > 0);
            let other = [0x55u8; 64];
            assert!(verify_and_extract(&buf, pubkey, &other).is_none(), "the same reply must not pass under another nonce");
        }
    }
}
