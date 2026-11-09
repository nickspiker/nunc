/// NTS (Network Time Security) client — RFC 8915.
///
/// Two-phase protocol:
///   1. NTS-KE: TLS 1.3 TCP on port 4460.  Exchange binary records.
///      Server returns opaque cookies and we export C2S/S2C keys from the TLS session.
///   2. Authenticated NTP: standard 48-byte NTPv4 UDP packet on port 123,
///      with two extension fields — NTS Cookie (0x0104) and NTS Authenticator (0x0404).
///      Response is verified with AEAD_AES_SIV_CMAC_256 using the S2C key.
///
/// Key derivation (RFC 8915 §5.1):
///   label = "EXPORTER-network-time-security"
///   C2S   = TLS-Exporter(label, ctx=`[0x00,0x0F,0x00]`, 32 bytes)
///   S2C   = TLS-Exporter(label, ctx=`[0x00,0x0F,0x01]`, 32 bytes)
#[cfg(feature = "nts")]
pub mod nts {
    use aes_siv::{Aes128SivAead, Nonce, aead::{Aead, KeyInit, Payload}};
    use crate::types::{Observation, Protocol};
    use rustls::pki_types::ServerName;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpStream, UdpSocket};
    use tokio_rustls::TlsConnector;
    use webpki_roots::TLS_SERVER_ROOTS;

    const TIMEOUT:    std::time::Duration = std::time::Duration::from_secs(8);
    const KE_PORT:    u16 = 4460;
    const NTP_PORT:   u16 = 123;

    // NTS-KE record types (RFC 8915 §4)
    const REC_END:          u16 = 0x8000; // Critical | End of Message
    const REC_NEXT_PROTO:   u16 = 0x8001; // Critical | Next Protocol Negotiation
    const REC_AEAD_ALGO:    u16 = 0x8004; // Critical | AEAD Algorithm Negotiation
    const REC_NEW_COOKIE:   u16 = 0x0005; // New Cookie (not critical)

    const PROTO_NTPV4:      u16 = 0x0000;
    const AEAD_AES_SIV_256: u16 = 0x000F; // id=15, AEAD_AES_SIV_CMAC_256

    // NTS key exporter contexts (RFC 8915 §5.1)
    // context = [proto_id: u16 BE] || [AEAD_id: u16 BE] || [direction: u8]
    // proto_id = 0x0000 (NTPv4), AEAD_id = 0x000F (AEAD_AES_SIV_CMAC_256)
    const CTX_C2S: &[u8] = &[0x00, 0x00, 0x00, 0x0F, 0x00];
    const CTX_S2C: &[u8] = &[0x00, 0x00, 0x00, 0x0F, 0x01];
    const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";

    // NTS extension field types (IANA NTP Extension Field Types registry, RFC 8915)
    const EF_UNIQUE_ID:  u16 = 0x0104; // Unique Identifier (MUST per RFC 8915 §5.7)
    const EF_NTS_COOKIE: u16 = 0x0204; // NTS Cookie
    const EF_NTS_AUTH:   u16 = 0x0404; // NTS Authenticator and Encrypted Extensions

    // NTP epoch offset: seconds between 1900-01-01 and 1970-01-01
    const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

    // -----------------------------------------------------------------------
    // NTS-KE record codec
    // -----------------------------------------------------------------------

    fn write_record(buf: &mut Vec<u8>, rec_type: u16, body: &[u8]) {
        buf.extend_from_slice(&rec_type.to_be_bytes());
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(body);
    }

    /// Parse all NTS-KE records from `data`, return list of (type, body) pairs.
    fn parse_records(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut records = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let rec_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let length   = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if pos + length > data.len() { break; }
            records.push((rec_type, data[pos..pos + length].to_vec()));
            pos += length;
            if rec_type & 0x7FFF == 0x0000 { break; } // End of Message
        }
        records
    }

    // -----------------------------------------------------------------------
    // Phase 1: NTS-KE
    // Returns (cookies, c2s_key, s2c_key) or None on failure.
    // -----------------------------------------------------------------------

    async fn ke(host: &str) -> Option<(Vec<Vec<u8>>, [u8; 32], [u8; 32])> {
        // Build TLS config using webpki roots (same trust store as HTTPS).
        // NTS-KE does not need certificate capture, so we use a plain config.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        // RFC 8915 §4: TLS ClientHello MUST include ALPN "ntske/1"
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"ntske/1".to_vec()];
        let connector = TlsConnector::from(std::sync::Arc::new(config));

        let tcp = TcpStream::connect(format!("{host}:{KE_PORT}")).await.ok()?;
        let server_name = ServerName::try_from(host.to_string()).ok()?;
        let mut tls = connector.connect(server_name, tcp).await.ok()?;

        // Send NTS-KE request
        let mut req = Vec::new();
        write_record(&mut req, REC_NEXT_PROTO, &PROTO_NTPV4.to_be_bytes());
        write_record(&mut req, REC_AEAD_ALGO,  &AEAD_AES_SIV_256.to_be_bytes());
        write_record(&mut req, REC_END,         &[]);
        tls.write_all(&req).await.ok()?;
        tls.flush().await.ok()?;

        // Export C2S and S2C keys immediately after handshake, before the server closes the connection (avoids any potential post-shutdown key export issues).
        let mut c2s = [0u8; 32];
        let mut s2c = [0u8; 32];
        {
            let inner = tls.get_ref().1;
            inner.export_keying_material(&mut c2s, EXPORTER_LABEL, Some(CTX_C2S)).ok()?;
            inner.export_keying_material(&mut s2c, EXPORTER_LABEL, Some(CTX_S2C)).ok()?;
        }

        // Read response (server closes after sending).
        // Some servers RST instead of FIN after sending — ignore the error as long as we got some bytes.
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf).await;
        if buf.is_empty() { return None; }

        // Collect cookies from response records
        let records = parse_records(&buf);
        let cookies: Vec<Vec<u8>> = records.into_iter()
            .filter(|(t, _)| *t == REC_NEW_COOKIE)
            .map(|(_, body)| body)
            .collect();

        if cookies.is_empty() { return None; }

        Some((cookies, c2s, s2c))
    }

    // -----------------------------------------------------------------------
    // Phase 2: authenticated NTP request/response
    // -----------------------------------------------------------------------

    /// Build a 48-byte NTPv4 client packet with NTS Cookie + NTS Auth extension fields.
    /// Returns the packet and the Unique Identifier it carries, which the reply must echo (security audit LIB-02).
    fn build_ntp_request(cookie: &[u8], c2s_key: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
        // Standard 48-byte NTPv4 header: LI=0, VN=4, mode=3 (client)
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0b00_100_011; // LI=0, VN=4, mode=3

        // Transmit timestamp (bytes 40–47): current system time in NTP epoch
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        let ntp_secs = (now.as_secs() + NTP_EPOCH_OFFSET) as u32;
        pkt[40..44].copy_from_slice(&ntp_secs.to_be_bytes());

        // Extension field: Unique Identifier (0x0104) — MUST per RFC 8915 §5.7
        // 32 random bytes; server echoes this back so we can match response to request.
        let mut uid = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut uid);
        pkt.extend_from_slice(&EF_UNIQUE_ID.to_be_bytes());
        pkt.extend_from_slice(&(36u16).to_be_bytes()); // 4 header + 32 body
        pkt.extend_from_slice(&uid);

        // Extension field: NTS Cookie (0x0204)
        // Length field = 4 (header) + cookie_len, rounded up to 4-byte boundary
        let cookie_padded_len = (cookie.len() + 3) & !3;
        let ef_cookie_total = 4 + cookie_padded_len;
        pkt.extend_from_slice(&EF_NTS_COOKIE.to_be_bytes());
        pkt.extend_from_slice(&(ef_cookie_total as u16).to_be_bytes());
        pkt.extend_from_slice(cookie);
        pkt.resize(pkt.len() + (cookie_padded_len - cookie.len()), 0); // zero-pad

        // AAD = NTP header + all preceding EFs (does NOT include the Auth EF header).
        // This matches the ntpd-rs / Cloudflare convention (and practical RFC 8915 interpretation).
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Aes128SivAead = AEAD_AES_SIV_CMAC_256 (32-byte key = 2×128-bit AES keys)
        // AES-SIV on empty plaintext → 16-byte SIV tag.
        let cipher = Aes128SivAead::new(c2s_key.into());
        let ciphertext = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: &[], aad: &pkt },
        ).ok()?;

        // Extension field: NTS Authenticator (0x0404)
        // Total: 4 (type+len) + 2 (nonce_len) + 2 (ct_len) + 16 (nonce) + 16 (ct) = 40.
        let ef_auth_total: u16 = 4 + 2 + 2 + nonce.len() as u16 + ciphertext.len() as u16;
        pkt.extend_from_slice(&EF_NTS_AUTH.to_be_bytes());
        pkt.extend_from_slice(&ef_auth_total.to_be_bytes());
        pkt.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&nonce);
        pkt.extend_from_slice(&ciphertext);

        Some((pkt, uid))
    }

    /// One 64-bit NTP timestamp (u32 seconds since 1900 ‖ u32 binary fraction) as Eagle Time, exactly: the fraction converts in integers with round-half-up, so the sub-second part NTS exists to deliver is kept (it used to be dropped — an authenticated sub-millisecond source reported whole seconds).
    fn ntp_ts_to_et(b: &[u8]) -> Option<i64> {
        let secs = u32::from_be_bytes(b.get(0..4)?.try_into().ok()?) as u64;
        let frac = u32::from_be_bytes(b.get(4..8)?.try_into().ok()?) as i128;
        if secs < NTP_EPOCH_OFFSET { return None; }
        let whole = crate::eagle::from_unix((secs - NTP_EPOCH_OFFSET) as i64, 0);
        let sub = (frac * crate::eagle::OPS as i128 + (1i128 << 31)) >> 32;
        Some(whole + sub as i64)
    }

    /// Parse NTP response: verify NTS Auth EF with S2C key, return the server's time at the MIDDLE of its hold — the midpoint of its receive (bytes 32–39) and transmit (40–47) timestamps — in Eagle Time. Midpoint-of-trip is the meaning every observation's `timestamp_et` carries (see consensus `offset_of`).
    /// The reply is untrusted bytes off the network, so the parse is total: any byte string yields a time or None, never a panic (security audit LIB-02).
    /// It must also answer OUR request: its origin timestamp (bytes 24–31) must be the transmit timestamp we sent (`origin`), and it must echo our Unique Identifier (`uid`) in an EF the Authenticator covers.
    fn parse_and_verify(response: &[u8], uid: &[u8; 32], origin: &[u8], s2c_key: &[u8; 32]) -> Option<i64> {
        if response.len() < 48 { return None; }

        // LIB-02: a reply whose origin timestamp is not our transmit timestamp answers some other request; the header sits inside the AAD, so once the Authenticator verifies this echo is the server's own.
        if response[24..32] != *origin { return None; }

        let t2 = ntp_ts_to_et(&response[32..40])?;
        let t3 = ntp_ts_to_et(&response[40..48])?;
        let server_mid_et = t2 + (t3 - t2) / 2;

        // Walk the EFs up to the NTS Auth EF (0x0404) and verify it.
        // AD = everything before the Auth EF, plaintext = the encrypted extensions (new cookies), unused here.
        let mut uid_echoed = false;
        let mut pos = 48usize;
        while pos + 4 <= response.len() {
            let ef_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
            let ef_len  = u16::from_be_bytes([response[pos + 2], response[pos + 3]]) as usize;
            if ef_type == EF_UNIQUE_ID {
                // LIB-02: the echoed Unique Identifier must be the one we sent; any other value means the reply belongs to another request.
                if response.get(pos + 4..pos + ef_len)? != uid { return None; }
                uid_echoed = true;
            }
            if ef_type == EF_NTS_AUTH {
                let body = response.get(pos + 4..pos + ef_len)?;
                if body.len() < 4 { return None; }
                let nonce_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                let ct_len    = u16::from_be_bytes([body[2], body[3]]) as usize;
                let body_rest = body.get(4..)?;
                if body_rest.len() < nonce_len + ct_len { return None; }
                // WHY/PROOF: nonce_len is read from the unauthenticated Auth EF of an untrusted UDP reply, and AES-SIV here takes exactly a 16-byte nonce.
                // `Nonce::from_slice` panics on any other length, so a spoofed reply crashed the caller's task (security audit LIB-02).
                // The array conversion returns None instead, and the reply is a failed source.
                let nonce: [u8; 16] = body_rest[..nonce_len].try_into().ok()?;
                let ciphertext = &body_rest[nonce_len..nonce_len + ct_len];

                // AAD = everything before the Auth EF (not including its header).
                let aad = &response[..pos];
                let cipher = Aes128SivAead::new(s2c_key.into());
                cipher.decrypt(
                    &Nonce::from(nonce),
                    Payload { msg: ciphertext, aad },
                ).ok()?; // verification failure → None

                // LIB-02: RFC 8915 §5.7 has the server echo the Unique Identifier; a reply without one cannot be matched to our request.
                if !uid_echoed { return None; }
                return Some(server_mid_et);
            }
            if ef_len < 4 { break; } // malformed
            pos += ef_len;
        }

        // No Auth EF found — server didn't authenticate the response
        None
    }

    // -----------------------------------------------------------------------
    // Public entry point
    // -----------------------------------------------------------------------

    pub async fn query(host: &str) -> Option<Observation> {
        tokio::time::timeout(TIMEOUT, query_inner(host))
            .await
            .ok()
            .flatten()
    }

    async fn query_inner(host: &str) -> Option<Observation> {
        // Phase 1: NTS-KE
        let (cookies, c2s, s2c) = ke(host).await?;
        let cookie = cookies.into_iter().next()?;

        // Phase 2: authenticated NTP over UDP
        let (request, uid) = build_ntp_request(&cookie, &c2s)?;

        // Prefer IPv4 for NTP UDP to avoid potential IPv6 routing issues.
        // Fall back to any address if no IPv4 found.
        let addrs: Vec<_> = tokio::net::lookup_host(format!("{host}:{NTP_PORT}"))
            .await.ok()?.collect();
        let addr = addrs.iter().find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .copied()?;
        let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = UdpSocket::bind(bind_addr).await.ok()?;
        // Connected, so only datagrams from the server's address are delivered: an off-path sprayer's reply never reaches the parser (security audit LIB-02).
        sock.connect(addr).await.ok()?;

        let t0 = Instant::now();
        sock.send(&request).await.ok()?;

        let mut buf = vec![0u8; 1024];
        let len = sock.recv(&mut buf).await.ok()?;
        let rtt_ms = t0.elapsed().as_millis() as u64;
        // The local clock AT RECEIPT — half of the offset this observation contributes (see consensus).
        let local_et = crate::eagle::from_system_time(std::time::SystemTime::now());
        buf.truncate(len);

        let server_mid_et = parse_and_verify(&buf, &uid, &request[40..48], &s2c)?;

        Some(Observation {
            source:       host.to_string(),
            protocol:     Protocol::Nts,
            timestamp_et: server_mid_et,
            rtt_ms,
            local_et,
            asn:          None,
            country:      None,
            sct_verified: false, // NTS uses its own authentication chain
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The fraction survives: half a second is exactly half of OPS (round half up), and a zero fraction is the whole second.
        #[test]
        fn ntp_timestamp_keeps_its_fraction() {
            let secs = (NTP_EPOCH_OFFSET + 1_790_000_000) as u32;
            let mut b = [0u8; 8];
            b[0..4].copy_from_slice(&secs.to_be_bytes());
            let whole = ntp_ts_to_et(&b).unwrap();
            assert_eq!(whole, crate::eagle::from_unix(1_790_000_000, 0));
            b[4..8].copy_from_slice(&0x8000_0000u32.to_be_bytes());
            assert_eq!(ntp_ts_to_et(&b).unwrap() - whole, crate::eagle::OPS / 2);
        }

        const S2C: [u8; 32] = [7u8; 32];
        const UID: [u8; 32] = [0xA5u8; 32];
        const ORIGIN: [u8; 8] = [0xE0, 0, 0, 1, 0, 0, 0, 0];

        /// A server reply as the wire carries it: header echoing `origin`, an optional Unique Identifier EF, then an Auth EF whose nonce is `nonce_len` bytes.
        /// A 16-byte nonce is sealed for real under `S2C`; any other length carries a dummy tag, since AES-SIV here cannot seal under it.
        fn reply(uid: Option<&[u8; 32]>, origin: &[u8; 8], nonce_len: usize) -> Vec<u8> {
            let secs = (NTP_EPOCH_OFFSET + 1_790_000_000) as u32;
            let mut pkt = vec![0u8; 48];
            pkt[0] = 0b00_100_100; // LI=0, VN=4, mode=4 (server)
            pkt[24..32].copy_from_slice(origin);
            pkt[32..36].copy_from_slice(&secs.to_be_bytes());
            pkt[40..44].copy_from_slice(&secs.to_be_bytes());
            if let Some(uid) = uid {
                pkt.extend_from_slice(&EF_UNIQUE_ID.to_be_bytes());
                pkt.extend_from_slice(&36u16.to_be_bytes());
                pkt.extend_from_slice(uid);
            }
            let nonce = vec![0x3Cu8; nonce_len];
            let ct = if nonce_len == 16 {
                Aes128SivAead::new((&S2C).into())
                    .encrypt(Nonce::from_slice(&nonce), Payload { msg: &[], aad: &pkt })
                    .unwrap()
            } else {
                vec![0u8; 16]
            };
            pkt.extend_from_slice(&EF_NTS_AUTH.to_be_bytes());
            pkt.extend_from_slice(&((4 + 4 + nonce.len() + ct.len()) as u16).to_be_bytes());
            pkt.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
            pkt.extend_from_slice(&(ct.len() as u16).to_be_bytes());
            pkt.extend_from_slice(&nonce);
            pkt.extend_from_slice(&ct);
            pkt
        }

        /// The control: a sealed reply that echoes our uid and origin gives the server's time.
        #[test]
        fn sealed_reply_answering_our_request_verifies() {
            let r = reply(Some(&UID), &ORIGIN, 16);
            assert_eq!(parse_and_verify(&r, &UID, &ORIGIN, &S2C), Some(crate::eagle::from_unix(1_790_000_000, 0)));
        }

        /// LIB-02: a nonce of any length but 16 is a failed source, never a panic (it used to reach `Nonce::from_slice`, which panics).
        #[test]
        fn nonce_len_not_16_is_rejected_without_panic() {
            for nonce_len in [0usize, 1, 8, 12, 15, 17, 24, 32, 64] {
                let r = reply(Some(&UID), &ORIGIN, nonce_len);
                assert_eq!(parse_and_verify(&r, &UID, &ORIGIN, &S2C), None, "nonce_len {nonce_len}");
            }
        }

        /// LIB-02: every value an attacker can write into the nonce_len field of a real reply yields a result, never a panic, and only the true 16 verifies.
        #[test]
        fn every_nonce_len_field_value_is_total() {
            let good = reply(Some(&UID), &ORIGIN, 16);
            // The Auth EF follows the 48-byte header and the 36-byte uid EF; its nonce_len field sits after its own 4-byte header.
            let at = 48 + 36 + 4;
            for v in 0..=u16::MAX {
                let mut r = good.clone();
                r[at..at + 2].copy_from_slice(&v.to_be_bytes());
                let got = parse_and_verify(&r, &UID, &ORIGIN, &S2C);
                assert_eq!(got.is_some(), v == 16, "nonce_len field {v}");
            }
        }

        /// LIB-02: a reply sealed under the right key but echoing another request's uid is rejected, and so is one echoing none.
        #[test]
        fn foreign_or_missing_unique_identifier_is_rejected() {
            let other = [0x5Au8; 32];
            assert_eq!(parse_and_verify(&reply(Some(&other), &ORIGIN, 16), &UID, &ORIGIN, &S2C), None);
            assert_eq!(parse_and_verify(&reply(None, &ORIGIN, 16), &UID, &ORIGIN, &S2C), None);
        }

        /// LIB-02: a reply whose origin timestamp is not our transmit timestamp answers another request.
        #[test]
        fn foreign_origin_timestamp_is_rejected() {
            let other = [0xE0, 0, 0, 2, 0, 0, 0, 0];
            assert_eq!(parse_and_verify(&reply(Some(&UID), &other, 16), &UID, &ORIGIN, &S2C), None);
        }

        /// LIB-02: every prefix of a reply, and every single-byte corruption of it, parses to a result without a panic.
        #[test]
        fn truncated_or_corrupted_reply_never_panics() {
            let good = reply(Some(&UID), &ORIGIN, 16);
            for len in 0..good.len() {
                assert_eq!(parse_and_verify(&good[..len], &UID, &ORIGIN, &S2C), None, "prefix {len}");
            }
            for i in 0..good.len() {
                for v in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                    let mut r = good.clone();
                    r[i] = v;
                    let _ = parse_and_verify(&r, &UID, &ORIGIN, &S2C);
                }
            }
        }
    }
}
