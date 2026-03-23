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

        // Export C2S and S2C keys immediately after handshake, before the server
        // closes the connection (avoids any potential post-shutdown key export issues).
        let mut c2s = [0u8; 32];
        let mut s2c = [0u8; 32];
        {
            let inner = tls.get_ref().1;
            inner.export_keying_material(&mut c2s, EXPORTER_LABEL, Some(CTX_C2S)).ok()?;
            inner.export_keying_material(&mut s2c, EXPORTER_LABEL, Some(CTX_S2C)).ok()?;
        }

        // Read response (server closes after sending).
        // Some servers RST instead of FIN after sending — ignore the error
        // as long as we got some bytes.
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
    fn build_ntp_request(cookie: &[u8], c2s_key: &[u8; 32]) -> Option<Vec<u8>> {
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

        Some(pkt)
    }

    /// Parse NTP response: verify NTS Auth EF with S2C key, return transmit timestamp
    /// as Unix seconds (i64).
    fn parse_and_verify(response: &[u8], s2c_key: &[u8; 32]) -> Option<i64> {
        if response.len() < 48 { return None; }

        // Transmit timestamp from server is at bytes 40–47 (NTP epoch, u32 seconds)
        let ntp_secs = u32::from_be_bytes(response[40..44].try_into().ok()?) as u64;
        if ntp_secs < NTP_EPOCH_OFFSET { return None; }
        let unix_secs = (ntp_secs - NTP_EPOCH_OFFSET) as i64;

        // Find the NTS Auth EF (0x0404) and verify it.
        // AD = everything before the Auth EF, plaintext = empty.
        let mut pos = 48usize;
        while pos + 4 <= response.len() {
            let ef_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
            let ef_len  = u16::from_be_bytes([response[pos + 2], response[pos + 3]]) as usize;
            if ef_type == EF_NTS_AUTH {
                let body = response.get(pos + 4..pos + ef_len)?;
                if body.len() < 4 { return None; }
                let nonce_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                let ct_len    = u16::from_be_bytes([body[2], body[3]]) as usize;
                let body_rest = body.get(4..)?;
                if body_rest.len() < nonce_len + ct_len { return None; }
                let nonce      = &body_rest[..nonce_len];
                let ciphertext = &body_rest[nonce_len..nonce_len + ct_len];

                // AAD = everything before the Auth EF (not including its header).
                let aad = &response[..pos];
                let cipher = Aes128SivAead::new(s2c_key.into());
                cipher.decrypt(
                    Nonce::from_slice(nonce.try_into().ok()?),
                    Payload { msg: ciphertext, aad },
                ).ok()?; // verification failure → None

                return Some(unix_secs);
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
        let request = build_ntp_request(&cookie, &c2s)?;

        // Prefer IPv4 for NTP UDP to avoid potential IPv6 routing issues.
        // Fall back to any address if no IPv4 found.
        let addrs: Vec<_> = tokio::net::lookup_host(format!("{host}:{NTP_PORT}"))
            .await.ok()?.collect();
        let addr = addrs.iter().find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .copied()?;
        let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = UdpSocket::bind(bind_addr).await.ok()?;

        let t0 = Instant::now();
        sock.send_to(&request, addr).await.ok()?;

        let mut buf = vec![0u8; 1024];
        let (len, _from) = sock.recv_from(&mut buf).await.ok()?;
        let rtt_ms = t0.elapsed().as_millis() as u64;
        buf.truncate(len);

        let unix_secs = parse_and_verify(&buf, &s2c)?;

        Some(Observation {
            source:       host.to_string(),
            protocol:     Protocol::Nts,
            timestamp_et: crate::eagle::from_unix(unix_secs, 0),
            rtt_ms,
            asn:          None,
            country:      None,
            sct_verified: false, // NTS uses its own authentication chain
        })
    }
}
