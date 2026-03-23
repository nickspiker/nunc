/// Extract the raw SCT bytes from a certificate's SCT list extension
/// (OID 1.3.6.1.4.1.11129.2.4.2, RFC 6962 §3.3).
///
/// The extension value is a DER OCTET STRING whose content is the SCT list:
///   uint16  total_length
///   [uint16 sct_length, bytes sct_data] ...
use x509_parser::prelude::*;

// OID 1.3.6.1.4.1.11129.2.4.2 — RFC 6962 SCT list certificate extension
const SCT_OID_COMPONENTS: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2];

/// Returns the individual serialized SCT blobs from the cert, or empty vec
/// if the extension is absent or unparseable.
pub fn extract_scts(cert_der: &[u8]) -> Vec<Vec<u8>> {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return vec![];
    };

    let Ok(oid) = oid_registry::Oid::from(SCT_OID_COMPONENTS) else {
        return vec![];
    };

    let ext = match cert.get_extension_unique(&oid) {
        Ok(Some(e)) => e,
        _           => return vec![],
    };

    // ext.value is the raw DER of the extension value field.
    // For this extension it is an OCTET STRING wrapping the SCT list bytes.
    parse_sct_list(strip_der_octet_string(ext.value).unwrap_or(ext.value))
}

/// Strip one layer of DER OCTET STRING (tag 0x04) encoding.
fn strip_der_octet_string(data: &[u8]) -> Option<&[u8]> {
    if data.first() != Some(&0x04) { return None; }
    let (len, hdr) = decode_der_length(&data[1..])?;
    let payload = data.get(1 + hdr..1 + hdr + len)?;
    Some(payload)
}

/// Decode DER length field.  Returns (length, bytes_consumed).
fn decode_der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else {
        let n_bytes = (first & 0x7f) as usize;
        if n_bytes == 0 || n_bytes > 4 || data.len() < 1 + n_bytes {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[1..=n_bytes] {
            len = (len << 8) | b as usize;
        }
        Some((len, 1 + n_bytes))
    }
}

/// Parse the TLS SCT list wire format into individual SCT blobs.
fn parse_sct_list(data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() < 2 { return vec![]; }
    let total = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut result = Vec::new();
    let mut pos = 2usize;
    let end = (pos + total).min(data.len());
    while pos + 2 <= end {
        let sct_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + sct_len > end { break; }
        result.push(data[pos..pos + sct_len].to_vec());
        pos += sct_len;
    }
    result
}
