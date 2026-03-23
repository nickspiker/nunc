use crate::types::{Protocol, ServerEntry};
use rand::seq::SliceRandom;
use rand::RngCore;

/// The full server pool, built from the compile-time pool_data table.
#[derive(Debug, Clone)]
pub struct Pool {
    pub servers: Vec<ServerEntry>,
}

impl Pool {
    /// Load the bundled pool (compiled into the binary via pool_data.rs).
    pub fn bundled() -> Self {
        Self {
            servers: crate::pool_data::SERVERS.iter().map(|&(host, protocol, asn, country, category)| {
                ServerEntry {
                    host:     host.to_string(),
                    protocol,
                    asn,
                    country:  country.map(str::to_string),
                    category: category.map(str::to_string),
                }
            }).collect()
        }
    }

    /// TRNG-seeded selection of `n` servers, enforcing protocol and diversity
    /// constraints where possible.
    ///
    /// Diversity strategy:
    ///   - Prefer unique ASNs first
    ///   - Within ASN budget, prefer unique countries
    ///   - Fill remainder randomly
    ///
    /// The nonce seeds the RNG so the caller controls which servers are picked —
    /// an adversary cannot predict the selection without knowing the nonce.
    pub fn select(&self, n: usize, protocols: &[Protocol], nonce: u64) -> Vec<ServerEntry> {
        use rand::SeedableRng;
        let mut rng = rand::rngs::SmallRng::seed_from_u64(nonce);

        let mut candidates: Vec<&ServerEntry> = self
            .servers
            .iter()
            .filter(|s| protocols.contains(&s.protocol))
            .collect();

        candidates.shuffle(&mut rng);

        // Greedy diversity pass: pick ASN-unique first
        let mut selected: Vec<ServerEntry> = Vec::with_capacity(n);
        let mut seen_asns: std::collections::HashSet<u32> = Default::default();
        let mut seen_countries: std::collections::HashSet<String> = Default::default();

        // Pass 1: country-unique, then ASN-unique within country budget
        for s in &candidates {
            if selected.len() >= n { break; }
            let country_ok = s.country.as_ref()
                .map(|c| !seen_countries.contains(c))
                .unwrap_or(false); // unknown country → pass 2
            let asn_ok = s.asn.as_ref()
                .map(|a| !seen_asns.contains(a))
                .unwrap_or(false); // unknown ASN → pass 2
            if country_ok || asn_ok {
                if let Some(a) = s.asn   { seen_asns.insert(a); }
                if let Some(c) = &s.country { seen_countries.insert(c.clone()); }
                selected.push((*s).clone());
            }
        }

        // Pass 2: fill remainder — any unselected candidate, ASN-unique preferred
        for s in &candidates {
            if selected.len() >= n { break; }
            if selected.iter().any(|x| x.host == s.host) { continue; }
            let asn_ok = s.asn.as_ref()
                .map(|a| !seen_asns.contains(a))
                .unwrap_or(true); // unknown ASN: include freely in fill pass
            if asn_ok {
                if let Some(a) = s.asn { seen_asns.insert(a); }
                selected.push((*s).clone());
            }
        }

        // Pass 3: fill any remaining slots without ASN constraint
        for s in &candidates {
            if selected.len() >= n { break; }
            if !selected.iter().any(|x| x.host == s.host) {
                selected.push((*s).clone());
            }
        }

        selected
    }
}

/// Generate a random nonce from the system TRNG.
/// This seeds server selection — unpredictable to an adversary.
pub fn trng_nonce() -> u64 {
    let mut rng = rand::thread_rng();
    rng.next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Protocol;

    fn make_pool(entries: &[(&'static str, Protocol, Option<u32>, Option<&'static str>)]) -> Pool {
        Pool {
            servers: entries.iter().map(|&(host, protocol, asn, country)| ServerEntry {
                host:     host.into(),
                protocol,
                asn,
                country:  country.map(str::to_string),
                category: None,
            }).collect(),
        }
    }

    #[test]
    fn select_respects_protocol_filter() {
        let pool = make_pool(&[
            ("a.example.com", Protocol::Https,    Some(1), Some("US")),
            ("b.example.com", Protocol::Ntp,      Some(2), Some("DE")),
            ("c.example.com", Protocol::Https,    Some(3), Some("GB")),
        ]);
        let selected = pool.select(10, &[Protocol::Https], 42);
        assert!(selected.iter().all(|s| s.protocol == Protocol::Https));
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_returns_at_most_n() {
        let pool = make_pool(&[
            ("a.example.com", Protocol::Https, Some(1), Some("US")),
            ("b.example.com", Protocol::Https, Some(2), Some("DE")),
            ("c.example.com", Protocol::Https, Some(3), Some("GB")),
            ("d.example.com", Protocol::Https, Some(4), Some("FR")),
        ]);
        let selected = pool.select(2, &[Protocol::Https], 42);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_is_deterministic_for_same_nonce() {
        let pool = Pool::bundled();
        let a = pool.select(32, &[Protocol::Https], 0xdeadbeef);
        let b = pool.select(32, &[Protocol::Https], 0xdeadbeef);
        let hosts_a: Vec<_> = a.iter().map(|s| &s.host).collect();
        let hosts_b: Vec<_> = b.iter().map(|s| &s.host).collect();
        assert_eq!(hosts_a, hosts_b);
    }

    #[test]
    fn select_varies_by_nonce() {
        let pool = Pool::bundled();
        let a = pool.select(32, &[Protocol::Https], 1);
        let b = pool.select(32, &[Protocol::Https], 2);
        let hosts_a: Vec<_> = a.iter().map(|s| s.host.clone()).collect();
        let hosts_b: Vec<_> = b.iter().map(|s| s.host.clone()).collect();
        assert_ne!(hosts_a, hosts_b);
    }

    #[test]
    fn select_empty_pool_returns_empty() {
        let pool = make_pool(&[]);
        assert!(pool.select(10, &[Protocol::Https], 0).is_empty());
    }

    #[test]
    fn bundled_pool_has_all_protocols() {
        let pool = Pool::bundled();
        assert!(pool.servers.iter().any(|s| s.protocol == Protocol::Https));
        assert!(pool.servers.iter().any(|s| s.protocol == Protocol::Ntp));
        assert!(pool.servers.iter().any(|s| s.protocol == Protocol::Nts));
    }
}
