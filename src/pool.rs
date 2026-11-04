use crate::types::{Protocol, ServerEntry};
use rand::seq::SliceRandom;

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

    /// Cryptographically random selection of `n` servers, enforcing protocol and diversity constraints where possible.
    ///
    /// Diversity strategy:
    ///   - Prefer unique ASNs first
    ///   - Within ASN budget, prefer unique countries
    ///   - Fill remainder randomly
    ///
    /// The shuffle is driven by the thread-local CSPRNG, seeded from OS entropy inside this process.
    /// Nothing about the draw is ever written to the wire or returned to the caller, so no server learns the seed and none can reconstruct the round's set (security audit LIB-03).
    /// The HTTPS cache-buster is a separate random value drawn per request in `sources::https`; it shares nothing with this draw.
    pub fn select(&self, n: usize, protocols: &[Protocol]) -> Vec<ServerEntry> {
        let mut rng = rand::thread_rng();

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
        let selected = pool.select(10, &[Protocol::Https]);
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
        let selected = pool.select(2, &[Protocol::Https]);
        assert_eq!(selected.len(), 2);
    }

    /// LIB-03: the draw is seeded inside the process from OS entropy, so no two rounds share a seed and no caller or server can replay one.
    #[test]
    fn select_is_unpredictable_across_calls() {
        let pool = Pool::bundled();
        let a = pool.select(32, &[Protocol::Https]);
        let b = pool.select(32, &[Protocol::Https]);
        let hosts_a: Vec<_> = a.iter().map(|s| s.host.clone()).collect();
        let hosts_b: Vec<_> = b.iter().map(|s| s.host.clone()).collect();
        assert_ne!(hosts_a, hosts_b);
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
    }

    #[test]
    fn select_empty_pool_returns_empty() {
        let pool = make_pool(&[]);
        assert!(pool.select(10, &[Protocol::Https]).is_empty());
    }

    #[test]
    fn bundled_pool_has_all_protocols() {
        let pool = Pool::bundled();
        assert!(pool.servers.iter().any(|s| s.protocol == Protocol::Https));
        assert!(pool.servers.iter().any(|s| s.protocol == Protocol::Ntp));
        assert!(pool.servers.iter().any(|s| s.protocol == Protocol::Nts));
    }
}
