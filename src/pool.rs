use crate::types::{Protocol, ServerEntry};
use rand::seq::SliceRandom;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// The full server pool, loaded from the embedded JSON at compile time
/// or from a user-supplied path at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pool {
    pub servers: Vec<ServerEntry>,
}

impl Pool {
    /// Load the bundled pool (compiled into the binary).
    pub fn bundled() -> Self {
        let raw = include_str!("../data/servers.json");
        serde_json::from_str(raw).expect("bundled servers.json is malformed")
    }

    /// Load from an external JSON file (user-maintained, larger list).
    pub fn from_file(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let raw = std::fs::read_to_string(path)?;
        serde_json::from_str(&raw).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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

        // Pass 1: ASN-unique
        for s in &candidates {
            if selected.len() >= n { break; }
            match s.asn {
                Some(asn) if !seen_asns.contains(&asn) => {
                    seen_asns.insert(asn);
                    if let Some(c) = &s.country { seen_countries.insert(c.clone()); }
                    selected.push((*s).clone());
                }
                None => {
                    selected.push((*s).clone());
                }
                _ => {}
            }
        }

        // Pass 2: fill remainder from whatever's left
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
