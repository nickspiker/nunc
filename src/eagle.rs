/// Eagle Time conversion utilities for use within nunc.
///
/// Eagle Time is defined as oscillation counts of the 21 cm hydrogen-1
/// hyperfine transition (1,420,407,826 Hz), referenced to the Apollo 11
/// lunar landing moment (1969-07-20 20:17:40 UTC).
///
/// i64 oscillation counts cover ±206 years at 704 ps resolution —
/// sufficient for all internet timestamp sources and free of the precision loss that f64 unix-second arithmetic introduces at current epoch values.

/// Oscillations per second (21 cm hydrogen-1 hyperfine transition frequency).
pub const OPS: i64 = 1_420_407_826;

/// Eagle epoch expressed as a Unix timestamp (signed seconds since 1970-01-01).
/// = 1969-07-20 20:17:40 UTC
/// Derivation: 165 days before 1970-01-01 00:00:00, plus 20h 17m 40s.
///   165 * 86400 - (20*3600 + 17*60 + 40) = 14_256_000 - 73_060 = 14_182_940
pub const EAGLE_EPOCH_UNIX_SECS: i64 = -14_182_940;

fn div_round_half_up(n: i128, d: i128) -> i128 {
    n.div_euclid(d) + ((n.rem_euclid(d) * 2 >= d) as i128)
}

/// Convert (unix_secs, subsec_nanos) to Eagle Time oscillation count — i128, round half up, the SAME arithmetic as `vsf::from_unix_ns` so the two crates agree to the oscillation (photon pins it with a cross-crate test).
///
/// `unix_secs` may be negative (pre-1970 dates).
/// `subsec_nanos` must be in [0, 999_999_999].
pub fn from_unix(unix_secs: i64, subsec_nanos: u32) -> i64 {
    let ns = (unix_secs as i128 - EAGLE_EPOCH_UNIX_SECS as i128) * 1_000_000_000 + subsec_nanos as i128;
    div_round_half_up(ns * OPS as i128, 1_000_000_000) as i64
}

/// Convert a `std::time::SystemTime` to Eagle Time oscillation count.
pub fn from_system_time(t: std::time::SystemTime) -> i64 {
    use std::time::UNIX_EPOCH;
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => from_unix(d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            // Before 1970: `e.duration()` is how far BEFORE, so the instant is −secs − nanos — borrow one second to keep nanos in [0, 1e9).
            let d = e.duration();
            let (secs, nanos) = if d.subsec_nanos() == 0 { (-(d.as_secs() as i64), 0) } else { (-(d.as_secs() as i64) - 1, 1_000_000_000 - d.subsec_nanos()) };
            from_unix(secs, nanos)
        }
    }
}

/// Convert an Eagle Time oscillation count back to `std::time::SystemTime` (round half up to the nanosecond, sub-seconds kept on both sides of 1970).
pub fn to_system_time(et: i64) -> std::time::SystemTime {
    use std::time::{Duration, UNIX_EPOCH};
    let ns = div_round_half_up(et as i128 * 1_000_000_000, OPS as i128) + EAGLE_EPOCH_UNIX_SECS as i128 * 1_000_000_000;
    if ns >= 0 {
        UNIX_EPOCH + Duration::new((ns / 1_000_000_000) as u64, (ns % 1_000_000_000) as u32)
    } else {
        let back = -ns;
        UNIX_EPOCH - Duration::new((back / 1_000_000_000) as u64, (back % 1_000_000_000) as u32)
    }
}

/// Convert Eagle Time oscillation count to `std::time::Duration` (positive only).
/// Used for confidence half-widths.
pub fn to_duration(et_delta: i64) -> std::time::Duration {
    use std::time::Duration;
    let secs  = (et_delta / OPS) as u64;
    let nanos = (et_delta % OPS * 1_000_000_000 / OPS) as u32;
    Duration::new(secs, nanos)
}

/// Convert milliseconds to Eagle Time oscillation count.
pub fn from_millis(ms: i64) -> i64 {
    ms * OPS / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn unix_epoch_roundtrip() {
        // Unix epoch (1970-01-01) is after Eagle epoch (1969-07-20) → ET is positive.
        let et = from_unix(0, 0);
        assert!(et > 0, "Unix epoch is after Eagle epoch so ET should be positive");
        let back = to_system_time(et);
        assert_eq!(back, UNIX_EPOCH);
    }

    #[test]
    fn current_epoch_roundtrip() {
        // A known recent timestamp: 2026-03-22 00:00:00 UTC = unix 1742601600
        let unix = 1_742_601_600i64;
        let et = from_unix(unix, 0);
        let back = to_system_time(et);
        let back_unix = back.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        assert_eq!(back_unix, unix);
    }

    #[test]
    fn subsecond_preserved() {
        let et = from_unix(1_000_000_000, 500_000_000); // +0.5s
        let back = to_system_time(et);
        let nanos = back.duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
        assert_eq!(nanos, 500_000_000, "the integer path is exact to the nanosecond");
    }

    /// Pre-1970 instants keep their sub-second on the way in and out (the old path dropped it one way and added it the other).
    #[test]
    fn pre_1970_subsecond_round_trips() {
        let t = UNIX_EPOCH - Duration::new(3, 250_000_000);
        assert_eq!(to_system_time(from_system_time(t)), t);
        assert_eq!(from_system_time(t), from_unix(-4, 750_000_000));
    }

    #[test]
    fn from_millis_consistent() {
        assert_eq!(from_millis(1000), OPS);
        assert_eq!(from_millis(0), 0);
        assert_eq!(from_millis(500), OPS / 2);
    }

    #[test]
    fn to_duration_consistent() {
        assert_eq!(to_duration(OPS), Duration::from_secs(1));
        assert_eq!(to_duration(0), Duration::ZERO);
    }
}
