/// Eagle Time conversion utilities for use within nunc.
///
/// Eagle Time is defined as oscillation counts of the 21 cm hydrogen-1
/// hyperfine transition (1,420,407,826 Hz), referenced to the Apollo 11
/// lunar landing moment (1969-07-20 20:17:40 UTC).
///
/// i64 oscillation counts cover ±206 years at 704 ps resolution —
/// sufficient for all internet timestamp sources and free of the precision
/// loss that f64 unix-second arithmetic introduces at current epoch values.

/// Oscillations per second (21 cm hydrogen-1 hyperfine transition frequency).
pub const OPS: i64 = 1_420_407_826;

/// Eagle epoch expressed as a Unix timestamp (signed seconds since 1970-01-01).
/// = 1969-07-20 20:17:40 UTC
/// Derivation: 165 days before 1970-01-01 00:00:00, plus 20h 17m 40s.
///   165 * 86400 - (20*3600 + 17*60 + 40) = 14_256_000 - 73_060 = 14_182_940
pub const EAGLE_EPOCH_UNIX_SECS: i64 = -14_182_940;

/// Convert (unix_secs, subsec_nanos) to Eagle Time oscillation count.
///
/// `unix_secs` may be negative (pre-1970 dates).
/// `subsec_nanos` must be in [0, 999_999_999].
pub fn from_unix(unix_secs: i64, subsec_nanos: u32) -> i64 {
    let secs_since_eagle = unix_secs - EAGLE_EPOCH_UNIX_SECS;
    secs_since_eagle * OPS + subsec_nanos as i64 * OPS / 1_000_000_000
}

/// Convert a `std::time::SystemTime` to Eagle Time oscillation count.
pub fn from_system_time(t: std::time::SystemTime) -> i64 {
    use std::time::UNIX_EPOCH;
    match t.duration_since(UNIX_EPOCH) {
        Ok(d)  => from_unix(d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            // t is before Unix epoch — negate and subtract subsecond contribution
            let d = e.duration();
            from_unix(-(d.as_secs() as i64), 0)
                .saturating_sub(d.subsec_nanos() as i64 * OPS / 1_000_000_000)
        }
    }
}

/// Convert an Eagle Time oscillation count back to `std::time::SystemTime`.
pub fn to_system_time(et: i64) -> std::time::SystemTime {
    use std::time::{Duration, UNIX_EPOCH};
    let secs_since_eagle = et / OPS;
    let leftover_osc     = et % OPS;
    let unix_secs        = secs_since_eagle + EAGLE_EPOCH_UNIX_SECS;
    let nanos            = (leftover_osc.abs() * 1_000_000_000 / OPS) as u32;

    if unix_secs >= 0 {
        UNIX_EPOCH + Duration::new(unix_secs as u64, nanos)
    } else {
        // Rare for internet sources but handle cleanly
        UNIX_EPOCH - Duration::new((-unix_secs) as u64, 0)
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
        // Allow 1ms rounding error from integer arithmetic
        assert!((nanos as i64 - 500_000_000).abs() < 1_000_000, "nanos={nanos}");
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
