use crate::types::{NuncTime, Observation, OutlierReport};
use crate::error::NuncError;
use std::time::{Duration, UNIX_EPOCH};

/// Compute consensus from a set of raw observations.
///
/// Algorithm:
///   1. Build an uncertainty interval per observation: [t - rtt/2, t + rtt/2]
///   2. Find the median timestamp
///   3. Reject outliers beyond `rejection_threshold_ms` from median
///   4. Compute the intersection of remaining intervals
///   5. Return midpoint + half-width as confidence
///
/// The distribution is expected to look roughly like a blackbody curve:
/// tight peak from well-behaved sources, long right tail from stale CDN
/// responses and slow links.  Plot `raw` observations to tune the threshold
/// empirically before hardcoding it.
pub fn consensus(
    observations: Vec<Observation>,
    min_sources: usize,
    rejection_threshold_ms: u64,
) -> Result<NuncTime, NuncError> {
    let sources_queried = observations.len();

    if observations.is_empty() {
        return Err(NuncError::EmptyPool);
    }

    // Build (midpoint, half_width) pairs — half_width = rtt_ms / 2
    let intervals: Vec<(u64, u64)> = observations
        .iter()
        .map(|o| {
            let t = o.timestamp * 1000; // work in milliseconds
            let hw = o.rtt_ms / 2;
            (t, hw)
        })
        .collect();

    // Median of midpoints
    let mut mids: Vec<u64> = intervals.iter().map(|(t, _)| *t).collect();
    mids.sort_unstable();
    let median = mids[mids.len() / 2];

    // Reject outliers
    let mut good: Vec<&Observation> = Vec::new();
    let mut outliers: Vec<OutlierReport> = Vec::new();

    for obs in &observations {
        let t_ms = obs.timestamp * 1000;
        let delta = t_ms as i64 - median as i64;
        if delta.unsigned_abs() <= rejection_threshold_ms {
            good.push(obs);
        } else {
            outliers.push(OutlierReport {
                source:   obs.source.clone(),
                protocol: obs.protocol,
                delta_ms: delta,
            });
        }
    }

    let sources_used = good.len();

    if sources_used < min_sources {
        return Err(NuncError::InsufficientSources {
            got:  sources_used,
            need: min_sources,
        });
    }

    // Intersect the uncertainty intervals of the good sources
    let mut lo = u64::MIN;
    let mut hi = u64::MAX;

    for obs in &good {
        let t_ms = obs.timestamp * 1000;
        let hw   = obs.rtt_ms / 2;
        lo = lo.max(t_ms.saturating_sub(hw));
        hi = hi.min(t_ms + hw);
    }

    // If intervals don't intersect, fall back to median with full spread as confidence.
    // This happens when stale CDN responses pass the outlier filter — tune
    // rejection_threshold_ms tighter until this doesn't occur in normal operation.
    let (midpoint_ms, confidence_ms) = if lo > hi {
        let spread = mids.last().unwrap_or(&0).saturating_sub(*mids.first().unwrap_or(&mids[0]));
        (median, spread / 2)
    } else {
        ((lo + hi) / 2, (hi - lo) / 2)
    };

    let timestamp = UNIX_EPOCH + Duration::from_millis(midpoint_ms);
    let confidence = Duration::from_millis(confidence_ms);

    Ok(NuncTime {
        timestamp,
        confidence,
        sources_queried,
        sources_used,
        outliers,
        raw: observations,
    })
}
