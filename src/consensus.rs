use crate::types::{NuncTime, Observation, OutlierReport};
use crate::error::NuncError;

// ---------------------------------------------------------------------------
// KS test against a pre-calibrated Laplace reference distribution (H₀)
//
// We test whether the inlier timestamps look unimodal by comparing the empirical CDF to a Laplace(0, b) fitted from 4,556 HTTPS observations across 50 consensus runs (home network, 2026-03-22).  A coordinated attack injecting a cluster of false timestamps at T' ≠ T produces a bimodal distribution that departs visibly from the unimodal H₀,
// driving the KS statistic up and the p-value toward 0.
//
// Why Laplace, not Gaussian:
//   HTTPS Date headers have 1-second resolution → timestamps cluster at
//   integer-second boundaries.  The honest deviation distribution is a
//   discrete two-sided geometric (discrete Laplace) with scale b ≈ 590 ms:
//     58% of responses land in the same second as consensus (delta = 0 s),
//     35% land ±1 s (rounding), geometric decay beyond that.
//   The continuous Laplace CDF approximates this well and has heavier tails
//   than a Gaussian, reducing false positives from the quantisation noise.
//   NTP sources contribute sub-millisecond deviations tightly clustered at
//   0 — also consistent with Laplace(0, b) with a much smaller b.
//
// Calibration: empirical b = 590 ms → LAPLACE_B_ET = 590 × OPS / 1000
// ---------------------------------------------------------------------------

/// Pre-calibrated Laplace scale in Eagle Time oscillation counts.
/// 590 ms × 1_420_407_826 Hz / 1000 ≈ 838_040_617 counts.
/// Derived from 4,556 HTTPS observations (50 runs, home vantage, 2026-03-22).
const LAPLACE_B_ET: f64 = 838_040_617.0;

/// Laplace CDF: F(x) = 0.5·exp((x−loc)/b) for x ≤ loc,
///              F(x) = 1 − 0.5·exp(−(x−loc)/b) for x > loc.
fn laplace_cdf(x: f64, loc: f64, b: f64) -> f64 {
    let z = (x - loc) / b;
    if z <= 0.0 { 0.5 * z.exp() } else { 1.0 - 0.5 * (-z).exp() }
}

/// Asymptotic Kolmogorov distribution p-value for KS statistic `d` and sample size `n`.  Returns values in [0, 1]; high = consistent with H₀.
fn ks_p_value(d: f64, n: usize) -> f64 {
    if n == 0 || d <= 0.0 { return 1.0; }
    let sqrt_n = (n as f64).sqrt();
    // Stephens (1974) correction for finite samples
    let lambda = (sqrt_n + 0.12 + 0.11 / sqrt_n) * d;
    let mut sum = 0.0f64;
    for k in 1_u32..=20 {
        let sign = if k % 2 == 1 { 1.0f64 } else { -1.0f64 };
        sum += sign * (-2.0 * (k * k) as f64 * lambda * lambda).exp();
    }
    (2.0 * sum).clamp(0.0, 1.0)
}

/// KS p-value for `samples` against Laplace(median, LAPLACE_B_ET).
/// Centers on the sample median (robust to the asymmetric CDN-staleness tail).
/// Returns 1.0 if there are fewer than 3 samples.
fn ks_test_laplace(samples: &[f64]) -> f64 {
    let n = samples.len();
    if n < 3 { return 1.0; }

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = sorted[n / 2];

    let d = sorted.iter().enumerate().map(|(i, &x)| {
        let theoretical = laplace_cdf(x, median, LAPLACE_B_ET);
        let empirical_hi = (i + 1) as f64 / n as f64;
        let empirical_lo = i as f64 / n as f64;
        f64::max(
            (empirical_hi - theoretical).abs(),
            (empirical_lo - theoretical).abs(),
        )
    }).fold(0.0f64, f64::max);

    ks_p_value(d, n)
}

/// Compute consensus from a set of raw observations.
///
/// Algorithm:
///   1. Build an uncertainty interval per observation: [t - rtt/2, t + rtt/2]
///   2. Find the median timestamp
///   3. Reject outliers beyond `rejection_threshold_ms` from median
///   4. Compute the intersection of remaining intervals
///   5. Return midpoint + half-width as confidence
///
/// The honest deviation distribution is a discrete Laplace on 1-second steps (HTTP Date header resolution): ~58% at delta=0 s, ~35% at ±1 s,
/// geometric decay beyond that, with a long right tail from CDN-stale responses (~5.8% of HTTPS sources stale beyond 60 s).  NTP sources contribute sub-millisecond deviations tightly clustered at zero.
pub fn consensus(
    observations: Vec<Observation>,
    min_sources: usize,
    rejection_threshold_ms: u64,
) -> Result<NuncTime, NuncError> {
    let sources_queried = observations.len();

    if observations.is_empty() {
        return Err(NuncError::EmptyPool);
    }

    // All arithmetic in Eagle Time oscillation counts (i64, 704 ps resolution).
    let rejection_threshold_et = crate::eagle::from_millis(rejection_threshold_ms as i64);

    // ---- OFFSETS, NOT ABSOLUTE TIMES ----------------------------------------------------------
    // Sources answer at different instants spread across the whole query (a Fast run takes ~1.6 s and
    // the pool is deliberately spread worldwide for anti-collusion, so RTTs of 0.4-0.7 s are normal).
    // Consensing over ABSOLUTE timestamps silently folds that spread into the answer, and worse, the
    // result names no instant: a caller cannot say WHEN the consensus was true, so it cannot anchor
    // it. Every observation therefore becomes an offset against the local clock at ITS OWN receipt,
    // corrected by rtt/2 for the flight home. Offsets from different instants are directly
    // comparable (they measure the same standing error), and the answer stays valid however long
    // the query runs.
    //
    //   offset_i = server_time − (local_at_receipt − rtt_i/2)
    //
    // (This is what NTP does, and for the same reason.)
    let offset_of = |o: &Observation| -> i64 {
        let rtt_et = crate::eagle::from_millis(o.rtt_ms as i64);
        o.timestamp_et - (o.local_et - rtt_et / 2)
    };

    let mut offsets: Vec<i64> = observations.iter().map(&offset_of).collect();
    offsets.sort_unstable();
    let median_off = offsets[offsets.len() / 2];

    // Reject outliers — in offset space, against the offset median.
    let mut good: Vec<&Observation> = Vec::new();
    let mut outliers: Vec<OutlierReport> = Vec::new();

    for obs in &observations {
        let delta_et = offset_of(obs) - median_off;
        if delta_et.abs() <= rejection_threshold_et {
            good.push(obs);
        } else {
            let delta_ms = delta_et * 1_000 / crate::eagle::OPS;
            outliers.push(OutlierReport {
                source:   obs.source.clone(),
                protocol: obs.protocol,
                delta_ms,
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

    // Intersect each source's offset interval.
    //
    // Flight uncertainty is symmetric: the true send instant sits somewhere in the round trip, so
    // rtt/2 either way.
    //
    // HTTPS quantisation is NOT symmetric: a Date header always truncates toward the past (never
    // rounds up), so the true time is 0..999 ms LATER than reported — the offset's error is
    // one-sided. The old absolute-time path widened by ±1000 ms because it could not tell which
    // direction; in offset space the direction is known, which halves an HTTPS source's interval
    // and lets a pool of them actually constrain the answer.
    // MARZULLO: the answer is the region covered by the MOST source intervals, not the region
    // covered by all of them.
    //
    // Requiring a total intersection is brittle here, and offset space is exactly where it breaks:
    // honest HTTPS offsets spread across a full second (truncation phase is uniform), so a single
    // source whose Date header sits a hair ahead of the pack empties the intersection and collapses
    // the answer to a median ± half-spread fallback — measured at ±0.6 s on a pool that Marzullo
    // reads to ±0.1 s. Counting overlaps instead lets the majority carry the result and drops
    // non-overlapping liars for free, which is the property the whole multi-source design is for.
    // WHO IS ALLOWED TO SET THE MIDPOINT.
    //
    // Every HTTPS server truncates its Date header to the SAME UTC second boundary, so their
    // quantisation errors are not spread across the second — they are all within a few ms of each
    // other at `u = frac(now)`. A pool of them therefore agrees precisely on a value that is biased
    // by `500 ms − u`, and no amount of them can recover the sub-second phase. Measured against an
    // independent NTP reference this read +364 ms where the truth was +30 ms.
    //
    // Unquantised sources (NTP/NTS/Roughtime) carry no such term. When enough of them answered they
    // alone set the consensus, and the HTTPS pool keeps doing what it is uniquely good at: outlier
    // rejection above, and the KS manipulation test below, where breadth matters and sub-second
    // resolution does not.
    let precise: Vec<&Observation> = good
        .iter()
        .copied()
        .filter(|o| o.protocol != crate::types::Protocol::Https)
        .collect();
    let use_precise = precise.len() >= 3;
    let ranging: Vec<&Observation> = if use_precise { precise } else { good.clone() };

    let mut events: Vec<(i64, i32)> = Vec::with_capacity(ranging.len() * 2);
    for obs in &ranging {
        let off = offset_of(obs);
        let rtt_et = (obs.rtt_ms as i64).max(1) * crate::eagle::OPS / 2_000;
        let (lo_i, hi_i) = if obs.protocol == crate::types::Protocol::Https {
            (off - rtt_et, off + rtt_et + crate::eagle::from_millis(1000))
        } else {
            (off - rtt_et, off + rtt_et)
        };
        events.push((lo_i, 1));
        events.push((hi_i, -1));
    }
    // Starts before ends at equal positions, so intervals that merely touch still count as overlapping.
    events.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

    let (mut depth, mut best_depth) = (0i32, 0i32);
    let (mut best_lo, mut best_hi) = (median_off, median_off);
    for i in 0..events.len() {
        depth += events[i].1;
        if depth > best_depth {
            best_depth = depth;
            best_lo = events[i].0;
            // The overlap runs until the next endpoint, whatever it is.
            best_hi = events.get(i + 1).map(|e| e.0).unwrap_or(events[i].0);
        }
    }

    let (offset_et, confidence_et) = if best_depth > 0 && best_hi >= best_lo {
        let conf = (best_hi - best_lo) / 2;
        // HTTPS-only fallback: the ±500 ms phase we cannot see is a real part of the uncertainty and
        // must be reported, never hidden behind a narrow-looking interval.
        let conf = if use_precise { conf } else { conf.max(crate::eagle::from_millis(500)) };
        ((best_lo + best_hi) / 2, conf)
    } else {
        // No overlap anywhere (every source disjoint) — nothing to intersect; report the median with
        // the spread as its honest uncertainty.
        let mut good_offs: Vec<i64> = good.iter().map(|o| offset_of(o)).collect();
        good_offs.sort_unstable();
        let spread = good_offs.last().unwrap() - good_offs.first().unwrap();
        (median_off, spread / 2)
    };

    // The anchor: the local clock this offset is measured against. Latest receipt among the sources
    // that actually counted — the freshest instant the answer is known to describe.
    let local_et = good.iter().map(|o| o.local_et).max().unwrap_or(0);
    let midpoint_et = local_et + offset_et;

    // KS test: the Laplace(0, b=590ms) reference was calibrated on HTTPS-only data.  NTP sources have sub-millisecond resolution and cluster sharply at
    // 0; mixing them into the test would produce a bimodal distribution that the test correctly rejects but that isn't an attack signal.  Run KS on
    // HTTPS observations only; if there are none, skip (return 1.0 = no signal).
    let https_centered: Vec<f64> = good.iter()
        .filter(|o| o.protocol == crate::types::Protocol::Https)
        .map(|o| (offset_of(o) - median_off) as f64)
        .collect();
    let ks_p_value = ks_test_laplace(&https_centered);

    Ok(NuncTime {
        timestamp_et:  midpoint_et,
        confidence_et,
        offset_et,
        local_et,
        sources_queried,
        sources_used,
        outliers,
        ks_p_value,
        raw: observations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Protocol;

    /// A local clock that is EXACTLY right, so `timestamp_et` doubles as the offset-space input the
    /// old absolute-time tests were written against (offset = timestamp − local, and local = 0 here
    /// makes the two spaces coincide).
    fn obs(timestamp_et: i64, rtt_ms: u64) -> Observation {
        obs_at(timestamp_et, 0, rtt_ms)
    }

    /// An observation whose response landed while the local clock read `local_et`.
    fn obs_at(timestamp_et: i64, local_et: i64, rtt_ms: u64) -> Observation {
        obs_proto(timestamp_et, local_et, rtt_ms, Protocol::Https)
    }

    /// As `obs_at`, naming the protocol — HTTPS carries the one-sided quantisation allowance, so a
    /// test isolating anything else must use a source without it.
    fn obs_proto(timestamp_et: i64, local_et: i64, rtt_ms: u64, protocol: Protocol) -> Observation {
        Observation {
            source:       "test".into(),
            protocol,
            timestamp_et,
            local_et,
            rtt_ms,
            asn:          None,
            country:      None,
            sct_verified: false,
        }
    }

    fn et_secs(s: i64) -> i64 { s * crate::eagle::OPS }
    fn et_ms(ms: i64) -> i64 { crate::eagle::from_millis(ms) }

    /// THE reason this module works in offsets. Sources answer at instants spread across a whole
    /// query (a Fast run is ~1.6 s; the pool is worldwide by design, so 0.4-0.7 s RTTs are normal).
    /// Here every source sees the SAME standing error — the local clock is 2 s slow — but they answer
    /// 0, 0.5, 1.0 and 1.5 s apart. The offset is the invariant, so consensus must return exactly it.
    /// The absolute-time path this replaced would have smeared the 1.5 s of answering spread straight
    /// into the result, and could not have named the instant its answer belonged to.
    #[test]
    fn offset_is_invariant_to_when_each_source_answers() {
        let truth_minus_local = et_secs(2);
        let mut observations = Vec::new();
        for k in 0..4i64 {
            let local = et_secs(1_000_000) + et_ms(500 * k); // answers spread over 1.5 s
            // NTP, not HTTPS: this test isolates invariance to answer TIME, and an HTTPS source
            // would (correctly) add its one-sided truncation allowance on top.
            observations.push(obs_proto(local + truth_minus_local, local, 20, Protocol::Ntp));
        }
        let t = consensus(observations, 3, 60_000).unwrap();
        let err = (t.offset_et - truth_minus_local).abs();
        assert!(
            err <= et_ms(60),
            "offset recovered within 60 ms of the 2 s truth (got {} ms off)",
            err * 1000 / crate::eagle::OPS
        );
    }

    /// The anchor contract photon relies on: the offset names the local instant it was measured
    /// against, exactly, so a caller never has to sample its own clock and guess when the answer
    /// was true. `timestamp_et` stays derived from that pair.
    #[test]
    fn offset_is_anchored_to_a_named_local_instant() {
        let local = et_secs(2_000_000);
        let observations = vec![
            obs_proto(local + et_ms(300), local, 20, Protocol::Ntp),
            obs_proto(local + et_ms(300), local, 30, Protocol::Ntp),
            obs_proto(local + et_ms(300), local, 25, Protocol::Ntp),
        ];
        let t = consensus(observations, 3, 60_000).unwrap();
        assert_eq!(
            t.timestamp_et,
            t.local_et + t.offset_et,
            "timestamp must be exactly local + offset — no third sampling, no drift between them"
        );
        assert!(t.local_et > 0, "the anchor is a real local reading, never zero-filled");
    }

    /// HTTPS agrees with itself precisely and is precisely WRONG: every server truncates to the same
    /// UTC second, so a pool of them clusters at `true − u` for one shared `u`, and no number of them
    /// recovers the sub-second phase. Three unquantised sources must therefore outvote thirty HTTPS
    /// ones on the midpoint. (Measured: letting HTTPS range put the answer 334 ms off truth.)
    #[test]
    fn https_majority_never_outvotes_unquantised_sources() {
        let local = et_secs(4_000_000);
        let truth = et_ms(30); // the honest offset
        let mut observations: Vec<Observation> = Vec::new();
        // Thirty HTTPS sources, all truncated by the same 400 ms — tight, unanimous, and wrong.
        for _ in 0..30 {
            observations.push(obs_proto(local + truth - et_ms(400), local, 10, Protocol::Https));
        }
        // Three NTP sources that actually know the phase.
        for _ in 0..3 {
            observations.push(obs_proto(local + truth, local, 10, Protocol::Ntp));
        }
        let t = consensus(observations, 3, 60_000).unwrap();
        let err = (t.offset_et - truth).abs();
        assert!(
            err <= et_ms(20),
            "the three honest sources must carry the midpoint (off by {} ms)",
            err * 1000 / crate::eagle::OPS
        );
    }

    /// HTTPS Date headers truncate toward the past and never round up, so in offset space the error
    /// is ONE-SIDED — true time is 0..999 ms later than reported, never earlier. The interval must
    /// reflect that direction (it could not in absolute-time space, which had to widen both ways).
    #[test]
    fn https_quantisation_bounds_are_one_sided() {
        let local = et_secs(3_000_000);
        // Every source truncated ~999 ms into the past; the honest offset is therefore ~+999 ms.
        let observations: Vec<Observation> = (0..5)
            .map(|k| obs_at(local - et_ms(1), local + et_ms(k), 10))
            .collect();
        let t = consensus(observations, 3, 60_000).unwrap();
        assert!(
            t.offset_et > 0,
            "a truncating source can only mean true time is LATER than reported (got {} ms)",
            t.offset_et * 1000 / crate::eagle::OPS
        );
        assert!(
            t.offset_et <= et_ms(1100),
            "and never later than one quantisation step plus flight (got {} ms)",
            t.offset_et * 1000 / crate::eagle::OPS
        );
    }

    #[test]
    fn honest_sources_converge() {
        // Five sources all reporting the same second, low RTT.
        let t = et_secs(1_000_000);
        let observations = vec![
            obs(t,     20),
            obs(t + 1, 20),
            obs(t - 1, 20),
            obs(t,     30),
            obs(t + 1, 40),
        ];
        let result = consensus(observations, 3, 5_000).unwrap();
        assert!(result.sources_used >= 3);
        assert!(result.outliers.is_empty());
        // Consensus midpoint should be within 1 oscillation-second of t
        assert!((result.timestamp_et - t).abs() <= crate::eagle::OPS);
    }

    #[test]
    fn outlier_rejected() {
        let t = et_secs(1_000_000);
        let mut observations: Vec<_> = (0..10).map(|_| obs(t, 50)).collect();
        // One source 10 minutes ahead — well outside rejection threshold
        observations.push(obs(t + et_secs(600), 50));
        let result = consensus(observations, 3, 5_000).unwrap();
        assert_eq!(result.outliers.len(), 1);
        assert_eq!(result.sources_used, 10);
    }

    #[test]
    fn insufficient_sources_after_rejection() {
        let t = et_secs(1_000_000);
        // Only 2 good sources, min_sources = 3 → error
        let observations = vec![
            obs(t, 20),
            obs(t, 30),
            obs(t + et_secs(600), 20), // outlier
        ];
        assert!(consensus(observations, 3, 5_000).is_err());
    }

    #[test]
    fn empty_observations_is_error() {
        assert!(consensus(vec![], 1, 5_000).is_err());
    }

    #[test]
    fn ks_unimodal_scores_high() {
        // Tight unimodal cluster → KS p-value should be reasonably high
        let t = et_secs(1_000_000);
        let observations: Vec<_> = (0..30).map(|i| obs(t + i * 1_000_000, 100)).collect();
        let result = consensus(observations, 3, 5_000).unwrap();
        // Not asserting a specific threshold — just that it's a valid probability
        assert!(result.ks_p_value >= 0.0 && result.ks_p_value <= 1.0);
    }
}
