/// Instrumentation example — collects raw observations and writes a binary
/// file for ex-Gaussian fitting.
///
/// Format (stdout, binary):
///   per observation: [i32 le delta_ms][hostname as ASCII][0x0A newline]
///
/// Usage:
///   cargo run --release --example instrument > local.bin
///   NUNC_RUNS=50 cargo run --release --example instrument > local.bin
///
/// Aggregate across vantage points:
///   cat local.bin tmobile.bin aws.bin > all.bin
///
/// Decode / inspect the binary:
///   cargo run --example dump -- all.bin

use std::io::Write;
use nunc::{query_with_config, Config, Protocol};

#[tokio::main]
async fn main() {
    let runs: u32 = std::env::var("NUNC_RUNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let cfg = Config {
        protocols:              vec![Protocol::Https, Protocol::Ntp, Protocol::Nts],
        batch_size:             350,
        target_sources:         256,
        min_sources:            4,
        rejection_threshold_ms: 60_000, // wide open — don't reject yet
        instrument:             true,
        pool:                   None,
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for run in 0..runs {
        match query_with_config(cfg.clone()).await {
            Ok(result) => {
                let consensus_et = result.timestamp_et;
                let ops = nunc::OPS;

                eprintln!(
                    "[run {}/{}] ±{}ms  {}/{} sources  {} outliers  KS p={:.3}",
                    run + 1, runs,
                    result.confidence().as_millis(),
                    result.sources_used,
                    result.sources_queried,
                    result.outliers.len(),
                    result.ks_p_value,
                );

                for obs in &result.raw {
                    let delta_et = consensus_et - obs.timestamp_et;
                    let delta_ms = (delta_et * 1_000 / ops) as i32;
                    out.write_all(&delta_ms.to_le_bytes()).unwrap();
                    out.write_all(obs.source.as_bytes()).unwrap();
                    out.write_all(b"\n").unwrap();
                }
            }
            Err(e) => eprintln!("[run {}/{}] error: {e}", run + 1, runs),
        }

        if run + 1 < runs {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}
