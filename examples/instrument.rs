/// Instrumentation example.
///
/// Run this, pipe the JSON output to your plotter of choice, and look at the
/// distribution.  The consensus threshold should be tuned against real data,
/// not guessed.
///
/// Usage:
///   cargo run --example instrument > observations.json
///   # then plot timestamp vs count, color by protocol

use nunc_time::{query_with_config, Config, Protocol};

#[tokio::main]
async fn main() {
    let cfg = Config {
        protocols:              vec![Protocol::Https, Protocol::Ntp],
        server_count:           64,
        min_sources:            4,   // low floor — we want to see everything
        rejection_threshold_ms: 60_000, // wide open — don't reject anything yet
        instrument:             true,
        pool:                   None,
    };

    match query_with_config(cfg).await {
        Ok(result) => {
            eprintln!(
                "consensus: {:?} ± {:?}ms  ({}/{} sources, {} outliers)",
                result.timestamp,
                result.confidence.as_millis(),
                result.sources_used,
                result.sources_queried,
                result.outliers.len(),
            );
            // Dump raw observations as JSON for plotting
            println!("{}", serde_json::to_string_pretty(&result.raw).unwrap());
        }
        Err(e) => eprintln!("error: {e}"),
    }
}
