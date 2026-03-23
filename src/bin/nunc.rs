//! nunc — take a fix on time.
//!
//! Usage:
//!   nunc                    fast fix (HTTPS, 32 sources)
//!   nunc -v                 verbose: per-source breakdown
//!   nunc -t / --thorough    HTTPS + NTP, 64 sources
//!   nunc -p / --paranoid    all protocols, 128 sources

use nunc::{query_with_config, Config, Mode};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose  = args.iter().any(|a| a == "-v" || a == "--verbose");
    let thorough = args.iter().any(|a| a == "-t" || a == "--thorough");
    let paranoid = args.iter().any(|a| a == "-p" || a == "--paranoid");
    let help     = args.iter().any(|a| a == "-h" || a == "--help");

    if help {
        eprintln!("{}", HELP);
        return;
    }

    let mode = if paranoid {
        Mode::Paranoid
    } else if thorough {
        Mode::Thorough
    } else {
        Mode::Fast
    };

    let cfg = {
        let mut c = Config::from_mode(mode);
        c.instrument = verbose;
        c
    };

    let fix = match query_with_config(cfg).await {
        Ok(f)  => f,
        Err(e) => { eprintln!("error: {e}"); std::process::exit(1); }
    };

    let unix_secs = fix.timestamp()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    println!(
        "{utc} UTC  ±{conf_ms}ms  ({used}/{queried} sources, KS p={ks:.3})",
        utc      = format_utc(unix_secs),
        conf_ms  = fix.confidence().as_millis(),
        used     = fix.sources_used,
        queried  = fix.sources_queried,
        ks       = fix.ks_p_value,
    );

    if !fix.outliers.is_empty() {
        println!("outliers ({}):", fix.outliers.len());
        for o in &fix.outliers {
            println!("  {:40}  {:>+8}ms  {:?}", o.source, o.delta_ms, o.protocol);
        }
    }

    if verbose && !fix.raw.is_empty() {
        println!("\nsources ({} responded):", fix.raw.len());
        let mut sorted = fix.raw.clone();
        sorted.sort_by_key(|o| o.rtt_ms);
        for o in &sorted {
            let sct = if o.sct_verified { "SCT✓" } else { "    " };
            println!(
                "  {:40}  {:>6}ms rtt  {sct}  {:?}",
                o.source, o.rtt_ms, o.protocol,
            );
        }
    }

    if fix.ks_p_value < 0.05 {
        eprintln!("warning: KS p={:.3} — timestamp distribution looks anomalous", fix.ks_p_value);
    }
}

// ── UTC formatter — no deps ───────────────────────────────────────────────────

fn format_utc(unix: u64) -> String {
    let secs  = unix % 60;
    let mins  = (unix / 60) % 60;
    let hours = (unix / 3600) % 24;
    let days  = unix / 86400;

    let jdn = days as i64 + 2_440_588;
    let a = jdn + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (146097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;

    let day   = e - (153 * m + 2) / 5 + 1;
    let month = m + 3 - 12 * (m / 10);
    let year  = 100 * b + d - 4800 + m / 10;

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{mins:02}:{secs:02}")
}

const HELP: &str = "\
nunc — take a fix on time

USAGE:
    nunc [OPTIONS]

OPTIONS:
    -v, --verbose     per-source breakdown sorted by RTT
    -t, --thorough    HTTPS + NTP, 64 sources
    -p, --paranoid    all protocols, 128 sources (needs port 25)
    -h, --help        this message

EXAMPLES:
    nunc
    nunc -v
    nunc -t -v

EXIT CODES:
    0   fix obtained
    1   consensus failed
";
