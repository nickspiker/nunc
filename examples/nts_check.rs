//! Live test for NTS: queries known NTS servers and prints the result.
//!
//! Usage:
//!   cargo run --example nts_check --features nts [host ...]
//!
//! Defaults to time.cloudflare.com, ptbtime1.ptb.de, nts.netnod.se.
#[cfg(feature = "nts")]
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let hosts: Vec<&str> = if args.is_empty() {
        vec!["time.cloudflare.com", "ptbtime1.ptb.de", "nts.netnod.se"]
    } else {
        args.iter().map(String::as_str).collect()
    };

    for host in hosts {
        match nunc::sources::nts::nts::query(host).await {
            Some(obs) => println!("[OK]  {host}  unix={}  rtt={}ms",
                obs.timestamp_et / nunc::OPS as i64, obs.rtt_ms),
            None => println!("[FAIL] {host}"),
        }
    }
}

#[cfg(not(feature = "nts"))]
fn main() { eprintln!("build with --features nts"); }
