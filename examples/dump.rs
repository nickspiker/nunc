//! Decode and print a binary observation file produced by the `instrument` example.
//!
//! Usage:
//!   cargo run --example dump -- local.bin
//!   cargo run --example dump -- all.bin | sort -n | head -20

use std::io::{BufRead, BufReader, Read};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: dump <file.bin>");
        std::process::exit(1);
    });

    let file = std::fs::File::open(&path).unwrap_or_else(|e| {
        eprintln!("error opening {path}: {e}");
        std::process::exit(1);
    });

    let mut reader = BufReader::new(file);
    let mut delta_buf = [0u8; 4];

    loop {
        match reader.read_exact(&mut delta_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => { eprintln!("read error: {e}"); break; }
        }
        let delta_ms = i32::from_le_bytes(delta_buf);

        let mut host = String::new();
        reader.read_line(&mut host).unwrap_or(0);
        let host = host.trim_end_matches('\n');

        println!("{delta_ms:>8}ms  {host}");
    }
}
