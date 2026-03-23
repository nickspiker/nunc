# nunc

![nunc](nunc.webp)

> *nunc* — Latin. "now, at this moment, at the present time."

Trustworthy wall-clock time via multi-source network consensus.

Every other Rust time crate assumes the system clock is ground truth.
`nunc` is what you call before you trust the system clock — or when you can't.

---

## The problem

`std::time::SystemTime::now()` reads the system clock. The system clock can be wrong. It can be wrong accidentally (fresh embedded system, drifting RTC, VM clock skew) or deliberately (adversarial environment, NTP poisoning, replay attack). Every time-dependent security property — token expiry, certificate validity, replay window — rests on an assumption that is never checked.

The standard answer is NTP, but NTP is unauthenticated by default. It tells you what a server *claims* the time is with no way to verify it wasn't intercepted, replayed, or simply lying.

## The approach

The internet is full of servers that publicly broadcast their idea of the current time — in `Date:` response headers, NTP packets, SMTP banners. Each one is an independent witness. They don't coordinate. For any adversary to fool you they must compromise all the sources you query, simultaneously, in a way that produces a coherent false consensus, without leaving signed evidence of the lie.

`nunc` queries a large, randomly-selected diverse pool of these sources in parallel, computes the consensus interval, and returns a timestamp with an explicit confidence bound.

## Why random selection matters

Server selection uses a cryptographic random nonce (CSPRNG seeded from OS entropy). An adversary cannot predict which servers you will query without knowing the nonce. Pre-positioning replayed responses across an unpredictable subset of a large diverse pool is not a practical attack.

## Why this works: the informal proof

Let *S* be the set of servers queried (selected randomly from pool *P*, |*P*| >> |*S*|).
Let *t* be the true time.
Each honest server *i* returns interval [*tᵢ* - *rttᵢ*/2, *tᵢ* + *rttᵢ*/2] containing *t*.
The intersection of all honest intervals therefore contains *t*.

For a lying server to shift the consensus it must push its reported interval outside the honest intersection *and* there must be enough lying servers to constitute a majority. Since selection is cryptographically random from a large pool, the probability of an adversary controlling a majority of the selected set without controlling the network paths to all of them simultaneously is negligible for any realistic threat model below nation-state.

The consensus interval shrinks as sources are added. The outlier rejection pass removes sources whose intervals don't overlap the median — these are either lying, stale (CDN cache hit), or simply slow.

## Usage

```rust
use nunc::{query, Mode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let t = query(Mode::Fast).await?;
    println!("time:       {}", t.timestamp());
    println!("confidence: ±{}ms", t.confidence().as_millis());
    println!("sources:    {}/{}", t.sources_used, t.sources_queried);
    Ok(())
}
```

## Modes

All modes query every protocol enabled at compile time — more precise sources are never excluded.
Modes differ only in how many sources are queried.

| Mode        | Sources | Notes                                              |
|-------------|---------|----------------------------------------------------|
| `Fast`      | 42      | ~1s wall clock. Good enough for almost everything. |
| `Thorough`  | 64      | More diversity, tighter consensus.                 |
| `Paranoid`  | 128     | For when you really mean it.                       |
| `Custom(_)` | yours   | Full control over every parameter.                 |

## Sources

### HTTPS `Date:` headers *(default)*
Every HTTPS server returns a `Date:` header. The pool spans major CDNs, government sites, national broadcasters, universities, and central banks across dozens of countries and ASNs. Cache-busting headers are sent on every request to discourage stale CDN responses. Stale responses (where `Date` predates the measured RTT) are flagged as outliers by the consensus algorithm.

### NTP / SNTP *(feature = "ntp")*
Standard UDP time protocol. Unauthenticated, but included for volume and diversity. ~960 servers from the NTP Pool Project. Weighted equally with HTTPS in consensus — the algorithm doesn't trust any single protocol more than another.

### NTS *(feature = "nts")* — RFC 8915
Network Time Security. Full TLS 1.3 key exchange (port 4460) followed by AEAD-authenticated NTP over UDP (port 123). Uses `AEAD_AES_SIV_CMAC_256` — misuse-resistant, nonce-reuse safe. A valid NTS response proves the server holds keys derived from the TLS session; a MITM on the UDP path cannot forge or replay it. The only authenticated time source in the pool.

### SMTP banners *(feature = "smtp")*
SMTP servers emit a timestamped greeting before the client sends anything. The timestamp is fresh by definition — not a cached response. Port 25 is blocked by most consumer ISPs outbound; useful in datacenter environments.

### Roughtime *(feature = "roughtime")* — IETF draft
Cryptographic nonce binding, signed responses, built-in malfeasance proof. Three public servers included.

## Instrumentation and threshold tuning

The consensus rejection threshold (`rejection_threshold_ms`) is set conservatively by default. The right value depends on your pool composition, network topology, and threat model. The distribution of raw timestamps across sources is expected to look roughly like a discrete Laplace — tight peak from well-behaved sources, long right tail from stale CDN responses and high-latency paths.

**Tune it empirically:**

```
cargo run --release --features "https,ntp,nts" --example instrument > observations.bin
```

The binary format is: per observation, `[i32 le delta_ms][hostname as ASCII][0x0A]`. Decode with the included `dump` example:

```
cargo run --example dump -- observations.bin
```

## Known limitations

- **RTT asymmetry**: the `rtt/2` correction assumes the packet took equal time in each direction. It didn't — the internet routes outbound and inbound paths independently, and the speed of light doesn't care about your topology. On asymmetric links (common on consumer broadband, worse on satellite) the true one-way delay is unknowable without a shared clock, which is exactly what we're trying to establish. The error is bounded by the path asymmetry and absorbed into the confidence interval; across many diverse sources it largely cancels.
- **Leap seconds**: servers handle leap seconds differently (step vs. 24h smear). During a leap second the consensus will show artificial spread of up to 1 second. Detect; do not attempt to correct.
- **CDN staleness**: some edge nodes serve cached responses with stale `Date:` headers. Detection is built in (timestamp predating RTT flags as outlier), but a sufficiently fresh stale response may pass. The consensus of many sources makes a single stale response statistically irrelevant.
- **UDP/123 filtering**: some ISPs and home routers intercept or filter UDP port 123. NTS-KE (TCP/4460) is unaffected; only the NTP exchange phase fails. On filtered networks NTS sources fall back to timeout and are excluded from consensus; HTTPS sources cover the gap.
- **System clock as fallback**: `nunc` does not discipline the system clock. It returns a timestamp you can compare against `SystemTime::now()` and act on the delta however you choose.

## License

MIT OR Apache-2.0
