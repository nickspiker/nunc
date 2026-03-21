# nunc

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

`nunc` queries a large, TRNG-seeded diverse pool of these sources in parallel, computes the consensus interval, and returns a timestamp with an explicit confidence bound.

## Why TRNG seeding matters

Server selection is seeded from a cryptographic random nonce. An adversary cannot predict which servers you will query without knowing the nonce. Pre-positioning replayed responses across an unpredictable subset of a large diverse pool is not a practical attack.

## Why this works: the informal proof

Let *S* be the set of servers queried (selected randomly from pool *P*, |*P*| >> |*S*|).  
Let *t* be the true time.  
Each honest server *i* returns interval [*tᵢ* - *rttᵢ*/2, *tᵢ* + *rttᵢ*/2] containing *t*.  
The intersection of all honest intervals therefore contains *t*.  

For a lying server to shift the consensus it must push its reported interval outside the honest intersection *and* there must be enough lying servers to constitute a majority.  Since selection is TRNG-seeded from a large pool, the probability of an adversary controlling a majority of the selected set without controlling the network paths to all of them simultaneously is negligible for any realistic threat model below nation-state.

The consensus interval shrinks as sources are added. The outlier rejection pass removes sources whose intervals don't overlap the median — these are either lying, stale (CDN cache hit), or simply slow.

## Usage

```rust
use nunc_time::{query, Mode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let t = query(Mode::Fast).await?;
    println!("time:       {:?}", t.timestamp);
    println!("confidence: ±{}ms", t.confidence.as_millis());
    println!("sources:    {}/{}", t.sources_used, t.sources_queried);
    Ok(())
}
```

## Modes

| Mode        | Protocols         | Sources | Notes                              |
|-------------|-------------------|---------|------------------------------------|
| `Fast`      | HTTPS             | 32      | ~1s wall clock. Works everywhere.  |
| `Thorough`  | HTTPS + NTP       | 64      | Broader diversity, slower.         |
| `Paranoid`  | HTTPS + NTP + SMTP| 128     | SMTP blocked on consumer ISPs.     |
| `Custom(_)` | your choice       | your choice | Full control.                  |

## Sources

### HTTPS `Date:` headers
Every HTTPS server returns a `Date:` header. The pool spans major CDNs, government sites, national broadcasters, universities, and central banks across dozens of countries and ASNs. Cache-busting headers are sent on every request to discourage stale CDN responses. Stale responses (where `Date` predates the measured RTT) are flagged as outliers by the consensus algorithm.

### NTP / SNTP
Standard UDP time protocol. Unauthenticated, but included for volume and diversity. Weighted equally with HTTPS in consensus — the algorithm doesn't trust any single protocol more than another.

### SMTP banners *(feature = "smtp")*
SMTP servers emit a timestamped greeting before the client sends anything. The timestamp is fresh by definition — not a cached response. Port 25 is blocked by most consumer ISPs outbound; useful in datacenter environments.

### Roughtime *(future)*
The right answer — cryptographic nonce binding, signed responses, built-in malfeasance proof. Three public servers as of early 2026. Included when the ecosystem matures enough to be useful.

## Instrumentation and threshold tuning

The consensus rejection threshold (`rejection_threshold_ms`) is set conservatively by default. The right value depends on your pool composition, network topology, and threat model. The distribution of raw timestamps across sources is expected to look roughly like a blackbody curve — tight peak from well-behaved sources, long tail from stale CDN responses and high-latency paths.

**Tune it empirically:**

```
cargo run --example instrument > observations.json
```

Plot `timestamp` vs count from the JSON output. The threshold should sit at the natural gap between the peak and the tail. Don't guess — run it, look at the data, then set the threshold.

## Known limitations

- **RTT asymmetry**: the `rtt/2` correction assumes symmetric latency. On asymmetric links (common on consumer broadband) the uncertainty interval is slightly off. The effect is bounded by the asymmetry magnitude and is absorbed into the confidence interval.
- **Leap seconds**: servers handle leap seconds differently (step vs. 24h smear). During a leap second the consensus will show artificial spread of up to 1 second. Document and detect; do not attempt to correct.
- **CDN staleness**: some edge nodes serve cached responses with stale `Date:` headers. Detection is built in (timestamp predating RTT flags as outlier), but a sufficiently fresh stale response may pass. The consensus of many sources makes a single stale response statistically irrelevant.
- **System clock as fallback**: `nunc` does not discipline the system clock. It returns a `SystemTime` you can compare against `SystemTime::now()` and act on the delta however you choose.

## Name

`nunc` is the crates.io target name (pending transfer from an abandoned 2021 stub). This crate is published as `nunc` in the interim.

## License

MIT OR Apache-2.0
