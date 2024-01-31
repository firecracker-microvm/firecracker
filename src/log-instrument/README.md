# log-instrument

Offers an attribute procedural macro that adds
[`log::trace!`](https://docs.rs/log/latest/log/macro.trace.html) events at the
start and end of attributed functions.

## Example

```rust
use log::*;

fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Trace)
        .init();
    info!("{}", one(2));
    info!("{}", one(3));
    info!("{}", one(4));
}
#[log_instrument::instrument]
fn one(x: u32) -> u32 {
    let cmp = x == 2;
    debug!("cmp: {cmp}");
    if cmp {
        return 4;
    }
    two(x + 3)
}
#[log_instrument::instrument]
fn two(x: u32) -> u32 {
    let res = x % 2;
    debug!("res: {res}");
    res
}
```

Outputs:

```
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:38:00Z DEBUG six] cmp: true
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:38:00Z INFO  six] 4
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:38:00Z DEBUG six] cmp: false
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)::one>>two
[2023-10-12T16:38:00Z DEBUG six] res: 0
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)::one<<two
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:38:00Z INFO  six] 0
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:38:00Z DEBUG six] cmp: false
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)::one>>two
[2023-10-12T16:38:00Z DEBUG six] res: 1
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)::one<<two
[2023-10-12T16:38:00Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:38:00Z INFO  six] 1
```
