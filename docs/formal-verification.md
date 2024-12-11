# Formal Verification in Firecracker

According to Firecracker’s
[threat model](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md#threat-containment),
all vCPUs are considered to be running potentially malicious code from the
moment they are started. This means Firecracker can make no assumptions about
well-formedness of data passed to it by the guest, and have to operate *safely*
no matter what input it is faced with. Traditional testing methods alone cannot
guarantee about the general absence of safety issues, as for this we would need
to write and run every possible unit test, exercising every possible code path -
a prohibitively large task.

To partially address these limitations, Firecracker is additionally using formal
verification to go further in verifying that safety issues such as buffer
overruns, panics, use-after-frees or integer overflows cannot occur in critical
components. We employ [Kani](https://github.com/model-checking/kani/), a formal
verification tool written specifically for Rust, which allows us to express
functional properties (such as any user-specified assertion) in familiar
Rust-style by replacing concrete values in unit tests with `kani::any()`. For
more details on how Kani works, and what properties it can verify, check out its
official [Kani book](https://model-checking.github.io/kani/) or try out this
[tutorial](https://model-checking.github.io/kani/kani-tutorial.html).

We aim to have Kani harnesses for components that directly interact with data
from the guest, such as the TCP/IP stack powering our microVM Metadata Service
(MMDS) integration, or which are difficult to test traditionally, such as our
I/O Rate Limiter. Our Kani harnesses live in `verification` modules that are
tagged with `#[cfg(kani)]`, similar to how unit tests in Rust are usually
structured.

Note that for some harnesses, Kani uses a “bounded” approach, where the inputs
are restricted based on some assumptions (e.g. the size of an Ethernet frame
being 1514 bytes). **Harnesses are only as strong as the assumptions they make,
so all guarantees from the harness are only valid based on the set of
assumptions we have in our Kani harnesses.** Generally, they should strive to
*over-approximate*, meaning it is preferred they cover some “impossible”
situations instead of making too strong assumptions that cause them to exclude
realistic scenarios.

## How to run Kani harnesses

To ensure that no incoming code changes cause regressions on formally verified
properties, **all Kani harnesses are run on every pull request in our CI.** To
check whether the harnesses all work for your pull request, check out the “Kani”
[Buildkite](https://buildkite.com/) step.

To run our harnesses locally, you can either enter our CI docker container via
`./tools/devtool shell -p`, or by
[installing Kani](https://model-checking.github.io/kani/install-guide.html#installing-the-latest-version)
locally. Note that the first invocation of Kani post-installation might take a
while, due to it setting up some dependencies.

Individual harnesses can then be executed using `cargo kani` similarly to how
`cargo test` can run individual unit tests, the only difference being that the
harness needs to be specified via `--harness`. Note, however, that many
harnesses require significant memory, and might result in OOM conditions.

## An example harness

The following is adapted from our Rate Limiter harness suite. It aims to verify
that creation of a rate-limiting policy upholds all
[Kani supported safety invariants](https://model-checking.github.io/kani/tutorial-kinds-of-failure.html)
(which can roughly be summarized as “everything that leads to a panic in a debug
build”), as well as results in a valid policy. A first attempt might look
something like this:

```
#[kani::proof]
fn verify_token_bucket_new() {
    let token_budget = kani::any();
    let complete_refill_time_ms = kani::any();

    // Checks if the `TokenBucket` is created with invalid inputs, the result
    // is always `None`.
    match TokenBucket::new(token_budget, 0, complete_refill_time_ms) {
        None => assert!(size == 0 || complete_refill_time_ms == 0),
        Some(bucket) => assert!(bucket.is_valid()),
    }
}
```

The `#[kani::proof]` attribute tells us that the function is a harness to be
picked up by the Kani compiler. It is the Kani equivalent of `#[test]`. Lines
3-5 indicate that we want to verify that policy creation works for arbitrarily
sized token buckets and arbitrary refill times. **This is the key difference to
a unit test**, where we would be using concrete values instead (e.g.
`let token_budget = 10;`). Note that Kani will not produce an executable, but
instead *statically* verifies that code does not violate invariants. We do not
actually execute the creation code for all possible inputs.

The final match statement tells us the property we want to verify, which is
“*bucket creation only fails if size of refill time are zero*”. In all other
cases, we assert `new` to give us a valid bucket. We mapped these properties
with assertions. If the verification fails, then that is because one of our
properties do not hold.

Now that we understand the code in the harness, let's try to verify
`TokenBucket::new` with the Kani!

If we run `cargo kani --harness verify_token_bucket_new` we will be greeted by

```
SUMMARY: ** 1 of 147 failed Failed Checks: attempt to multiply with overflow
File: "src/rate_limiter/src/lib.rs", line 136, in TokenBucket::new

VERIFICATION:- FAILED
Verification Time: 0.21081695s
```

In this particular case, Kani has found a safety issue related to an integer
overflow! Due to `complete_refill_time_ms` getting converted from milliseconds
to nanoseconds in the constructor, we have to take into consideration that the
nanosecond value might not fit into a `u64` anymore. Here, the finding is
benign, as no one would reasonably configure a `ratelimiter` with a replenish
time of 599730287.457 *years*. A
[quick check](https://github.com/firecracker-microvm/firecracker/commit/0db2a130ca4eeffeca9a46e7b6bd45c1bc1c9e21)
in the constructor fixes it. However, we will also have to adjust our harness!
Rerunning the harness from above now yields:

```
SUMMARY: ** 1 of 149 failed Failed Checks: assertion failed: size == 0
                                            || complete_refill_time_ms == 0
File: "src/rate_limiter/src/lib.rs", line 734, in verification::verify_token_bucket_new

VERIFICATION:- FAILED
Verification Time: 0.21587047s
```

This makes sense: There are now more scenarios in which we explicitly fail
construction. Changing our failure property from
`size == 0 || complete_refill_time_ms == 0` to
`size == 0 || complete_refill_time_ms == 0 || complete_refill_time >= u64::MAX / 1_000_000`
in the harness will account for this change, and rerunning the harness will now
tell us that no more issues are found:

```
SUMMARY: ** 0 of 150 failed

VERIFICATION:- SUCCESSFUL
Verification Time: 0.19135727s
```

## FAQ

**Q:** What is the Kani verifier?\
**A:** The [Kani Rust Verifier](https://github.com/model-checking/kani) is a
bit-precise model checker for Rust. Kani is particularly useful for verifying
unsafe code blocks in Rust, where the
“[unsafe superpowers](https://doc.rust-lang.org/stable/book/ch19-01-unsafe-rust.html#unsafe-superpowers)"
are unchecked by the compiler.

**Q:** What safety properties does Kani verify?\
**A:** Kani verifies memory safety properties (e.g., invalid-pointer
dereferences, out-of-bounds array access), user-specified assertions (i.e.,
`assert!(...)`), the absence of `panic!()`s (e.g., `unwrap()` on `None` values),
and the absence of some types of unexpected behavior (e.g., arithmetic
overflows). For a full overview, see the
[Kani documentation](https://model-checking.github.io/kani/tutorial-kinds-of-failure.html).

**Q:** Do we expect all contributors to write harnesses for newly introduced
code?\
**A:** No. Kani is complementary to unit testing, and we do not have target for
“proof coverage”. We employ formal verification in especially critical code
areas. Generally we do not expect someone who might not be familiar with formal
tools to contribute harnesses. We do expect all contributed code to pass
verification though, just like we expect it to pass unit test!

**Q:** How should I report issues related to any Firecracker harnesses?\
**A:** Our Kani harnesses verify safety critical invariants. If you discover a
flaw in a harness, please report it using the
[security issue disclosure process](https://github.com/firecracker-microvm/firecracker/blob/main/SECURITY.md).

**Q:** How do I know which properties I should prove in the Kani harness?\
**A:** Generally, these are given by some sort of specification. This can either
be the function contract described in its document (e.g. what relation between
input and output do callers expect?), or even something formal such as the
TCP/IP standard. Don't forget to mention the specification in your proof
harness!

**Q:** Where do I debug a broken proof?\
**A:** Check out the Kani book section on
[debugging verification failures](https://model-checking.github.io/kani/debugging-verification-failures.html).
