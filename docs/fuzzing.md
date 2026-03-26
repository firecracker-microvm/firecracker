# Fuzzing

> [!WARNING]
>
> The fuzzing feature is not for production use. Binaries built with this
> feature must never be deployed to production.

Firecracker includes compile-time helpers for fuzz testing its internals via the
`fuzzing` feature flag.

## What it changes

Building with `--features fuzzing` alters several subsystems to make Firecracker
more amenable to fuzz testing:

- TCP Initial Sequence Numbers use a deterministic hardcoded value instead of
  the usual random ones, so network behavior is reproducible across runs.
- The balloon device processes the stats queue inline rather than relying on the
  timer-driven path, which is not available during fuzzing.

## Building

To build Firecracker with the fuzzing helpers enabled:

```bash
cargo build --features "fuzzing"
```
