# Profile-Guided Optimization (PGO) for Firecracker

This document provides a guide for building Firecracker using Profile-Guided
Optimization (PGO) in an isolated manner.

PGO can help improve performance by using runtime profiling data to guide
compiler optimizations. This process is fully **optional** and does **not**
affect the default Firecracker build system.

## Overview

PGO allows the Rust compiler (via LLVM) to use runtime profiling data to
optimize the generated binary for actual workloads. This generally results in
performance improvements for CPU-bound applications like Firecracker.

We generate .profraw files at runtime and merge them into .profddata files to
then be reused in an optimized build of Firecracker.

The PGO build process involves three main phases:

1. **Instrumentation**: Build Firecracker with instrumentation to collect
   profiling data.
1. **Profiling**: Run realistic workloads to generate `.profraw` profiling
   files.
1. **Optimize**: Rebuild Firecracker using the collected profiling data for
   improved performance.

## 1. Build with Instrumentation

Build Firecracker with profiling instrumentation enabled. If starting in the
`firecracker` directory, the command will be:

```
./tools/devtool pgo_build instrument
```

This produces a binary that, when executed, generates `.profraw` files
containing runtime behavior data.

______________________________________________________________________

\*\* Note: the ideal environment for PGO is the same as the ideal environment
for firecracker: x86_64 architecture, Ubuntu OS (24.04 currently), and bare
metal (so that /dev/kvm is exposed). However, this step specifically can be done
on non-x86_64 machines with
`RUSTFLAGS="-Cprofile-generate=/tmp/firecracker-profdata" cargo build --release --package firecracker`.

### Common Issue: Failed to run custom build command for `cpu-template-helper`

Try: Ensuring the build directory exists and is writable with:

```
mkdir -p src/cpu-template-helper/build
chmod -R u+rw src/cpu-template-helper/build
```

Also ensure all dependencies (e.g., aws-lc-sys, userfaultfd-sys) can be built by
running:

```
cargo clean
cargo build --release
```

### Common Issue: failed to run custom build command for userfaultfd-sys v0.5.0

Try: `sudo apt install libclang-dev clang pkg-config`

### Common Issue: failed to run custom build command for aws-lc-sys v0.28.1

Try: `sudo apt install cmake ninja-build perl`

### Common Issue: a bunch of errors like..

```
OUTPUT: Failed to compile memcmp_invalid_stripped_check
note: run with RUST_BACKTRACE=1 environment variable to display a backtrace
warning: build failed, waiting for other jobs to finish...
```

You might have an issue with global include-path overrides.

## 2. Profiling

Run realistic workloads to generate these `.profraw` files. Here are some
examples of typical workloads:

- Boot a microVM
- Simulate network activity on a microVM
- Simulate basic I/O on a microVM

Try to touch all major systems you personally care about optimizing so that you
can benchmark it against the base build later.

Here's an example process of booting a minimal microVM:

1. Download a test kernel and rootfs.
1. Start Firecracker
1. Use curl to configure in another terminal. E.g.,

```
# Configure boot source
curl --unix-socket $API_SOCKET -i \
  -X PUT 'http://localhost/boot-source' \
  -H 'Content-Type: application/json' \
  -d '{
        "kernel_image_path": "vmlinux.bin",
        "boot_args":   "console=ttyS0 reboot=k panic=1 pci=off"
      }'

# Configure rootfs
curl --unix-socket $API_SOCKET -i \
  -X PUT 'http://localhost/drives/rootfs' \
  -H 'Content-Type: application/json' \
  -d '{
        "drive_id":       "rootfs",
        "path_on_host":   "rootfs.ext4",
        "is_root_device": true,
        "is_read_only":   false
      }'

# (Optional) set machine config if you want custom vCPU/RAM:
curl --unix-socket $API_SOCKET -i \
  -X PUT 'http://localhost/machine-config' \
  -H 'Content-Type: application/json' \
  -d '{
        "vcpu_count": 1,
        "mem_size_mib": 128
      }'

# Start the VM
curl --unix-socket $API_SOCKET -i \
  -X PUT 'http://localhost/actions' \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"InstanceStart"}'
```

Please refer to the Firecracker getting started guide
[(link here)](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
for a more in-depth look at how to do this.

## 3. Optimize

After running your desired workloads, the resulting `.profraw` files can be seen
with:

```
ls /tmp/firecracker-profdata/
```

______________________________________________________________________

#### Merging

To merge these files into valid profile data use:

```
./tools/devtool pgo_build merge
```

#### Common Issue: version mismatch

This will look something like: “raw profile format version = 10; expected
version = 9”

This is common and might even happen on an ideal environment due to the Rust
toolchain producing v10 profile but Ubuntu 24.04 packages not shipping an
llvm-profdata that works for v10. You may be able to install the matching LLVM
on your host, but if it gives you trouble, using Rust's nightly toolchain can
also work.

To use nightly, try:

```
rustup toolchain install nightly
rustup component add llvm-tools-preview --toolchain nightly

export PATH="$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin:$PATH"
```

______________________________________________________________________

#### Optimized Build

Once the `.profraw` files are merged into `.profdata`, you can re-build with the
merged profile:

```
./tools/devtool pgo_build optimize
```

Then, you can verify your optimized binary is in
`build/cargo_target/release/firecracker` and run it with

```
./build/cargo_target/release/firecracker --api-sock /tmp/fc.socket
```

### 4. Verify/Benchmark

Once you have this PGO build, you can run any of the repository's existing
performance tests to observe the speed-ups.

### Community Benchmark Results

Please feel free to fork this repo, run your own benchmarks, and submit a PR
updating the table below.

| Machine (CPU/RAM)             | Firecracker (non-PGO) | Firecracker (PGO) | Δ (PGO vs. baseline) | Notes                                        |
| ----------------------------- | --------------------: | ----------------: | -------------------: | -------------------------------------------- |
| AMD Ryzen 7 7700X; 32 GiB RAM |               0.01275 |           0.01079 |              -15.37% | Ubuntu 24.04; used test_boottime.py for both |
|                               |                       |                   |                      |                                              |
|                               |                       |                   |                      |                                              |
