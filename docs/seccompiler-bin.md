# Seccompiler-bin - overview and user guide

## Overview

Seccompiler-bin is a tool that compiles seccomp filters expressed as JSON files
into serialized, binary BPF code that can be directly consumed by Firecracker,
at launch time.

The seccompiler-bin executable in Firecracker uses the
[seccompiler library from rust-vmm](https://github.com/rust-vmm/seccompiler),
with the added functionality of serializing the compiled BPF filters into a
binary file using `bincode`.

## Usage

### Seccompiler-bin

To view the seccompiler-bin command line arguments, pass the `--help` parameter
to the executable.

Example usage:

```bash
./seccompiler-bin
    --target-arch "x86_64"  # The CPU arch where the BPF program will run.
                            # Supported architectures: x86_64, aarch64.
    --input-file "x86_64_musl.json" # File path of the JSON input.
    --output-file "bpf_x86_64_musl" # Optional path of the output file.
                                    # [default: "seccomp_binary_filter.out"]
```

## Where is seccompiler-bin implemented?

Seccompiler-bin is implemented as another package in the Firecracker cargo
workspace. The code is located at `firecracker/src/seccompiler-bin/src`.

## Supported platforms

Seccompiler-bin is supported on the
[same platforms as Firecracker](../README.md#supported-platforms).

## Release policy

Seccompiler-bin follows Firecracker's [release policy](RELEASE_POLICY.md) and
version (it's released at the same time, with the same version number and
adheres to the same support window).

## JSON file format

A JSON file expresses the seccomp policy for the entire Firecracker process. It
contains multiple filters, one per each thread category and is specific to just
one target platform.

This means that Firecracker has a JSON file for each supported target
(currently determined by the arch-libc combinations). You can view them in
`resources/seccomp`.

For an overview of the JSON file format, view the
[seccompiler docs from rust-vmm][1]

[1]: https://github.com/rust-vmm/seccompiler/blob/main/docs/json_format.md
