# Seccompiler - overview and user guide

## Overview

Seccompiler is a tool that compiles seccomp filters expressed as JSON files
into serialized, binary BPF code that is directly consumed by Firecracker,
at build or launch time.

Seccompiler defines a custom [JSON file structure](#json-file-format), detailed
further below, that the filters must adhere to.

Besides the compiler binary, seccompiler also exports a small library
interface, with a couple of helper functions, for deserializing and installing
the binary filters.

## Usage

### Seccompiler binary

To view the seccompiler command line arguments, pass the `--help` parameter to
the executable.

Example usage:

```bash
./seccompiler
    --target-arch "x86_64"  # The CPU arch where the BPF program will run.
                            # Supported architectures: x86_64, aarch64.
    --input-file "x86_64_musl.json" # File path of the JSON input.
    --output-file "bpf_x86_64_musl" # Optional path of the output file.
                                    # [default: "seccomp_binary_filter.out"]
    --basic # Optional, creates basic filters, discarding rule-level actions
            # and any parameter checks. Not recommended.
```

### Seccompiler library

To view the library documentation, navigate to the seccompiler source code, in
`firecracker/src/seccompiler/src` and run `cargo doc --lib --open`.

## Where is seccompiler implemented?

Seccompiler is implemented as another package in the Firecracker cargo
workspace. The code is located at `firecracker/src/seccompiler/src`.

## Supported platforms

Seccompiler is supported on the
[same platforms as Firecracker](../README.md#supported-platforms).

## Release policy

Seccompiler follows Firecracker's [release policy](RELEASE_POLICY.md) and
version (it's released at the same time, with the same version number and
adheres to the same support window).

## JSON file format

A JSON file expresses the seccomp policy for the entire Firecracker process. It
contains multiple filters, one per each thread category and is specific to just
one target platform.

This means that Firecracker has a JSON file for each supported target
(currently determined by the arch-libc combinations). You can view them in
`resources/seccomp`.

At the top level, the file requires an object that maps thread categories
(vmm, api and vcpu) to seccomp filters:

```
{
    "vmm": {
       "default_action": {
            "errno" : -1
       },
       "filter_action": "allow",
       "filter": [...]
    },
    "api": {...},
    "vcpu": {...},
}
```

The associated filter is a JSON object containing the `default_action`,
`filter_action` and `filter`.

The `default_action` represents the action we have to execute if none of the
rules in `filter` matches, and `filter_action` is what gets executed if a rule
in the filter matches
(e.g: `"Allow"` in the case of implementing an allowlist).

An **action** is the JSON representation of the following enum:

```rust
pub enum SeccompAction {
    Allow, // Allows syscall.
    Errno(u32), // Returns from syscall with specified error number.
    Kill, // Kills calling process.
    Log, // Same as allow but logs call.
    Trace(u32), // Notifies tracing process of the caller with respective number.
    Trap, // Sends `SIGSYS` to the calling process.
}
```

The `filter` property specifies the set of rules that would trigger a match.
This is an array containing multiple **or-bound SyscallRule** **objects**
(if one of them matches, the corresponding action gets triggered).

The **SyscallRule** object is used for adding a rule to a syscall.
It has an optional `args` property that is used to specify a vector of
and-bound conditions that the syscall arguments must satisfy in order for the
rule to match.

In the absence of the `args` property, the corresponding action will get
triggered by any call that matches that name, irrespective of the argument
values.

Here is the structure of the object:

```
{
    "syscall": "accept4", // mandatory, the syscall name
    "action": "allow", // optional, overrides the filter_action if present
    "comment": "Used by vsock & api thread", // optional, for adding meaningful comments
    "args": [...] // optional, vector of and-bound conditions for the parameters
}
```

Note that the file format expects syscall names, not arch-specific numbers, for
increased usability. This is not true, however for the syscall arguments, which
are expected as base-10 integers.

In order to allow a syscall with multiple alternatives for the same parameters,
you can write multiple syscall rule objects at the filter-level, each with its
own rules.

Note that, when passing the `--basic` flag to seccompiler, all `action` and
`args` fields of the `SeccompRule`s are ignored.

A **condition object** is made up of the following mandatory properties:

- `arg_index` (0-based index of the syscall argument we want to check)
- `arg_type` (`dword` or `qword`, which specifies the argument size - 4 or 8
    bytes respectively)
- `op`, which is one of `eq, ge, gt, ge, lt, masked_eq, ne` (the operator used
    for comparing the parameter to `val`)
- `val` is the integer value being checked against

As mentioned eariler, we don’t support any named parameters, but only numeric
constants in the JSON file. You may however add an optional `comment` property
to each condition object. This way, you can provide meaning to each numeric
value, much like when using named parameters, like so:

```
{
    "syscall": "accept4",
    "args": [
        {
            "arg_index": 3,
            "arg_type": "dword",
            "op": "eq",
            "val": 1,
            "comment": "libc::AF_UNIX"
        }
    ]
}
```

To see example filters, look over Firecracker's JSON filters in
`resources/seccomp`.
