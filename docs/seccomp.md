# Seccomp in Firecracker

Seccomp filters are used by default to limit the host system calls Firecracker
can use. The default filters only allow the bare minimum set of system calls and
parameters that Firecracker needs in order to function correctly.

The filters are loaded in the Firecracker process, on a per-thread basis, as
follows:

- VMM (main) - right before executing guest code on the VCPU threads;
- API - right before launching the HTTP server;
- VCPUs - right before executing guest code.

> [!WARNING]
>
> On debug binaries and experimental GNU targets, there are no default seccomp
> filters installed, since they are not intended for production use.

Firecracker uses JSON files for expressing the filter rules and relies on the
[seccompiler](seccompiler.md) tool for all the seccomp functionality.

## Default filters (recommended)

At build time, the default target-specific JSON file is compiled into the
serialized binary file, using seccompiler-bin, and gets embedded in the
Firecracker binary.

This process is performed automatically, when building the executable.

To minimise the overhead of successive builds, the compiled filter file is
cached in the build folder and is only recompiled if modified.

You can find the default seccomp filters under `resources/seccomp`.

For a certain release, the default JSON filters used to build Firecracker are
also included in the respective release archive, viewable on the
[releases page](https://github.com/firecracker-microvm/firecracker/releases).

### Feature-tagged rules

Not every rule in the default filters is needed by every microVM: the ioctls a
virtio-net device issues are useless, and therefore an unnecessary attack
surface, for a microVM without network interfaces. Rules in the JSON files can
therefore be tagged with the microVM *feature* they are needed for, for example
`"feature": "net"`. seccompiler compiles tagged rules into separate BPF
fragments, and Firecracker only installs the fragments of the features the
microVM in front of it actually uses. For the vmm and vcpu threads the decision
is taken right before their filters are installed, once the microVM is built and
its device configuration is known (see above). The API thread starts before any
configuration exists, so its filter is composed from `api` and the features
`--seccomp-features` adds only; rules of the api thread should therefore be
untagged or tagged `api`. The features are:

| Feature          | Enabled when                                                                                                                                             |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `api`            | the API is enabled (pausing and snapshotting a microVM is only possible through the API), or a gdb socket is configured in builds with the `gdb` feature |
| `pci`            | `--enable-pci` is used (or the restored snapshot uses the PCI transport)                                                                                 |
| `hotplug`        | the API is enabled and the PCI transport is used, i.e. devices can be hot-plugged                                                                        |
| `block`          | a virtio-block device is configured                                                                                                                      |
| `async-io`       | a virtio-block device uses the `Async` io engine                                                                                                         |
| `net`            | a virtio-net device is configured                                                                                                                        |
| `vsock`          | a vsock device is configured                                                                                                                             |
| `pmem`           | a virtio-pmem device is configured                                                                                                                       |
| `memory-hotplug` | virtio-mem memory hotplug is configured                                                                                                                  |

Untagged rules are always installed. The features derived from the configuration
are logged at `INFO` level when the microVM is built, e.g.
`Seccomp features required by the microVM: [api,block,net]`, followed by
`Seccomp features added by the command line: [...]` when `--seccomp-features` is
used, and the filter each thread gets is logged when it is composed, e.g.
`Seccomp filter of the vmm thread: 211 instructions, features [api,block,net]`.

> [!NOTE]
>
> When devices can be hot-plugged (`--enable-pci` together with the API), the
> device set is not final when the filters are installed, so the rules of every
> hot-pluggable device type (`block`, `async-io`, `net`, `pmem`) are kept along
> with `hotplug`. Without PCI or with `--no-api`, no device can be added after
> boot and only the configured device types are allowed.

The optional `--seccomp-features` parameter enables additional features on top
of the derived ones, for every thread. It takes `all` or a comma-separated list
of feature names, e.g. `--seccomp-features net,block`. Use it when a custom
filter tags rules in a way the derivation does not cover, or to rule out the
feature derivation while investigating a seccomp violation (which Firecracker
reports as `Shutting down VM after intercepting a bad syscall`, together with
the `seccomp.num_faults` metric).

## Custom filters (advanced users only)

> [!NOTE]
>
> This feature overrides the default filters and can be dangerous. Filter
> misconfiguration can result in abruptly terminating the process or disabling
> the seccomp security boundary altogether. We recommend using the default
> filters instead.

> [!NOTE]
>
> The user is fully responsible for managing the filter files. We recommend
> using integrity checks whenever transferring/downloading files, for example
> checksums, as well as for the Firecracker binary or other artifacts, in order
> to mitigate potential man-in-the-middle attacks.

Firecracker exposes a way for advanced users to override the default filters
with fully customisable alternatives, leveraging the same JSON/seccompiler
tooling, at startup time.

Via Firecracker's optional `--seccomp-filter` parameter, one can supply the path
to a custom filter file compiled with seccompiler-bin. Rules tagged with
features in a custom filter are composed exactly like the default ones, so a tag
must be one of the feature names listed above; Firecracker refuses to start with
a filter tagged with a name it does not know.

Potential use cases:

- Users of experimentally-supported targets (like GNU libc builds) may be able
  to use this feature to implement seccomp filters without needing to have a
  custom build of Firecracker.
- Users of debug binaries who need to use a seccomp filter for any reason will
  be able to use this feature to implement seccomp filters without needing to
  have a custom build of Firecracker. Note: there may be some differences in
  syscalls between `debug` and `release` builds. A non-comprehensive list is:
  - `fcntl(F_GETFD)` is used by debug assertions to verify a dropped `fd` is
    valid.
- Faced with a _theoretical_ production issue, due to a syscall that was issued
  by the Firecracker process, but not allowed by the seccomp policy, one may use
  a custom filter in order to quickly mitigate the issue. This can speed up the
  resolution time, by not needing to build and deploy a new Firecracker binary.
  However, as the note above states, this needs to be thoroughly tested and
  should not be a long-term solution.

## Disabling seccomp (not recommended)

Firecracker also has support for a `--no-seccomp` parameter, which disables all
seccomp filtering. It can be helpful when quickly prototyping changes in
Firecracker that use new system calls.

Do **not** use in production.
