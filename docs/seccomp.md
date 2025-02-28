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

To minimise the overhead of succesive builds, the compiled filter file is cached
in the build folder and is only recompiled if modified.

You can find the default seccomp filters under `resources/seccomp`.

For a certain release, the default JSON filters used to build Firecracker are
also included in the respective release archive, viewable on the
[releases page](https://github.com/firecracker-microvm/firecracker/releases).

## Custom filters (advanced users only)

**Note 1**: This feature overrides the default filters and can be dangerous.
Filter misconfiguration can result in abruptly terminating the process or
disabling the seccomp security boundary altogether. We recommend using the
default filters instead.

**Note 2**: The user is fully responsible for managing the filter files. We
recommend using integrity checks whenever transferring/downloading files, for
example checksums, as well as for the Firecracker binary or other artifacts, in
order to mitigate potential man-in-the-middle attacks.

Firecracker exposes a way for advanced users to override the default filters
with fully customisable alternatives, leveraging the same JSON/seccompiler
tooling, at startup time.

Via Firecracker's optional `--seccomp-filter` parameter, one can supply the path
to a custom filter file compiled with seccompiler-bin.

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
