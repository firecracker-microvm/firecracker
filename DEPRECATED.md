# Deprecated Features

The following functionality of Firecracker is deprecated, and will be removed in
a future major Firecracker release, in accordance with our
[release policy](docs/RELEASE_POLICY.md).

- \[[#2763](https://github.com/firecracker-microvm/firecracker/pull/2763)\] The
  `vsock_id` body field in `PUT` requests on `/vsock`
- \[[#2980](https://github.com/firecracker-microvm/firecracker/pull/2980)\] The
  `mem_file_path` body field in `PUT` requests on `/snapshot/load`
- \[[#2973](https://github.com/firecracker-microvm/firecracker/pull/2973)\]
  MicroVM Metadata Service v1 (MMDSv1)
- \[[#4126](https://github.com/firecracker-microvm/firecracker/pull/4126)\]
  Static CPU templates
- \[[#4209](https://github.com/firecracker-microvm/firecracker/pull/4209)\] The
  `rebase-snap` tool
- \[[#4500](https://github.com/firecracker-microvm/firecracker/pull/4500)\] The
  `--start-time-cpu-us` and `--start-time-us` CLI arguments
- \[[#4428](https://github.com/firecracker-microvm/firecracker/pull/4428)\]
  Booting microVMs using MPTable and command line parameters for VirtIO devices.
  The functionality is substituted with ACPI.
- \[[#2628](https://github.com/firecracker-microvm/firecracker/pull/2628)\] The
  `--basic` parameter of `seccompiler-bin`.
