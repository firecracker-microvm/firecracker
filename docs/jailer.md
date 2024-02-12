# The Firecracker Jailer

## Disclaimer

The jailer is a program designed to isolate the Firecracker process in order to
enhance Firecracker's security posture. It is meant to address the security
needs of Firecracker only and is not intended to work with other binaries.
Additionally, each jailer binary should be used with a statically linked
Firecracker binary (with the default musl toolchain) of the same version.
Experimental gnu builds are not supported.

## Jailer Usage

The jailer is invoked in this manner:

```bash
jailer --id <id> \
       --exec-file <exec_file> \
       --uid <uid> \
       --gid <gid>
       [--parent-cgroup <relative_path>]
       [--cgroup-version <cgroup-version>]
       [--cgroup <cgroup>]
       [--chroot-base-dir <chroot_base>]
       [--netns <netns>]
       [--resource-limit <resource=value>]
       [--daemonize]
       [--new-pid-ns]
       [--...extra arguments for Firecracker]
```

- `id` is the unique VM identification string, which may contain alphanumeric
  characters and hyphens. The maximum `id` length is currently 64 characters.
- `exec_file` is the path to the Firecracker binary that will be exec-ed by the
  jailer. The filename must include the string `firecracker`. This is enforced
  because the interaction with the jailer is Firecracker specific.
- `uid` and `gid` are the uid and gid the jailer switches to as it execs the
  target binary.
- `parent-cgroup` is used to allow the placement of microvm cgroups in custom
  nested hierarchies. By specifying this parameter, the jailer will create a new
  cgroup named `id` for the microvm in the `<cgroup_base>/<parent_cgroup>`
  subfolder. `cgroup_base` is the cgroup controller root for `cgroup v1` (e.g.
  `/sys/fs/cgroup/cpu`) or the unified controller hierarchy for `cgroup v2` (
  e.g. `/sys/fs/cgroup/unified`. `<parent_cgroup>` is a relative path within
  that hierarchy. For example, if `--parent-cgroup all_uvms/external_uvms` is
  specified, the jailer will write all cgroup parameters specified through
  `--cgroup` in `/sys/fs/cgroup/<controller_name>/all_uvms/external_uvms/<id>`.
  By default, the parent cgroup is `exec-file`. If there are no `--cgroup`
  parameters specified and `--group-version=2` was passed, then the jailer will
  move the process to the specified cgroup.
- `cgroup-version` is used to select which type of cgroup hierarchy to use for
  the creation of cgroups. The default value is "1" which means that cgroups
  specified with the `cgroup` argument will be created within a v1 hierarchy.
  Supported options are "1" for cgroup-v1 and "2" for cgroup-v2.
- `cgroup` cgroups can be passed to the jailer to let it set the values when the
  microVM process is spawned. The `--cgroup` argument must follow this format:
  `<cgroup_file>=<value>` (e.g `cpuset.cpus=0`). This argument can be used
  multiple times to set multiple cgroups. This is useful to avoid providing
  privileged permissions to another process for setting the cgroups before or
  after the jailer is executed. The `--cgroup` flag can help as well to set
  Firecracker process cgroups before the VM starts running, with no need to
  create the entire cgroup hierarchy manually (which requires privileged
  permissions).
- `chroot_base` represents the base folder where chroot jails are built. The
  default is `/srv/jailer`.
- `netns` represents the path to a network namespace handle. If present, the
  jailer will use this to join the associated network namespace.
- For extra security and control over resource usage, `resource-limit` can be
  used to set bounds to the process resources. The `--resource-limit` argument
  must follow this format: `<resource>=<value>` (e.g `no-file=1024`) and can be
  used multiple times to set multiple bounds. Current available resources that
  can be limited using this argument are:
  - `fsize`: The maximum size in bytes for files created by the process.
  - `no-file`: Specifies a value one greater than the maximum file descriptor
    number that can be opened by this process.

Here is an example on how to set multiple resource limits using this argument:

```bash
--resource-limit fsize=250000000 --resource-limit no-file=1024
```

- When present, the `--daemonize` flag causes the jailer to call `setsid()` and
  redirect all three standard I/O file descriptors to `/dev/null`.
- When present, the `--new-pid-ns` flag causes the jailer to spawn the provided
  binary into a new PID namespace. It makes use of the libc `clone()` function
  with the `CLONE_NEWPID` flag. As a result, the jailer and the process running
  the exec file have different PIDs. The PID of the child process is stored in
  the jail root directory inside `<exec_file_name>.pid`.
- The jailer adheres to the "end of command options" convention, meaning all
  parameters specified after `--` are forwarded to Firecracker. For example,
  this can be paired with the `--config-file` Firecracker argument to specify a
  configuration file when starting Firecracker via the jailer (the file path and
  the resources referenced within must be valid relative to a jailed
  Firecracker). Please note the jailer already passes `--id` parameter to the
  Firecracker process.

## Jailer Operation

After starting, the Jailer goes through the following operations:

- Validate **all provided paths** and the VM `id`.
- Close all open file descriptors based on `/proc/<jailer-pid>/fd` except input,
  output and error.
- Cleanup all environment variables received from the parent process.
- Create the `<chroot_base>/<exec_file_name>/<id>/root` folder, which will be
  henceforth referred to as `chroot_dir`. `exec_file_name` is the last path
  component of `exec_file` (for example, that would be `firecracker` for
  `/usr/bin/firecracker`). Nothing is done if the path already exists (it should
  not, since `id` is supposed to be unique).
- Copy `exec_file` to
  `<chroot_base>/<exec_file_name>/<id>/root/<exec_file_name>`. This ensures the
  new process will not share memory with any other Firecracker process.
- Set resource bounds for current process and its children through
  `--resource-limit` argument, by calling `setrlimit()` system call with the
  specific resource argument. If no limits are provided, the jailer bounds
  `no-file` to a maximum default value of 2048.
- Create the `cgroup` sub-folders. The jailer can use either `cgroup v1` or
  `cgroup v2`. On most systems, this is mounted by default in `/sys/fs/cgroup`
  (should be mounted by the user otherwise). The jailer will parse
  `/proc/mounts` to detect where each of the controllers required in `--cgroup`
  can be found (multiple controllers may share the same path). For each
  identified location (referred to as `<cgroup_base>`), the jailer creates the
  `<cgroup_base>/<parent_cgroup>/<id>` subfolder, and writes the current pid to
  `<cgroup_base>/<parent_cgroup>/<id>/tasks`. Also, the value passed for each
  `<cgroup_file>` is written to the file. If `--node` is used the corresponding
  values are written to the appropriate `cpuset.mems` and `cpuset.cpus` files.
- Call `unshare()` into a new mount namespace, use `pivot_root()` to switch the
  old system root mount point with a new one base in `chroot_dir`, switch the
  current working directory to the new root, unmount the old root mount point,
  and call `chroot` into the current directory.
- Use `mknod` to create a `/dev/net/tun` equivalent inside the jail.
- Use `mknod` to create a `/dev/kvm` equivalent inside the jail.
- Use `chown` to change ownership of the `chroot_dir` (root path `/` as seen by
  the jailed firecracker), `/dev/net/tun`, `/dev/kvm`. The ownership is changed
  to the provided `uid:gid`.
- If `--netns <netns>` is present, attempt to join the specified network
  namespace.
- If `--daemonize` is specified, call `setsid()` and redirect `STDIN`, `STDOUT`,
  and `STDERR` to `/dev/null`.
- If `--new-pid-ns` is specified, call `clone()` with `CLONE_NEWPID` flag to
  spawn a new process within a new PID namespace. The new process will assume
  the role of init(1) in the new namespace. The parent will store child's PID
  inside `<exec_file_name>.pid`, while the child drops privileges and `exec()`s
  into the `<exec_file_name>`, as described below.
- Drop privileges via setting the provided `uid` and `gid`.
- Exec into
  `<exec_file_name> --id=<id> --start-time-us=<opaque> --start-time-cpu-us=<opaque>`
  (and also forward any extra arguments provided to the jailer after `--`, as
  mentioned in the **Jailer Usage** section), where:
  - `id`: (`string`) - The `id` argument provided to jailer.
  - `opaque`: (`number`) time calculated by the jailer that it spent doing its
    work.

## Example Run and Notes

Let’s assume Firecracker is available as `/usr/bin/firecracker`, and the jailer
can be found at `/usr/bin/jailer`. We pick the **unique id
551e7604-e35c-42b3-b825-416853441234**, and we choose to run on **NUMA node 0**
(in order to isolate the process in the 0th NUMA node we need to set
`cpuset.mems=0` and `cpuset.cpus` equals to the CPUs of that NUMA node), using
**uid 123**, and **gid 100**. For this example, we are content with the default
`/srv/jailer` chroot base dir.

We start by running:

```bash
/usr/bin/jailer --id 551e7604-e35c-42b3-b825-416853441234
--cgroup cpuset.mems=0 --cgroup cpuset.cpus=$(cat /sys/devices/system/node/node0/cpulist)
--exec-file /usr/bin/firecracker --uid 123 --gid 100 \
--netns /var/run/netns/my_netns --daemonize
```

After opening the file descriptors mentioned in the previous section, the jailer
will create the following resources (and all their prerequisites, such as the
path which contains them):

- `/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root/firecracker`
  (copied from `/usr/bin/firecracker`)

We are going to refer to
`/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root` as
`<chroot_dir>`.

Let’s also assume the, **cpuset** cgroups are mounted at
`/sys/fs/cgroup/cpuset`. The jailer will create the following subfolder (which
will inherit settings from the parent cgroup):

- `/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234`

It’s worth noting that, whenever a folder already exists, nothing will be done,
and we move on to the next directory that needs to be created. This should only
happen for the common `firecracker` subfolder (but, as for creating the chroot
path before, we do not issue an error if folders directly associated with the
supposedly unique `id` already exist).

The jailer then writes the current pid to
`/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234/tasks`,
It also writes `0` to
`/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234/cpuset.mems`,
And the corresponding CPUs to
`/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234/cpuset.cpus`.

Since the `--netns` parameter is specified in our example, the jailer opens
`/var/run/netns/my_netns` to get a file descriptor `fd`, uses
`setns(fd, CLONE_NEWNET)` to join the associated network namespace, and then
closes `fd`.

The `--daemonize` flag is also present, so the jailers opens `/dev/null` as
**RW** and keeps the associate file descriptor as `dev_null_fd` (we do this
before going inside the jail), to be used later.

Build the chroot jail. First, the jailer uses `unshare()` to enter a new mount
namespace, and changes the propagation of all mount points in the new namespace
to private using `mount(NULL, “/”, NULL, MS_PRIVATE | MS_REC, NULL)`, as a
prerequisite to `pivot_root()`. Another required operation is to bind mount
`<chroot_dir>` on top of itself using
`mount(<chroot_dir>, <chroot_dir>, NULL, MS_BIND, NULL)`. At this point, the
jailer creates the folder `<chroot_dir>/old_root`, changes the current directory
to `<chroot_dir>`, and calls `syscall(SYS_pivot_root, “.”, “old_root”)`. The
final steps of building the jail are unmounting `old_root` using
`umount2(“old_root”, MNT_DETACH)`, deleting `old_root` with `rmdir`, and finally
calling `chroot(“.”)` for good measure. From now, the process is jailed in
`<chroot_dir>`.

Create the special file `/dev/net/tun`, using
`mknod(“/dev/net/tun”, S_IFCHR | S_IRUSR | S_IWUSR, makedev(10, 200))`, and then
call `chown(“/dev/net/tun”, 123, 100)`, so Firecracker can use it after dropping
privileges. This is required to use multiple TAP interfaces when running jailed.
Do the same for `/dev/kvm`.

Change ownership of `<chroot_dir>` to `uid:gid` so that Firecracker can create
its API socket there.

Since the `--daemonize` flag is present, call `setsid()` to join a new session,
a new process group, and to detach from the controlling terminal. Then, redirect
standard file descriptors to `/dev/null` by calling `dup2(dev_null_fd, STDIN)`,
`dup2(dev_null_fd, STDOUT)`, and `dup2(dev_null_fd, STDERR)`. Close
`dev_null_fd`, because it is no longer necessary.

Finally, the jailer switches the `uid` to `123`, and `gid` to `100`, and execs

```console
./firecracker \
  --id="551e7604-e35c-42b3-b825-416853441234" \
  --start-time-us=<opaque> \
  --start-time-cpu-us=<opaque>
```

Now firecracker creates the socket at
`/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root/<api-sock>`
to interact with the VM.

Note: default value for `<api-sock>` is `/run/firecracker.socket`.

### Observations

- The user must create hard links for (or copy) any resources which will be
  provided to the VM via the API (disk images, kernel images, named pipes, etc)
  inside the jailed root folder. Also, permissions must be properly managed for
  these resources; for example the user which Firecracker runs as must have both
  **read and write permissions** to the backing file for a RW block device.
- By default the VMs are not asigned to any NUMA node or pinned to any CPU. The
  user must manage any fine tuning of resource partitioning via cgroups, by
  using the `--cgroup` command line argument.
- It’s up to the user to handle cleanup after running the jailer. One way to do
  this involves registering handlers with the cgroup `notify_on_release`
  mechanism, while being wary about potential race conditions (the instance
  crashing before the subscription process is complete, for example).
- For extra resilience, the `--new-pid-ns` flag enables the Jailer to exec the
  binary file in a new PID namespace, in order to become a pseudo-init process.
  Alternatively, the user can spawn the jailer in a new PID namespace via a
  combination of `clone()` with the `CLONE_NEWPID` flag and `exec()`.
- We run the jailer as the `root` user; it actually requires a more restricted
  set of capabilities, but that's to be determined as features stabilize.
- The jailer can only log messages to stdout/err for now, which is why the logic
  associated with `--daemonize` runs towards the end, instead of the very
  beginning. We are working on adding better logging capabilities.

### Known limitations

- When passing the --daemonize option to Firecracker without the --new-ns-pid
  option, the Firecracker process will have a different PID than the Jailer
  process and killing the Jailer will not kill the Firecracker process. As a
  workaround to get Firecracker PID, the Jailer stores the PID of the child
  process in the jail root directory inside `<exec_file_name>.pid` for all cases
  regardless of whether `--new-pid-ns` was provided. The suggested way to fetch
  Firecracker's PID when using the Jailer is to read the `firecracker.pid` file
  present in the Jailer's root directory.

## Caveats

- If all the cgroup controllers are bunched up on a single mount point using the
  "all" option, our current program logic will complain it cannot detect
  individual controller mount points.
