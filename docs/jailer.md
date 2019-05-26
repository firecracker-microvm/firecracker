# The Firecracker Jailer

## Jailer Usage

The jailer is invoked in this manner:

``` bash
jailer --id <id> \
       --node <numa_node>\
       --exec-file <exec_file> \
       --uid <uid> \
       --gid <gid>
       [--chroot-base-dir <chroot_base>]
       [--netns <netns>]
       [--daemonize]
       [--seccomp-level <level>]
```

- `id` is the unique VM identification string, which may contain alphanumeric
  characters and hyphens. The maximum `id` length is currently 64 characters.
- `numa_node` represents the NUMA node the process gets assigned to. More
  details are available below.
- `exec_file` is the path to the Firecracker binary that will be exec-ed by the
  jailer. The user can provide a path to any binary, but the interaction with
  the jailer is mostly Firecracker specific.
- `uid` and `gid` are the uid and gid the jailer switches to as it execs the
  target binary.
- `chroot_base` represents the base folder where chroot jails are built. The
  default is `/srv/jailer`.
- `netns` represents the path to a network namespace handle. If present, the
  jailer will use this to join the associated network namespace.
- When present, the `--daemonize` flag causes the jailer to cal `setsid()` and
  redirect all three standard I/O file descriptors to `/dev/null`.
- `--seccomp-level` specifies whether seccomp filters should be installed and
  how restrictive they should be. Possible values are:
  - 0 : disabled.
  - 1 : basic filtering. This prohibits syscalls not whitelisted by
    Firecracker.
  - 2 (default): advanced filtering. This adds further checks on some of the
    parameters of the allowed syscalls.

## Jailer Operation

After starting, the Jailer goes through the following operations:

- Validate **all provided paths** and the VM `id`.
- Close all open file descriptors based on `/proc/<jailer-pid>/fd` except
  input, output and error.
- Create the `<chroot_base>/<exec_file_name>/<id>/root` folder, which will be
  henceforth referred to as `chroot_dir`. `exec_file_name` is the
  last path component of `exec_file` (for example, that would be `firecracker`
  for `/usr/bin/firecracker`). Nothing is done if the path already
  exists (it should not, since `id` is supposed to be unique).
- Copy `exec_file` to
  `<chroot_base>/<exec_file_name>/<id>/root/<exec_file_name>`.
- Create the `cgroup` sub-folders. At the moment, the jailer uses three
  `cgroup v1` controllers: `cpu`, `cpuset`, and `pids`. On most systems, these
  (along with others) are mounted by default somewhere in `/sys/fs/cgroup`
  (they should be mounted by the user otherwise). The jailer will parse
  `/proc/mounts` to detect where each of the three controllers can be found
  (multiple controllers may share the same path). For each identified location
  (referred to as `<cgroup_base>`), the jailer creates the
  `<cgroup_base>/<exec_file_name>/<id>` subfolder, and writes the current pid
  to `<cgroup_base>/<exec_file_name>/<id>/tasks`. Also, the value of
  `numa_node` is written to the appropriate `cpuset.mems` file.
- Call `unshare()` into a new mount namespace, use `pivot_root()` to switch
  the old system root mount point with a new one base in `chroot_dir`, switch
  the current working directory to the new root, unmount the old root mount
  point, and call `chroot` into the current directory.
- Use `mknod` to create a `/dev/net/tun` equivalent inside the jail.
- Use `mknod` to create a `/dev/kvm` equivalent inside the jail.
- Use `chown` to change ownership of the `chroot_dir` (root path `/` as seen
  by the jailed firecracker), `/dev/net/tun`, `/dev/kvm`. The ownership is
  changed to the provided `uid:gid`.
- If `--netns <netns>` is present, attempt to join the specified network
  namespace.
- If `--daemonize` is specified, call `setsid()` and redirect `STDIN`,
  `STDOUT`, and `STDERR` to `/dev/null`.
- Drop privileges via setting the provided `uid` and `gid`.
- Exec into `<exec_file_name> --id=<id> --api-sock=/api.socket
  --seccomp-level=<level> --start-time-us=<opaque>
  --start-time-cpu-us=<opaque>`.
  Where:
  - `id`: (`string`) - The `id` argument provided to jailer.
  - `level`: (`number`) - the `--seccomp-level` argument provided to jailer.
  - `opaque`: (`number`) time calculated by the jailer that it spent doing
     its work.

## Example Run and Notes

Let’s assume Firecracker is available as `/usr/bin/firecracker`, and the jailer
can be found at `/usr/bin/jailer`. We pick the **unique id
551e7604-e35c-42b3-b825-416853441234**, and we choose to run on **NUMA node
0**, using **uid 123**, and **gid 100**. For this example, we are content with
the default `/srv/jailer` chroot base dir.

We start by running:

``` bash
/usr/bin/jailer --id 551e7604-e35c-42b3-b825-416853441234 --node 0 \
--exec-file /usr/bin/firecracker --uid 123 --gid 100 \
--netns /var/run/netns/my_netns --daemonize
```

After opening the file descriptors mentioned in the previous section, the
jailer will create the following resources (and all their prerequisites, such
as the path which contains them):

- `/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root/firecracker`
  (copied from `/usr/bin/firecracker`)

Firecracker will create its API socket at
`/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root/api.socket`

We are going to refer to
`/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root`
as `<chroot_dir>`.

Let’s also assume the **cpu**, **cpuset**, and **pids** cgroups are mounted at
`/sys/fs/cgroup/cpu`, `/sys/fs/cgroup/cpuset`, and `/sys/fs/cgroup/pids`,
respectively. The jailer will create the following subfolders (which will
inherit settings from the parent cgroup):

- `/sys/fs/cgroup/cpu/firecracker/551e7604-e35c-42b3-b825-416853441234`
- `/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234`
- `/sys/fs/cgroup/pids/firecracker/551e7604-e35c-42b3-b825-416853441234`

It’s worth noting that, whenever a folder already exists, nothing will be done,
and we move on to the next directory that needs to be created. This should only
happen for the common `firecracker` subfolder (but, as for creating the chroot
path before, we do not issue an error if folders directly associated with the
supposedly unique `id` already exist).

The jailer then writes the current pid to
`/sys/fs/cgroup/cpu/firecracker/551e7604-e35c-42b3-b825-416853441234/tasks`,
`/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234/tasks`,
and
`/sys/fs/cgroup/pids/firecracker/551e7604-e35c-42b3-b825-416853441234/tasks`.
It also writes `0` to
`/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234/cpuset.mems`.

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
`<chroot_dir>` on top of itself using `mount(<chroot_dir>, <chroot_dir>,
NULL, MS_BIND, NULL)`. At this point, the jailer creates the folder
`<chroot_dir>/old_root`, changes the current directory to `<chroot_dir>`,
and calls `syscall(SYS_pivot_root, “.”, “old_root”)`. The final steps of
building the jail are unmounting `old_root` using `umount2(“old_root”,
MNT_DETACH)`, deleting `old_root` with `rmdir`, and finally calling
`chroot(“.”)` for good measure. From now, the process is jailed in
`<chroot_dir>`.

Create the special file `/dev/net/tun`, using `mknod(“/dev/net/tun”, S_IFCHR |
S_IRUSR | S_IWUSR, makedev(10, 200))`, and then call `chown(“/dev/net/tun”,
123, 100)`, so Firecracker can use it after dropping privileges. This is
required to use multiple TAP interfaces when running jailed. Do the same for
`/dev/kvm`.

Change ownership of `<chroot_dir>` to `uid:gid` so that Firecracker can create
its API socket there.

Since the `--daemonize` flag is present, call `setsid()` to join a new
session, a new process group, and to detach from the controlling terminal.
Then, redirect standard file descriptors to `/dev/null` by calling
`dup2(dev_null_fd, STDIN)`, `dup2(dev_null_fd, STDOUT)`, and `dup2(dev_null_fd,
STDERR)`. Close `dev_null_fd`, because it is no longer necessary.

Finally, the jailer switches the `uid` to `123`, and `gid` to `100`, and execs

```
./firecracker \
  --id="551e7604-e35c-42b3-b825-416853441234" \
  --api-sock=/api.socket \
  --seccomp-level=2 \
  --start-time-us=<opaque> \
  --start-time-cpu-us=<opaque>
```

We can now use the socket at
`/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root/api.socket`
to interact with the VM.

### Observations

- The user must create hard links for (or copy) any resources which will be
  provided to the VM via the API (disk images, kernel images, named pipes, etc)
  inside the jailed root folder. Also, permissions must be properly managed for
  these resources; for example the user which Firecracker runs as must have
  both **read and write permissions** to the backing file for a RW block
  device.
- It’s up to the user to load balance VM placement among multiple NUMA nodes
  (if present), using the ```--node``` command line argument.
- The user must also manage any further fine tuning of resource partitioning
  via cgroups (most likely the ones created by the jailer), or any other means.
- It’s up to the user to handle cleanup after running the jailer. One way to do
  this involves registering handlers with the cgroup `notify_on_release`
  mechanism, while being wary about potential race conditions (the instance
  crashing before the subscription process is complete, for example).
- For extra resilience, the jailer expects to be spawned by the user in a new
  PID namespace, most likely via a combination of `clone()` with the
  `CLONE_NEWPID` flag and `exec()`. A process must be created in a new PID
  namespace in order to become a pseudo-init process, and the other option is
  to use a `clone()` in the jailer, which seems unnecessary.
- When running with `--daemonize`, the jailer will fail to start if it's a
  process group leader, because `setsid()` returns an error in this case.
  Spawning the jailer via `clone()` and `exec()` also ensures it cannot be a
  process group leader.
- We run the jailer as the `root` user; it actually requires a more restricted
  set of capabilities, but that's to be determined as features stabilize.
- The jailer can only log messages to stdout/err for now, which is why the
  logic associated with `--daemonize` runs towards the end, instead of the very
  beginning. We are working on adding better logging capabilities.

## Caveats

- If all the cgroup controllers are bunched up on a single mount point using
  the "all" option, our current program logic will complain it cannot detect
  individual controller mount points.
