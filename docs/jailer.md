# The Firecracker Jailer

## Jailer Usage

The jailer is invoked in this manner:

``` bash
jailer --id <id> --node <numa_node> --exec-file <exec_file> --uid <uid> --gid <gid> [--chroot-base-dir <chroot_base>]
```

- `id` is the unique VM identification string (i.e the UUID) and needs to follow
  one of the three UUID formats (simple, hyphenated or urn). See [RFC4122: A
  Universally Unique ID (UUID) URN Namespace](
  https://tools.ietf.org/html/rfc4122).
- `numa_node` represents the NUMA node the process gets assigned to. More
  details are available below.
- `exec_file` is the path to the Firecracker binary that will be exec-ed by the
  jailer. The user can provide a path to any binary, but the interaction with
  the jailer is mostly Firecracker specific.
- `uid` and `gid` are the uid and gid the jailer switches to as it execs the
  target binary.
- **chroot_base** represents the base folder where chroot jails are built. The
  default is `/srv/jailer`.

## Jailer Operation

After starting, the Jailer goes through the following operations:

- If the `USE_SECCOMP` environment variable is set, sets up a list of seccomp
  filters, white listing the minimum set of system calls that Firecracker
  requires to function.
- Validate **all provided paths** and the VM `id`.
- Open `/dev/kvm` as *RW*, `/dev/net/tun` as *RW non-blocking*, and bind a Unix
  domain socket listener to `<chroot_base>/<exec_file_name>/<id>/api.socket`.
  `exec_file_name` is the last path component of `exec_file` (for example, that
  would be `firecracker` for `/usr/bin/firecracker`). All three file descriptors
  remain open across exec-ing into the target binary, which would be otherwise
  unable to open/create the associated files.
- Create the `<chroot_base>/<exec_file_name>/<id>/root` folder, which will be
  henceforth referred to as **chroot_dir**. Nothing is done if the path already
  exists (it should not, since **id** is supposed to be unique).
- Copy **exec_file** to
  `<chroot_base>/<exec_file_name>/<id>/root/<exec_file_name>`. This (as opposed
  to hard linking) is currently the default behavior. Being able to create hard
  links instead of copies will be implemented as a command line option shortly.
- Create the `cgroup` sub-folders. At the moment, the jailer uses three
  `cgroup v1` controllers: `cpu`, `cpuset`, and `pids`. On most systems, these
  (along with others) are mounted by default somewhere in `/sys/fs/cgroup` (they
  should be mounted by the user otherwise). The jailer will parse `/proc/mounts`
  to detect where each of the three controllers can be found (multiple
  controllers may share the same path). For each identified location (referred
  to as `<cgroup_base>`), the jailer creates the
  `<cgroup_base>/<exec_file_name>/<id>` subfolder, and writes the current pid to `<cgroup_base>/<exec_file_name>/<id>/tasks`. Also, the value of `numa_node` is
  written to the appropriate `cpuset.mems` file.
- Chroot into `chroot_dir`.
- Drop privileges via setting the provided `uid` and `gid`.
- Exec into `<exec_file_name> --jailed`. The `--jailed` command line argument to
  the target binary is then interpreted by Firecracker, that realizes it’s
  running inside a jail, and continues the execution accordingly.

## Example Run and Notes

Let’s assume Firecracker is available as `/usr/bin/firecracker`, and the jailer
can be found at `/usr/bin/jailer`. We pick the **unique id
551e7604-e35c-42b3-b825-416853441234**, and we choose to run on **NUMA node 0**,
using **uid 123**, and **gid 100**. For this example, we are content with the
default `/srv/jailer` **chroot base dir**.

We start by running

``` bash
/usr/bin/jailer --id 551e7604-e35c-42b3-b825-416853441234 --node 0 --exec-file /usr/bin/firecracker --uid 123 --gid 100
```

After opening the file descriptors mentioned in the previous section, the jailer
will create the following resources (and all their prerequisites, such as the
path which contains them):

- `/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/api.socket`
  (created via `bind`)
- `/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root/firecracker`
  (copied from `/usr/bin/firecracker`)

Let’s also assume the **cpu**, **cpuset**, and **pids** cgroups are mounted at
`/sys/fs/cgroup/cpu`, `/sys/fs/cgroup/cpuset`, and `/sys/fs/cgroup/pids`,
respectively. The jailer will create the following subfolders (which will
inherit settings from the parent cgroup):

- `/sys/fs/cgroup/cpu/firecracker/551e7604-e35c-42b3-b825-416853441234`
- `/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234`
- `/sys/fs/cgroup/pids/firecracker/551e7604-e35c-42b3-b825-416853441234`.

It’s worth noting that, whenever a folder already exists, nothing will be done,
and we move on to the next directory that needs to be created. This should only
happen for the common **firecracker** subfolder (but, as for creating the chroot
path before, we do not issue an error if folders directly associated with the
supposedly unique **id** already exist).

The jailer then writes the current pid to `/sys/fs/cgroup/cpu/firecracker/551e7604-e35c-42b3-b825-416853441234/tasks`, `/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234/tasks`,
and `/sys/fs/cgroup/pids/firecracker/551e7604-e35c-42b3-b825-416853441234/tasks`.
It also writes `0` to
`/sys/fs/cgroup/cpuset/firecracker/551e7604-e35c-42b3-b825-416853441234/cpuset.mems`.

Finally, the jailer chroots into
`/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root`, switches
the **uid** to ```123```, and **gid** to ```100```, and execs
`/firecracker —jailed`.

We can now use the socket at
`/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/api.socket` to
interact with the VM.

### Observations

- The user must create hard links for (or copy) any resources which will be
  provided to the VM via the API (disk images, kernel images, named pipes, etc)
  inside the jailed root folder. Also, permissions must be properly managed for
  these resources; for example the user which Firecracker runs as must have both
  **read and write permissions** to the backing file for a RW block device.
- It’s up to the user to load balance VM placement among multiple NUMA nodes
  (if present), using the ```--node``` command line argument.
- The user must also manage any further fine tuning of resource partitioning via
  cgroups (most likely the ones created by the jailer), or any other means.
- It’s up to the user to handle cleanup after running the jailer. One way to do
  this involves registering handlers with the cgroup **notify_on_release**
  mechanism, while being wary about potential race conditions (the instance
  crashing before the subscription process is complete, for example).
- Seccomp filtering is currently disabled by default and needs to be enabled by
  setting the `USE_SECCOMP` environment variable due to a bug in the Linux
  kernel. Enabling it might cause slowness as a result of an increased number of
  page faults.

## Caveats

- If all the cgroup controllers are bunched up on a single mount point using the
  "all" option, our current program logic will complain it cannot detect
  individual controller mount points.
