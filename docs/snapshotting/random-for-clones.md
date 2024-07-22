# Entropy for Clones

This document provides a high level perspective on the implications of restoring
multiple VM clones from a single snapshot. We start with an overview of the
Linux random number generation (RNG) facilities, then go through the potential
issues we’ve identified related to cloning state, and finally conclude with a
series of recommendations. It’s worth stressing that we aim to prevent stale
state being a problem only for the kernel interfaces. Some userspace
applications or libraries keep their own equivalent of entropy pools and suffer
from the same potential issues after being cloned. There is no generic solution
under the current programming model, and all we can do is recommend against
their use in pre-snapshot logic.

## Background

The Linux kernel exposes three main `RNG` interfaces to userspace: the
`/dev/random` and `/dev/urandom` special devices, and the `getrandom` syscall,
which are described in the [random(7) man page][1]. Moreover, Firecracker
supports the [`virtio-rng`](../entropy.md) device which can provide additional
entropy to guest VMs. It draws its random bytes from the [`aws-lc-rs`][8] crate
which wraps the [`AWS-LC` cryptographic library][9].

Traditionally, `/dev/random` has been considered a source of “true” randomness,
with the downside that reads block when the pool of entropy gets depleted. On
the other hand, `/dev/urandom` doesn’t block, which lead people believe that it
provides lower quality results.

It turns out the distinction in output quality is actually very hard to make.
According to [this article][2], for kernel versions prior to 4.8, both devices
draw their output from the same pool, with the exception that `/dev/random` will
block when the system estimates the entropy count has decreased below a certain
threshold. The `/dev/urandom` output is considered secure for virtually all
purposes, with the caveat that using it before the system gathers sufficient
entropy for initialization may indeed produce low quality random numbers. The
`getrandom` syscall helps with this situation; it uses the `/dev/urandom` source
by default, but will block until it gets properly initialized (the behavior can
be altered via configuration flags).

Newer kernels (4.8+) have switched to an implementation where `/dev/random`
output comes from a pool called the blocking pool, the output of `/dev/urandom`
is given by a CSPRNG (cryptographically secure pseudorandom number generator),
and there’s also an input pool which gathers entropy from various sources
available on the system, and is used to feed into or seed the other two
components. A very detailed description is available [here][3].

The details of this newer implementation are used to make the recommendations
present in the document. There are in-kernel interfaces used to obtain random
numbers as well, but they are similar to using `/dev/urandom` (or `getrandom`
with the default source) from userspace.

Whenever a VM clone is created based on a snapshot, execution resumes precisely
from the previously saved state. Getting random bytes from either `/dev/random`
or `/dev/urandom` does not lead to identical results for different clones
created from the same snapshot because multiple parameters (such as timer data,
or output from `CPU HWRNG` instructions which are present on Ivy Bridge or newer
Intel processors and enabled in a Firecracker guest) are mixed with each result.
Extra bits are mixed in both when reading random values, and in conjunction with
entropy related events such as interrupts. Moreover, the guest kernel will
eventually receive fresh entropy from `virtio-rng`, if attached. There are two
questions here:

- Is the `CPU HWRNG` output always mixed in when the feature is present (as
  opposed to only when the `CPU HWRNG` is trusted)?
- Is the added noise strong enough to consider the final RNG output sufficiently
  divergent from all other clones?

Both these questions are particularly relevant immediately after resuming a VM
from a snapshot. After the VM gets to run for a "sufficient" amount of time it
should be able to gather some more entropy by itself and its state should be
sufficiently divergent that of any other clones.

It seems the `CPU HWRNG` is always added to mix when present. More specifically,
[page 32 point 1 (at the top of the page)][3] mentions using the `CPU HWRNG`
when present for the entropy pool output function. Page 34 states *in case a CPU
random number generator is known to the Linux-RNG, data from that hardware RNG
is mixed into the entropy pool in a second step*. With respect to the
initialization of the random pools and DRNG behind /dev/urandom. The discussion
regarding DRNG state on page 35 mentions *the key part, the counter, and the
nonce are XORed with the output of the CPU random number generator if one is
present. If it is not present, one high-resolution time stamp obtained with the
kernel function random_get_entropy word is XORed with the key part*. The
`CPU HWRNG` is also used for the DRNG state transition function (as stated on
page 36 point 1), and during the reseed operation (page 37 point 2). The
document explicitly mentions when the `CPU HWRNG` has to be trusted (for
example, the bullet points at the end of Section 3.3.2.3).

It’s not yet clear whether the noise that gets added for each clone post restore
is sufficient to consider their RNG states distinct for security purposes. The
conservative approach is to presume the stale state has a significant influence
on RNG output, so we should reinitialize both sources based on fresh data after
each restore. It would seem that simply writing data to `/dev/urandom` is enough
to muddle the entropy pools, but the bits only get mixed with the input pool.
It’s not certain at this point whether such writes have any immediate impact on
the blocking pool, and it’s unlikely they cause the `CSPRNG` to be automatically
reseeded.

The standard methods of interacting with the kernel RNG sources are documented
in the [random(4) man page][4]. It states that any writes to either
`/dev/random` or `/dev/urandom` are mixed with the input entropy pool, but do
not increase the current entropy estimation. There is also an `ioctl` interface
which, given the appropriate privileges, can be used to add data to the input
entropy pool while also increasing the count, or completely empty all pools.

### Linux kernels with VMGenID support

Linux has support for the
[Virtual Machine Generation Identifier](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/virtual-machine-generation-identifier)
since 5.18 for ACPI systems. Since 6.10, Linux added support also for systems
that use DeviceTree instead of ACPI. The purpose of VMGenID is to notify the
guest about time shift events, such as resuming from a snapshot. The device
exposes a 16-byte cryptographically random identifier in guest memory.
Firecracker implements VMGenID. When resuming a microVM from a snapshot
Firecracker writes a new identifier and injects a notification to the guest.
Linux,
[uses this value](https://elixir.bootlin.com/linux/v5.18.19/source/drivers/virt/vmgenid.c#L77)
[as new randomness for its CSPRNG](https://elixir.bootlin.com/linux/v5.18.19/source/drivers/char/random.c#L908).
Quoting the random.c implementation of the kernel:

```
/*
 * Handle a new unique VM ID, which is unique, not secret, so we
 * don't credit it, but we do immediately force a reseed after so
 * that it's used by the crng posthaste.
 */
```

As a result, values returned by `getrandom()` and `/dev/(u)random` are distinct
in all VMs started from the same snapshot, **after** the kernel handles the
VMGenID notification. This leaves a race window between resuming vCPUs and Linux
CSPRNG getting successfully re-seeded. In Linux 6.8, we
[extended VMGenID](https://lore.kernel.org/lkml/20230531095119.11202-2-bchalios@amazon.es/)
to emit a uevent to user space when it handles the notification. User space can
poll this uevent to know when it is safe to use `getrandom()`, et al. avoiding
the race condition.

Firecracker supports VMGenID on ARM systems using the DeviceTree binding that
was added for the device in Linux 6.10. However, the latest Linux kernel that
Firecracker supports is 6.1. As a result, in order to use VMGenID on ARM
systems, users need to use a 6.1 kernel with the DeviceTree binding support
backported from 6.10. We provide a set of patches that apply cleanly on mainline
Linux 6.1 [here](../../resources/patches/vmgenid_dt).

Please note that, Firecracker will always enable VMGenID. In kernels where there
is no VMGenID driver, the device will not have any effect in the guest.

### User space considerations

Init systems (such as `systemd` used by AL2 and other distros) might save a
random seed file after boot. For `systemd`, the path is
`/var/lib/systemd/random-seed`. Just to be on the safe side, any such file
should be deleted before taking a snapshot, to prevent its reuse for any
purposes by the guest. There’s also the `/proc/sys/kernel/random/boot_id`
special file, which gets initialized with a random string at boot time, and is
read-only afterwards. All clones restored from the same snapshot will implicitly
read the same value from this file. If that’s not desirable, it’s possible to
alter the read result via bind mounting another file on top of
`/proc/sys/kernel/random/boot_id`.

## Recommendations

- Delete `/var/lib/systemd/random-seed`, or any equivalent files.
- If changing the value present in `/proc/sys/kernel/random/boot_id` is
  important, bind mount another file on top of it.
- If microVMs run on machines with IvyBridge or newer Intel processors (which
  provide RDRAND; in addition, RDSEED is offered starting with Broadwell).
  Hardware supported reseeding is done on a cadence defined by the Linux Kernel
  and should be sufficient for most cases.
- Use `virtio-rng`. When present, the guest kernel uses the device as an
  additional source of entropy.
- On kernels before 5.18, to be as safe as possible, the direct approach is to
  do the following (before customer code is resumed in the clone):
  1. Open one of the special devices files (either `/dev/random` or
     `/dev/urandom`). Take note that `RNDCLEARPOOL` no longer
     [has any effect][7] on the entropy pool.
  1. Issue an `RNDADDENTROPY` ioctl call (requires `CAP_SYS_ADMIN`) to mix the
     provided bytes into the input entropy pool and increase the entropy count.
     This should also cause the `/dev/urandom` `CSPRNG` to be reseeded. The
     bytes can be generated locally in the guest, or obtained from the host.
  1. Issue a `RNDRESEEDCRNG` ioctl call ([4.14][5], [5.10][6], (requires
     `CAP_SYS_ADMIN`)) that specifically causes the `CSPRNG` to be reseeded from
     the input pool.
- On kernels starting from 5.18 onwards, the CSPRNG will be automatically
  reseeded when the guest kernel handles the VMGenID notification. To completely
  avoid the race condition, users should follow the same steps as with kernels
  \< 5.18.
- On kernels starting from 6.8, users can poll for the VMGenID uevent that the
  driver sends when the CSPRNG is reseeded after handling the VMGenID
  notification.

**Annex 1 contains the source code of a C program which implements the previous
three steps.** As soon as the guest kernel version switches to 4.19 (or higher),
we can rely on the `CONFIG_RANDOM_TRUST_CPU` kernel option (or the
random.trust_cpu=on cmdline parameter) to have the entropy pool automatically
refilled using the `CPU HWRNG`, so step 3 would no longer be necessary. Another
way around step 3 is to attach a `virtio-rng` device. However, we cannot control
when the guest kernel will request for random bytes from the device.

## Annex 1: Source code that clears and reinitializes the entropy pool

```cpp
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

void exit_usage() {
    printf("Usage: ./rerand [<hexadecimal_string>]\n"
           "The length of the string must be a multiple of 8.\n");
    exit(EXIT_FAILURE);
}

void exit_perror(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char ** argv) {
    if (argc > 2) {
        exit_usage();
    }

    size_t len = 0;
    struct rand_pool_info *info = NULL;

    if (argc == 2) {
        len = strlen(argv[1]);
        // We want len to be a multiple of 8 such that we have an easier time
        // parsing argv[1] into an array of u32s.
        if (len % 8) {
            exit_usage();
        }

        info = malloc(sizeof(struct rand_pool_info) + len / 8);
        if (info == NULL) {
            exit_perror("Could not alloc rand_pool_info struct");
        }
        // This is measured in bits IIRC.
        info->entropy_count = len * 4;
        info->buf_size = len / 8;
    }

    int fd = open("/dev/urandom", O_RDWR);
    if (fd < 0) {
        exit_perror("Unable to open /dev/urandom");
    }

    if (ioctl(fd, RNDCLEARPOOL) < 0) {
        exit_perror("Error issuing RNDCLEARPOOL operation");
    }

    if (argc == 1) {
        exit(EXIT_SUCCESS);
    }

    // Add the entropy bytes supplied by the user.
    char num_buf[9] = {};
    size_t pos = 0;

    while (pos < len) {
        memcpy(num_buf, &argv[1] + pos, 8);
        info->buf[pos / 8] = strtoul(num_buf, NULL, 16);
        pos += 8;
    }

    if (ioctl(fd, RNDADDENTROPY, info) < 0) {
        exit_perror("Error issuing RNDADDENTROPY operation");
    }
}
```

[1]: http://man7.org/linux/man-pages/man7/random.7.html
[2]: https://www.2uo.de/myths-about-urandom
[3]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/LinuxRNG/LinuxRNG_EN.pdf
[4]: http://man7.org/linux/man-pages/man4/random.4.html
[5]: https://elixir.bootlin.com/linux/v4.14.295/source/drivers/char/random.c#L1355
[6]: https://elixir.bootlin.com/linux/v5.10.147/source/drivers/char/random.c#L1360
[7]: https://elixir.bootlin.com/linux/v4.14.295/source/drivers/char/random.c#L1351
[8]: https://docs.rs/aws-lc-rs/latest/aws_lc_rs/index.html
[9]: https://github.com/aws/aws-lc
