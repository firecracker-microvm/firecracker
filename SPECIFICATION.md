# Specification

The specifications below quantify Firecracker's promise to enable
minimal-overhead execution of container and serverless workloads. These
specifications are enforced by integration tests (that run for each PR and
master branch merge).

On an I3.metal instance¹, with hyperthreading disabled and given host system
resources are available (e.g., there are enough free CPU cycles, there is enough
RAM, etc.), customers can rely on the following:

1. **Stability:** The Firecracker virtual machine manager starts (up to API
   socket availability) within `8 CPU ms`² and never crashes/halts/terminates
   for internal reasons once started. _Note_: The wall-clock time has a large
   standard deviation, spanning `6 ms to 60 ms`, with typical durations around
   `12 ms`.
1. **Failure Information:** When failures occur due to external circumstances,
   they are logged³ by the Firecracker process.
1. **API Stability:** The API socket is always available and the API conforms
   to the in-tree [Open API specification](api_server/swagger/firecracker.yaml). API
   failures are logged in the Firecracker log.
1. **Overhead:** For a Firecracker virtual machine manager running a microVM
   with `2 CPUs and 256 MiB of RAM`, and a guest OS with the Firecracker-tuned
   kernel:
   - Firecracker's virtual machine manager threads always have a memory
     overhead `<= 5 MiB`;
   - It takes `<= 125 ms` to go from receiving the Firecracker InstanceStart API
     call to the start of the Linux guest user-space `/sbin/init` process.
   - The compute-only guest CPU performance is `> 95%` of the equivalent
     bare-metal performance. _`[integration test pending]`_
1. **IO Performance:** With a host CPU core dedicated to the Firecracker device
   emulation thread,
   - the guest achieves up to `14.5 Gbps` network throughput by using `<= 80%`
     of the host CPU core for emulation. _`[integration test pending]`_
   - the guest achieves up to `1 GiB/s` storage throughput by using `<= 70%`
     the host CPU cores for emulation. _`[integration test pending]`_
1. **Telemetry:** Firecracker emits logs and metrics to the named pipes passed
   to the logging API. Any logs and metrics emitted while their respective
   pipes are full will be lost. Any such events will be signaled through the
   `lost-logs` and `lost-metrics` counters.

¹ I3.metal instances: [https://aws.amazon.com/ec2/instance-types/i3/](https://aws.amazon.com/ec2/instance-types/i3/)

² CPU ms are actual ms of a user space thread's on-CPU runtime; useful for
  getting consistent measurements for some performance metrics.

³ No logs are currently produced in the span of time between the `jailer`
  process start-up and the logging system initialization in the `firecracker`
  process.

