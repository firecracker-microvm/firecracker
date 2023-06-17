# Network Connectivity for Clones

This document presents the strategy to ensure continued network connectivity
for multiple clones created from a single Firecracker microVM snapshot.
This document also provides an overview of the scalability benchmarks we
performed.

## Setup

There are two things which prevent network connectivity from resuming
out-of-the-box for clones created from the same snapshot: Firecracker currently
saves and attempts to restore network devices using the initially
configured TAP names, and each guest will be resumed with the same
network configuration, most importantly with the same IP address(es).
To work around the former, each clone should be started within a
separate network namespace (we can have multiple TAP interfaces with the
same name, as long as they reside in distinct network namespaces).
The latter can be mitigated by leveraging `iptables` `SNAT` and `DNAT`
support. We choose a clone address (**CA**) for each clone, which is the
new address that’s going to represent the guest, and make it so all
packets leaving the VM have their source address rewritten to CA,
and all incoming packets with the destination address equal to CA
have it rewritten to the IP address configured inside the guest (which
remains the same for all clones). Each individual clone continues to
believe it’s using the original address, but outside the VM packets are
assigned a different one for every clone.

Let’s have a more detailed look at this approach. We assume each VM has
a single network interface attached. If multiple interfaces with full
connectivity are required, we simply repeat the relevant parts of this
process for each additional interface. A typical setup right before
taking a snapshot involves having a VM with a network interface backed
by a TAP device (named `vmtap0`, for example) with an IP address
(referred to as the TAP IP address, for example `192.168.241.1/29`), and
an IP address configured inside the guest for the corresponding virtio
device (referred to as the guest IP address, for example
`192.168.241.2/29`).

### Network namespaces

Attempting to restore multiple clones from the same snapshot faces the
problem of every single one of them attempting to use a TAP device with
the original name, which is not possible by default. Therefore, we need
to start each clone in a separate network namespace. This is already
possible using the netns jailer parameter, described in the
[documentation](../jailer.md). The specified namespace must already
exist, so we have to create it first using

```bash
sudo ip netns add fc0
```

(where `fc0` is the name of the network namespace we plan to use for
this specific clone - `clone0`). A new network namespace is initially
empty, so we also have to create a new tap interface within using

```bash
sudo ip netns exec fc0 ip tuntap add name vmtap0 mode tap
```

The `ip netns exec <ns_name> <command>` allows us to execute `command`
in the context of the specified network namespace (in the previous case,
the secondary command creates a new tap interface). Next we configure
the new TAP interface to match the expectations of the snapshotted guest
by running

```bash
sudo ip netns exec fc0 ip addr add 192.168.241.1/29 dev vmtap0
sudo ip netns exec fc0 ip link set vmtap0 up
```

At this point we can start multiple clones, each in its separate
namespace, but they won’t have connectivity to the rest of the host,
only the respective TAP interfaces. However, interaction over the
network is still possible; for example we can connect over ssh to
clone0 using

```bash
sudo ip netns exec fc0 ssh root@192.168.241.2
```

### `veth` interfaces to connect the network namespaces

In order to obtain full connectivity we have to begin by connecting the
network namespace to the rest of the host, and then solving the
*“same guest IP”* problem. The former requires the use of `veth`
pairs - *virtual interfaces that are link-local to each other (any
packet sent through one end of the pair is immediately received on the
other, and the other way around)*.
One end resides inside the network namespace, while the other is moved
into the parent namespace (the host global namespace in this case),
and packets flow in or out according to the network configuration. We
have to pick IP addresses for both ends of the veth pair. For clone
index `idx`, let’s use `10.<idx / 30>.<(idx % 30) * 8>.1/24` for the
endpoint residing in the host namespace, and the same address ending
with `2` for the other end which remains inside the clone's namespace.
Thus, for `clone 0` the former is `10.0.0.1` and the latter `10.0.0.2`.

The first endpoint must have an unique name on the host, for example
chosen as `veth(idx + 1) (so veth1 for clone 0)`. To create and setup
the veth pair, we use the following commands (for namespace `fc0`):

```bash
# create the veth pair inside the namespace
sudo ip netns exec fc0 ip link add veth1 type veth peer name veth0
# move veth1 to the global host namespace
sudo ip netns exec fc0 ip link set veth1 netns 1

sudo ip netns exec fc0 ip addr add 10.0.0.2/24 dev veth0
sudo ip netns exec fc0 ip link set dev veth0 up

sudo ip addr add 10.0.0.1/24 dev veth1
sudo ip link set dev veth1 up

# designate the outer end as default gateway for packets leaving the namespace
sudo ip netns exec fc0 ip route add default via 10.0.0.1
```

### `iptables` rules for end-to-end connectivity

The last step involves adding the `iptables` rules which change the
source/destination IP address of packets on the fly (thus allowing all
clones to have the same internal IP). We need to choose a clone address,
which is unique on the host for each VM. In the demo, we use
`192.168.<idx / 30>.<(idx % 30) * 8 + 3>` (which is `192.168.0.3` for
`clone 0`):

```bash
# for packets that leave the namespace and have the source IP address of the
# original guest, rewrite the source address to clone address 192.168.0.3
sudo ip netns exec fc0 iptables -t nat -A POSTROUTING -o veth0 \
-s 192.168.241.2 -j SNAT --to 192.168.0.3

# do the reverse operation; rewrites the destination address of packets
# heading towards the clone address to 192.168.241.2
sudo ip netns exec fc0 iptables -t nat -A PREROUTING -i veth0 \
-d 192.168.0.3 -j DNAT —to 192.168.241.2

# (adds a route on the host for the clone address)
sudo ip route add 192.168.0.3 via 10.0.0.2
```

**Full connectivity to/from the clone should be present at this point.**

To make sure the guest also adjusts to the new environment, you can explicitly
clear the ARP/neighbour table in the guest:

```bash
ip -family inet neigh flush any
ip -family inet6 neigh flush any
```

 Otherwise, packets originating from the guest might be using old Link Layer
 Address for up to arp cache timeout seconds. After said timeout period,
 connectivity will work both ways even without an explicit flush.

## Scalability evaluation

We ran synthetic tests to determine the impact of the addtional iptables
rules and namespaces on network performance. We compare the case where
each VM runs as regular Firecracker (gets assigned a TAP interface and a
unique IP address in the global namespace) versus the setup with a
separate network namespace for each VM (together with the veth pair and
additional rules). We refer to the former as the basic case, while the
latter is the ns case. We measure latency with the `ping` command and
throughput with `iperf`.

The experiments, ran on an Amazon AWS `m5d.metal` EC2 instace, go as follows:

* Set up 3000 network resource slots (different TAP interfaces for the
  basic case, and namespaces + everything else for ns). This is mainly
  to account for any difference the setup itself might make, even if
  there are not as many active endpoints at any given time.
* Start 1000 Firecracker VMs, and pick `N < 1000` as the number of
  active VMs that are going to generate network traffic. For ping
  experiments, we ping each active VM from the host every 500ms for 30
  seconds. For `iperf` experiments, we measure the average bandwidth of
  connections from the host to every active VM lasting 40 seconds.
  There is one separate client process per VM.
* When `N = 100`, in the basic case we get average latencies of `0.315
  ms (0.160/0.430 min/max)` for `ping`, and an average throughput of
  `2.25 Gbps (1.62/3.21 min/max)` per VM for `iperf`. In the ns case,
  the ping results **are bumped higher by around 10-20 us**, while the
  `iperf` results are virtually the same on average, with a higher
  minimum (1.73 Gbps) and a lower maximum (3 Gbps).
* When `N = 1000`, we start facing desynchronizations caused by
  difficulties in starting (and thus finishing) the client processes all
  at the same time, which creates a wider distribution of results. In
  the basic case, the average latency for ping  experiments has gone
  down to 0.305 ms, the minimum decreased to 0.155 ms, but the maximum
  increased to 0.640 ms. The average `iperf` per VM throughput is around
  `440 Mbps (110/3936 min/max)`. In the ns case, average `ping` latency
  is now `0.318 ms (0.170/0.650 min/max)`. For `iperf`, the average
  throughput is very close to basic at `~430 Mbps`, while the minimum
  and maximum values are lower at `85/3803 Mbps`.

**The above measurements give a significant degree of confidence in the
scalability of the solution** (subject to repeating for different values
of the experimental parameters, if necessary). The increase in latency
is almost negligible considering usual end-to-end delays. The lower
minimum throughput from the iperf measurements might be significant, but
only if that magnitude of concurrent, data-intensive transfers is likely.
Moreover, the basic measurements are close to an absolute upper bound.
