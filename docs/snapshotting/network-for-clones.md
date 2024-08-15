# Network Connectivity for Clones

This document presents a strategy to ensure continued network connectivity for
multiple clones created from a single Firecracker microVM snapshot.

> [!CAUTION]
>
> This should be considered as just an example to get you started, and we don't
> claim this is a performant or secure setup.

## Setup

There are two things which prevent network connectivity from resuming
out-of-the-box for clones created from the same snapshot: Firecracker currently
saves and attempts to restore network devices using the initially configured TAP
names, and each guest will be resumed with the same network configuration, most
importantly with the same IP address(es). To work around the former, each clone
should be started within a separate network namespace (we can have multiple TAP
interfaces with the same name, as long as they reside in distinct network
namespaces). The latter can be mitigated by leveraging `iptables` `NAT` support.

Let’s have a more detailed look at this approach. We assume each VM has a single
network interface attached. If multiple interfaces with full connectivity are
required, we simply repeat the relevant parts of this process for each
additional interface. A typical setup right before taking a snapshot involves
having a VM with a network interface backed by a TAP device (named `vmtap0`, for
example) with an IP address (referred to as the TAP IP address, for example
`192.168.241.1/29`), and an IP address configured inside the guest for the
corresponding virtio device (referred to as the guest IP address, for example
`192.168.241.2/29`).

### Network namespaces

Attempting to restore multiple clones from the same snapshot faces the problem
of every single one of them attempting to use a TAP device with the original
name, which is not possible by default. Therefore, we need to start each clone
in a separate network namespace. This is already possible using the `--netns`
jailer parameter, described in the [documentation](../jailer.md). The specified
namespace must already exist, so we have to create it first using

```bash
sudo ip netns add fc0
```

(where `fc0` is the name of the network namespace we plan to use for this
specific clone - `clone0`). A new network namespace is initially empty, so we
also have to create a new tap interface within using

```bash
sudo ip netns exec fc0 ip tuntap add name vmtap0 mode tap
```

The `ip netns exec <ns_name> <command>` allows us to execute `command` in the
context of the specified network namespace (in the previous case, the secondary
command creates a new tap interface). Next we configure the new TAP interface to
match the expectations of the snapshotted guest by running

```bash
sudo ip netns exec fc0 ip addr add 192.168.241.1/29 dev vmtap0
sudo ip netns exec fc0 ip link set vmtap0 up
```

At this point we can start multiple clones, each in its separate namespace, but
they won’t have connectivity to the rest of the host, only the respective TAP
interfaces. However, interaction over the network is still possible; for example
we can connect over ssh to clone0 using

```bash
sudo ip netns exec fc0 ssh root@192.168.241.2
```

### `veth` interfaces to connect the network namespaces

In order to obtain full connectivity we have to begin by connecting the network
namespace to the rest of the host, and then solving the *“same guest IP”*
problem. The former requires the use of `veth` pairs - *virtual interfaces that
are link-local to each other (any packet sent through one end of the pair is
immediately received on the other, and the other way around)*. One end resides
inside the network namespace, while the other is moved into the parent namespace
(the host global namespace in this case), and packets flow in or out according
to the network configuration. We have to pick IP addresses for both ends of the
veth pair. For clone index `idx`, let’s use
`10.<idx / 30>.<(idx % 30) * 8>.1/24` for the endpoint residing in the host
namespace, and the same address ending with `2` for the other end which remains
inside the clone's namespace. Thus, for `clone 0` the former is `10.0.0.1` and
the latter `10.0.0.2`.

The first endpoint must have an unique name on the host, for example chosen as
`veth(idx + 1) (so veth1 for clone 0)`. To create and setup the veth pair, we
use the following commands (for namespace `fc0`):

```bash
# create the veth pair inside the namespace
sudo ip link add name veth1 type veth peer name veth0 netns fc0

sudo ip netns exec fc0 ip addr add 10.0.0.2/24 dev veth0
sudo ip netns exec fc0 ip link set dev veth0 up

sudo ip addr add 10.0.0.1/24 dev veth1
sudo ip link set dev veth1 up

# designate the outer end as default gateway for packets leaving the namespace
sudo ip netns exec fc0 ip route add default via 10.0.0.1
```

### `iptables` rules for VM egress connectivity

The last step involves adding the `iptables` rules which change the
source/destination IP address of packets on the fly (thus allowing all clones to
have the same internal IP).

```sh
# Find the host egress device
UPSTREAM=$(ip -j route list default |jq -r '.[0].dev')
# anything coming from the VMs, we NAT the address
iptables -t nat -A POSTROUTING -s 10.0.0.0/30 -o $UPSTREAM -j MASQUERADE
# forward packets by default
iptables -P FORWARD ACCEPT
ip netns exec fc0 ip route add default via 10.0.0.1
ip netns exec fc0 iptables -P FORWARD ACCEPT
```

You may also want to configure the guest with a default route and a DNS
nameserver:

```bash
ip route default via 10.0.0.1
echo nameserver 8.8.8.8 >/etc/resolv.conf
```

**Connectivity from the clone should be present at this point.**

To make sure the guest also adjusts to the new environment, you can explicitly
clear the ARP/neighbour table in the guest:

```bash
ip -family inet neigh flush any
ip -family inet6 neigh flush any
```

Otherwise, packets originating from the guest might be using old Link Layer
Address for up to arp cache timeout seconds. After said timeout period,
connectivity will work both ways even without an explicit flush.

### Renaming host device names

In some environments where the jailer is not being used, restoring a snapshot
may be tricky because the tap device on the host will not be the same as the tap
device that the original VM was mapped to when it was snapshotted, for example
when the tap device comes from a pool of such devices.

In this case you can use the `network_overrides` parameter of the snapshot
restore API to specify which guest network device maps to which host tap device.

For example, if we have a network interface named `eth0` in the snapshotted
microVM, we can override it to point to the host device `vmtap01` during
snapshot resume, like this:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT 'http://localhost/snapshot/load' \
    -H  'Accept: application/json' \
    -H  'Content-Type: application/json' \
    -d '{
            "snapshot_path": "./snapshot_file",
            "mem_backend": {
                "backend_path": "./mem_file",
                "backend_type": "File"
            },
            "network_overrides": [
                 {
                     "iface_id": "eth0",
                     "host_dev_name": "vmtap01"
                 }
            ]
    }'
```

This may require reconfiguration of the networking inside the VM so that it is
still routable externally.
[network setup documentation](../network-setup.md#in-the-guest) describes what
the typical setup is. If you are not using network namespaces or the jailer,
then the guest will have to be made aware (via vsock or other channel) that it
needs to reconfigure its network to match the network configured on the tap
device.

If the new TAP device, say `vmtap3` has been configured to use a guest address
of `172.16.3.2` then after snapshot restore you would run something like:

```bash
# In the guest

# Clear out the previous addr and route
ip addr flush dev eth0
ip route flush dev eth0

# Configure the new address
ip addr add 172.16.3.2/30 dev eth0
ip route add default via 172.16.3.1/30 dev eth0
```

# Ingress connectivity

The above setup only provides egress connectivity. If in addition we also want
to add ingress (in other words, make the guest VM routable outside the network
namespace), then we need to choose a "clone address" that will represent this VM
uniquely. For our example we can use IPs from `172.16.0.0/12`, for example
`172.16.0.1`.

Then we can rewrite destination address heading towards the "clone address" to
the guest IP.

```bash
ip netns exec fc0 iptables -t nat -A PREROUTING -i veth0 \
    -d 172.16.0.1 -j DNAT --to 192.168.241.2
```

And add a route on the host so we can access the guest VM from the host network
namespace:

```bash
ip route add 172.16.0.1 via 10.0.0.2
```

To confirm that ingress connectivity works, try

```bash
ping 172.16.0.1
# or
ssh root@172.16.0.1
```

# See also

For an improved setup with full ingress and egress connectivity to the
individual VMs, see
[this discussion](https://github.com/firecracker-microvm/firecracker/discussions/4720).
