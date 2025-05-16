# Getting Started Firecracker Network Setup

This is a simple quick-start guide to getting one or more Firecracker microVMs
connected to the Internet via the host. If you run a production setup, you
should consider modifying this setup to accommodate your specific needs.

**Note:** Currently, Firecracker supports only a TUN/TAP network backend with no
multi queue support.

The steps in this guide assume `eth0` to be your Internet-facing network
interface on the host. If `eth0` isn't your main network interface, you should
change the value to the correct one in the commands below. IPv4 is also assumed
to be used, so you will need to adapt the instructions accordingly to support
IPv6.

Each microVM requires a host network interface (like `eth0`) and a Linux `tap`
device (like `tap0`) used by Firecracker, but the differences in configuration
stem from routing: how packets from the `tap` get to the network interface
(egress) and vice-versa (ingress). There are three main approaches of how to
configure routing for a microVM.

1. **NAT-based**, which is presented in the main part of this guide. It is
   simple but doesn't expose your microVM to the local network (LAN).
1. **Bridge-based**, which exposes your microVM to the local network. Learn more
   about in the _Advanced: Bridge-based routing_ section of this guide.
1. **Namespaced NAT**, which sacrifices performance in comparison to the other
   approaches but is desired in the scenario when two clones of the same microVM
   are running at the same time. To learn more about it, check out the
   [Network Connectivity for Clones](./snapshotting/network-for-clones.md)
   guide.

To run multiple microVMs while using NAT-based routing, check out the _Advanced:
Multiple guests_ section. The same principles can be applied to other routing
methods with a bit more effort.

For the choice of firewall, `nft` is recommended for use on production Linux
systems, but, for the sake of compatibility, this guide provides a choice
between either `nft` or the `iptables-nft` translation layer. The latter is
[no longer recommended](https://access.redhat.com/solutions/6739041) but may be
more familiar to readers.

## On the Host

The first step on the host for any microVM is to create a Linux `tap` device,
which Firecracker will use for networking.

For this setup, only two IP addresses will be necessary - one for the `tap`
device and one for the guest itself, through which you will, for example, `ssh`
into the guest. So, we'll choose the smallest IPv4 subnet needed for 2
addresses: `/30`. For this VM, let's use the `172.16.0.1` `tap` IP and the
`172.16.0.2` guest IP.

```bash
# Create the tap device.
sudo ip tuntap add tap0 mode tap
# Assign it the tap IP and start up the device.
sudo ip addr add 172.16.0.1/30 dev tap0
sudo ip link set tap0 up
```

**Note:** The IP of the TAP device should be chosen such that it's not in the
same subnet as the IP address of the host.

We'll need to enable IPv4 forwarding on the system.

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### Configuration via `nft`

We'll need an nftables table for our routing needs, and 2 chains inside that
table: one for NAT on `postrouting` stage, and another one for filtering on
`forward` stage:

```bash
sudo nft add table firecracker
sudo nft 'add chain firecracker postrouting { type nat hook postrouting priority srcnat; policy accept; }'
sudo nft 'add chain firecracker filter { type filter hook forward priority filter; policy accept; }'
```

The first rule we'll need will masquerade packets from the guest IP as if they
came from the host's IP, by changing the source IP address of these packets:

```bash
sudo nft add rule firecracker postrouting ip saddr 172.16.0.2 oifname eth0 counter masquerade
```

The second rule we'll need will accept packets from the tap IP (the guest will
use the tap IP as its gateway and will therefore route its own packets through
the tap IP) and direct them to the host network interface:

```bash
sudo nft add rule firecracker filter iifname tap0 oifname eth0 accept
```

### Configuration via `iptables-nft`

Tables and chains are managed by `iptables-nft` automatically, but we'll need
three rules to perform the NAT steps:

```bash
sudo iptables-nft -t nat -A POSTROUTING -o eth0 -s 172.16.0.2 -j MASQUERADE
sudo iptables-nft -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables-nft -A FORWARD -i tap0 -o eth0 -j ACCEPT
```

## Setting Up Firecracker

Before starting the guest, configure the network interface using Firecracker's
API:

**Note:** If you use the rootfs from the
[getting started guide](getting-started.md), you need to use a specific `MAC`
address like `06:00:AC:10:00:02`. In this `MAC` address, the last 4 bytes
(`AC:10:00:02`) will represent the IP address of the guest. In the default case,
it is `172.16.0.2`. Otherwise, you can skip the `guest_mac` field for network
configuration. This way, the guest will generate a random MAC address on
startup.

```bash
curl --unix-socket /tmp/firecracker.socket -i \
  -X PUT 'http://localhost/network-interfaces/eth0' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
      "iface_id": "eth0",
      "guest_mac": "06:00:AC:10:00:02",
      "host_dev_name": "tap0"
    }'
```

If you are using a configuration file instead of the API, add a section to your
configuration file like this:

```json
"network-interfaces": [
  {
    "iface_id": "eth0",
    "guest_mac": "06:00:AC:10:00:02",
    "host_dev_name": "tap0"
  }
],
```

Alternatively, if you are using firectl, add
`--tap-device=tap0/06:00:AC:10:00:02\` to your command line.

## In The Guest

Once you have booted the guest, it will have its networking interface with the
name specified by `iface_id` in the Firecracker configuration.

You'll now need to assign the guest its IP, activate the guest's networking
interface and set up the `tap` IP as the guest's gateway address, so that
packets are routed through the `tap` device, where they are then picked up by
the setup on the host prepared before:

```bash
ip addr add 172.16.0.2/30 dev eth0
ip link set eth0 up
ip route add default via 172.16.0.1 dev eth0
```

Now your guest should be able to route traffic to the internet (assuming that
your host can get to the internet). To do anything useful, you probably want to
resolve DNS names. In production, you'd want to use the right DNS server for
your environment. For testing, you can add a public DNS server to
`/etc/resolv.conf` by adding a line like this:

```console
nameserver 8.8.8.8
```

**Note:** Sometimes, it's undesirable to have `iproute2` (providing the `ip`
command) installed on your guest OS, or you simply want to have these steps be
performed automatically. To do this, check out the _Advanced: Guest network
configuration using kernel command line_ section.

## Cleaning up

The first step to cleaning up is to delete the tap device on the host:

```bash
sudo ip link del tap0
```

### Cleanup using `nft`

You'll want to delete the two nftables rules for NAT routing from the
`postrouting` and `filter` chains. To do this with nftables, you'll need to look
up the _handles_ (identifiers) of these rules by running:

```bash
sudo nft -a list ruleset
```

Now, find the `# handle` comments relating to the two rules and delete them. For
example, if the handle to the masquerade rule is 1 and the one to the forwarding
rule is 2:

```bash
sudo nft delete rule firecracker postrouting handle 1
sudo nft delete rule firecracker filter handle 2
```

Run the following steps only **if you have no more guests** running on the host:

Set IPv4 forwarding back to disabled:

```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

If you're using `nft`, delete the `firecracker` table to revert your nftables
configuration fully back to its initial state:

```bash
sudo nft delete table firecracker
```

### Cleanup using `iptables-nft`

Of the configured `iptables-nft` rules, two should be deleted if you have guests
remaining in your configuration:

```bash
sudo iptables-nft -t nat -D POSTROUTING -o eth0 -s 172.16.0.2 -j MASQUERADE
sudo iptables-nft -D FORWARD -i tap0 -o eth0 -j ACCEPT
```

**If you have no more guests** running on the host, then similarly set IPv4
forwarding back to disabled:

```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

And delete the remaining `conntrack` rule that applies to all guests:

```bash
sudo iptables-nft -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

If nothing else is using `iptables-nft` on the system, you may even want to
delete the entire system ruleset like so:

```bash
sudo iptables-nft -F
sudo iptables-nft -t nat -F
```

## Advanced: Multiple guests

To configure multiple guests, we will only need to repeat some of the steps in
this setup for each of the microVMs:

1. Each microVM has its own subnet and the two IP addresses inside of it: the
   `tap` IP and the guest IP.
1. Each microVM has its own two nftables rules for masquerading and forwarding,
   while the same table and two chains can be shared between the microVMs.
1. Each microVM has its own routing configuration inside the guest itself
   (achieved through `iproute2` or the method described in the _Advanced: Guest
   network configuration at kernel level_ section).

To give a more concrete example, **let's add a second microVM** to the one
you've already configured:

Let's assume we allocate /30 subnets in the 172.16.0.0/16 range sequentially to
give out as few addresses as needed.

The next /30 subnet in the 172.16.0.0/16 range will give us these two IPs:
172.16.0.5 as the `tap` IP and 172.16.0.6 as the guest IP.

Our new `tap` device will, sequentially, have the name `tap1`:

```bash
sudo ip tuntap add tap1 mode tap
sudo ip addr add 172.16.0.5/30 dev tap1
sudo ip link set tap1 up
```

Now, let's add the new two `nft` rules, also with the new values:

```bash
sudo nft add rule firecracker postrouting ip saddr 172.16.0.6 oifname eth0 counter masquerade
sudo nft add rule firecracker filter iifname tap1 oifname eth0 accept
```

If using `iptables-nft`, add the rules like so:

```bash
sudo iptables-nft -t nat -A POSTROUTING -o eth0 -s 172.16.0.6 -j MASQUERADE
sudo iptables-nft -A FORWARD -i tap1 -o eth0 -j ACCEPT
```

Modify your Firecracker configuration with the `host_dev_name` now being `tap1`
instead of `tap0`, boot up the guest and perform the routing inside of it like
so, changing the guest IP and `tap` IP:

```bash
ip addr add 172.16.0.6/30 dev eth0
ip link set eth0 up
ip route add default via 172.16.0.5 dev eth0
```

Or, you can use the setup from _Advanced: Guest network configuration at kernel
level_ by simply changing the G and T variables, i.e. the guest IP and `tap` IP.

**Note:** if you'd like to calculate the guest and `tap` IPs using the
sequential subnet allocation method that has been used here, you can use the
following formulas specific to IPv4 addresses:

`tap` IP = `172.16.[(A*O+1)/256].[(A*O+1)%256]`.

Guest IP = `172.16.[(A*O+2)/256].[(A*O+2)%256]`.

Round down the division and replace `A` with the amount of IP addresses inside
your subnet (for a /30 subnet, that will be 4 addresses, for example) and
replace `O` with the sequential number of your microVM, starting at 0. You can
replace `172.16` with any other values that fit between between 1 and 255 as
usual with an IPv4 address.

For example, let's calculate the addresses of the 1000-th microVM with a /30
subnet in the `172.16.0.0/16` range:

`tap` IP = `172.16.[(4*999+1)/256].[(4*999+1)%256]` = `172.16.15.157`.

Guest IP = `172.16.[(4*999+2)/256].[(4*999+2)%256]` = `172.16.15.158`.

This allocation setup has been used successfully in the `firecracker-demo`
project for launching several thousand microVMs on the same host:
[relevant lines](https://github.com/firecracker-microvm/firecracker-demo/blob/63717c6e7fbd277bdec8e26a5533d53544a760bb/start-firecracker.sh#L45).

## Advanced: Bridge-based routing

### On The Host

1. Create a bridge interface:

   ```bash
   sudo ip link add name br0 type bridge
   ```

1. Add the `tap` device [created above](#on-the-host) to the bridge:

   ```bash
   sudo ip link set dev tap0 master br0
   ```

1. Define an IP address in your network for the bridge:

   For example, if your gateway were on `192.168.1.1` and you wanted to use this
   for getting dynamic IPs, you would want to give the bridge an unused IP
   address in the `192.168.1.0/24` subnet.

   ```bash
   sudo ip address add 192.168.1.7/24 dev br0
   ```

1. Add a firewall rule to allow traffic to be routed to the guest:

   ```bash
   sudo iptables -t nat -A POSTROUTING -o br0 -j MASQUERADE
   ```

1. Once you're cleaning up the configuration, make sure to delete the bridge:

   ```bash
   sudo ip link del br0
   ```

### On The Guest

1. Define an unused IP address in the bridge's subnet e.g., `192.168.1.169/24`.

   **Note**: Alternatively, you could rely on DHCP for getting a dynamic IP
   address from your gateway.

   ```bash
   ip addr add 192.168.1.169/24 dev eth0
   ```

1. Enable the network interface:

   ```bash
   ip link set eth0 up
   ```

1. Create a route to the bridge device

   ```bash
   ip r add 192.168.1.1 via 192.168.1.7 dev eth0
   ```

1. Create a route to the internet via the bridge

   ```bash
   ip r add default via 192.168.1.7 dev eth0
   ```

   When done, your route table should look similar to the following:

   ```bash
   ip r
   default via 192.168.1.7 dev eth0
   192.168.1.0/24 dev eth0 scope link
   192.168.1.1 via 192.168.1.7 dev eth0
   ```

1. Add your nameserver to `/etc/resolve.conf`

   ```bash
   # cat /etc/resolv.conf
   nameserver 192.168.1.1
   ```

## Advanced: Guest network configuration using kernel command line

The Linux kernel supports an `ip` CLI arguments that can be passed to it when
booting. Boot arguments in Firecracker are configured in the `boot_args`
property of the boot source (`boot-source` object in the JSON configuration or
the equivalent endpoint in the API server).

The value of the `ip` CLI argument for our setup will be the of this format:
`G::T:GM::GI:off`. G is the guest IP (without the subnet), T is the `tap` IP
(without the subnet), GM is the "long" mask IP of the guest CIDR and GI is the
name of the guest network interface.

Substituting our values, we get:
`ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off`. Insert this at the end of
your boot arguments for your microVM, and the guest Linux kernel will
automatically perform the routing configuration done in the _In the Guest_
section without needing `iproute2` installed in the guest.

As soon as you boot the guest, it will already be connected to the network
(assuming you correctly performing the other steps).
