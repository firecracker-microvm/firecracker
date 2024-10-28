# Getting Started Firecracker Network Setup

This is a simple quick-start guide to getting one or more Firecracker microVMs
connected to the Internet via the host. If you run a production setup, you should
consider modifying this setup to accommodate your specific needs.

**Note:** Currently, Firecracker supports only a TUN/TAP network backend with no
multi queue support.

The steps in this guide assume `eth0` to be your Internet-facing network interface
on the host. If `eth0` isn't your main network interface, you should change the
value to the correct one in the commands below. IPv4 is also assumed to be used,
check out the _Advanced: IPv6 support_ section as an alternative.

To run multiple microVMs with this approach, check out the
_Advanced: Multiple guests_ section.

The `nftables` Linux firewall with the `nft` command should be used instead of
`iptables`, since `iptables` and the associated tools are
[no longer recommended](https://access.redhat.com/solutions/6739041) for use on
production Linux systems.

## On the Host

The first step on the host for any microVM is to create a Linux `tap` device, which Firecracker
will use for networking.

For this setup, only two IP addresses will be necessary - one for the `tap` device and one for
the guest itself, through which you will, for example, `ssh` into the guest. So, we'll choose the
smallest IPv4 subnet needed for 2 addresses: `/30`. For this VM, let's use the `172.16.0.1` `tap` IP
and the `172.16.0.2` guest IP.

```bash
# Create the tap device.
sudo ip tuntap add tap0 mode tap
# Assign it the tap IP and start up the device.
sudo ip addr add 172.16.0.1/30 dev tap0
sudo ip link set tap0 up
```

We'll use **NAT** for routing packets from the TAP device to `eth0` - you might want to consider
a bridge interface instead in order to connect the guest to your local network (LAN), for which
you can check out the _Advanced: Bridge-based routing_ section.

Firstly, we'll need to enable IPv4 forwarding on the system.
```bash
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
```

Then, we'll need an nftables table for our routing needs, and 2 chains inside that table: one
for NAT on `postrouting` stage, and another one for filtering on `forward` stage:
```bash
sudo nft add table firecracker
sudo nft 'add chain firecracker postrouting { type nat hook postrouting priority srcnat; policy accept; }'
sudo nft 'add chain firecracker filter { type filter hook forward priority filter; policy accept; }'
```

The first rule we'll need will masquerade packets from the guest IP as if they came from the
host's IP, by changing the source IP address of these packets:
```bash
sudo nft add rule firecracker postrouting ip saddr 172.16.0.2 oifname eth0 counter masquerade
```

The second rule we'll need will accept packets from the tap IP (the guest will use the tap IP as its
gateway and will therefore route its own packets through the tap IP) and direct them to the host
network interface:
```bash
sudo nft add rule firecracker filter iifname tap0 oifname eth0 accept
```

*Note:* The IP of the TAP device should be chosen such that it's not in the same
subnet as the IP address of the host.

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
interface and set up the `tap` IP as the guest's gateway address, so that packets
are routed through the `tap` device, where they are then picked up by the setup
on the host prepared before:

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

**Note:** Sometimes, it's undesirable to have `iproute2` (providing the `ip` command)
installed on your guest OS, or you simply want to have these steps be performed
automatically. To do this, check out the
_Advanced: Guest network configuration at kernel level_ section.

## Cleaning up

The first step to cleaning up is deleting the tap device:

```bash
sudo ip link del tap0
```

If you don't have anything else using `iptables` on your machine, clean up those
rules:

```bash
sudo iptables -F
sudo sh -c "echo 0 > /proc/sys/net/ipv4/ip_forward" # usually the default
```

If you have an existing iptables setup, you'll want to be more careful about
cleaning up.

*Advanced:* If you saved your iptables rules in the first step, then you can
restore them like this:

```bash
if [ -f iptables.rules.old ]; then
    sudo iptables-restore < iptables.rules.old
fi
```

*Advanced:* If you created a bridge interface, delete it using the following:

```bash
sudo ip link del br0
```

## Advanced: Bridge-based routing

### On The Host

1. Create a bridge interface

   ```bash
   sudo ip link add name br0 type bridge
   ```

1. Add tap interface [created above](#on-the-host) to the bridge

   ```bash
   sudo ip link set dev tap0 master br0
   ```

1. Define an IP address in your network for the bridge.

   For example, if your gateway were on `192.168.1.1` and you wanted to use this
   for getting dynamic IPs, you would want to give the bridge an unused IP
   address in the `192.168.1.0/24` subnet.

   ```bash
   sudo ip address add 192.168.1.7/24 dev br0
   ```

1. Add firewall rules to allow traffic to be routed to the guest

   ```bash
   sudo iptables -t nat -A POSTROUTING -o br0 -j MASQUERADE
   ```

### On The Guest

1. Define an unused IP address in the bridge's subnet e.g., `192.168.1.169/24`.

   _Note: Alternatively, you could rely on DHCP for getting a dynamic IP address
   from your gateway._

   ```bash
   ip addr add 192.168.1.169/24 dev eth0
   ```

1. Set the interface up.

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

1. Add your nameserver to `resolve.conf`

   ```bash
   # cat /etc/resolv.conf
   nameserver 192.168.1.1
   ```

## Advanced: Guest network configuration at kernel level

**TODO**

## Advanced: IPv6 support

**TODO**

## Advanced: Multiple guests
