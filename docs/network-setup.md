# Getting Started Firecracker Network Setup

This is a very simple quick-start guide to getting a Firecracker guest connected
to the network. If you're using Firecracker in production, or even want to run
multiple guests, you'll need to adapt this setup.

**Note** Currently firecracker supports only TUN/TAP network backend with no
multi queue support.

The simple steps in this guide assume that your internet-facing interface is
`eth0`, you have nothing else using `tap0` and no other `iptables` rules. Check
out the *Advanced:* sections if that doesn't work for you.

## On The Host

The first step on the host is to create a `tap` device:

```bash
sudo ip tuntap add tap0 mode tap
```

Then you have a few options for routing traffic out of the tap device, through
your host's network interface. One option is NAT, set up like this:

```bash
sudo ip addr add 172.16.0.1/24 dev tap0
sudo ip link set tap0 up
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i tap0 -o eth0 -j ACCEPT
```

*Note:* The IP of the TAP device should be chosen such that it's not in the same
subnet as the IP address of the host.

*Advanced:* If you are running multiple Firecracker MicroVMs in parallel, or
have something else on your system using `tap0` then you need to create a `tap`
for each one, with a unique name.

*Advanced:* You also need to do the `iptables` set up for each new `tap`. If you
have `iptables` rules you care about on your host, you may want to save those
rules before starting.

```bash
sudo iptables-save > iptables.rules.old
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
--tap-device=tap0/06:00:AC:10:00:02\` to your command line.

## In The Guest

Once you have booted the guest, bring up networking within the guest:

```bash
ip addr add 172.16.0.2/24 dev eth0
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

## \[Advanced\] Setting Up a Bridge Interface

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
