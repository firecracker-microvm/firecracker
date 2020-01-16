# Getting Started Firecracker Network Setup

This is a very simple quick-start guide to getting a Firecracker guest connected
to the network. If you're using Firecracker in production, or even want to run
multiple guests, you'll need to adapt this setup.

The simple steps in this guide assume that your internet-facing interface is
`eth0`, you have nothing else using `tap0` and no other `iptables` rules.
Check out the *Advanced:* sections if that doesn't work for you.

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

*Advanced:* If you are running multiple Firecracker MicroVMs in parallel, or
have something else on your system using `tap0` then you need to create a `tap`
for each one, with a unique name.

*Advanced:* You also need to do the `iptables` set up for each new `tap`. If
you have `iptables` rules you care about on your host, you may want to save
those rules before starting.

```bash
sudo iptables-save > iptables.rules.old
```

## Setting Up Firecracker

Before starting the guest, configure the network interface using Firecracker's
API:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
  -X PUT 'http://localhost/network-interfaces/eth0' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
      "iface_id": "eth0",
      "guest_mac": "AA:FC:00:00:00:01",
      "host_dev_name": "tap0"
    }'
```

Alternatively, if you are using firectl, add
--tap-device=tap0/AA:FC:00:00:00:01` to your command line.

## In The Guest

Once you have booted the guest, bring up networking within the guest:

```bash
ip addr add 172.16.0.2/24 dev eth0
ip link set eth0 up
ip route add default via 172.16.0.1 dev eth0
```

Now your guest should be able to route traffic to the internet (assuming that
your host can get to the internet).

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
