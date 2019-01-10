# Getting Started Firecracker Network Setup

This is a very simple quick-start guide to getting a Firecracker guest connected to the network. If you're using Firecracker in production, or even want to run multiple guests, you'll need to adapt this setup.

## On The Host

The first step on the host is to create a `tap` device:

```bash
sudo ip tuntap add tap0 mode tap
```

Then you have a few options for routing traffic out of the tap device, through your host's network interface. One option is NAT, set up like this:

```bash
DEV=eth0
sudo ip addr add 169.254.0.1/24 dev tap0
sudo ip link set tap0 up
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -t nat -A POSTROUTING -o $DEV -j MASQUERADE
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i tap0 -o $DEV -j ACCEPT
```

## Setting Up Firecracker

Before starting the guest, configure the network interface using Firecracker's API:

```bash
curl -X PUT \
  --unix-socket /tmp/firecracker.socket \
  http://localhost/network-interfaces/eth0 \
  -H accept:application/json \
  -H content-type:application/json \
  -d '{
    "iface_id": "eth0",
    "guest_mac": "AA:FC:00:00:00:01",
    "host_dev_name": "tap0"
}'
```

Alternatively, if you are using firectl, add `--tap-device=veth0/AA:FC:00:00:00:01` to your command line.

## In The Guest

Once you have booted the guest, bring up networking within the guest:

```bash
ip addr add 169.254.0.2/24 dev eth0
ip route add default via 169.254.0.1 dev eth0
```

Now your guest should be able to route traffic to the internet (assuming that your host can get to the internet).

## Cleaning up

The first step to cleaning up is deleting the tap device:

```bash
sudo ip link del tap0
```

If you don't have anything else using `iptables` on your machine, clean up those rules:

```bash
sudo iptables -F
sudo sh -c "echo 0 > /proc/sys/net/ipv4/ip_forward" # usually the default
```

If you have an existing iptables setup, you'll want to be more careful about cleaning up.

