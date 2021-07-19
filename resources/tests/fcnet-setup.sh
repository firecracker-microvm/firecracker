#!/usr/bin/env bash

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This script assigns IP addresses to the existing
# virtual networking devices based on their MAC address.
# It is a simple solution on which Firecracker's integration
# tests are based. Each network device attached in a test will
# assign the next available MAC.
# The IP is obtained by converting the last 4 hexa groups of the MAC into decimals.

main() {
    devs=$(ls /sys/class/net | grep -v lo)
    for dev in $devs; do
        mac_ip=$(ip link show dev $dev \
            | grep link/ether \
            | grep -Po "(?<=06:00:)([0-9a-f]{2}:?){4}"
        )
        ip=$(printf "%d.%d.%d.%d" $(echo "0x${mac_ip}" | sed "s/:/ 0x/g"))
        ip addr add "$ip/30" dev $dev
        ip link set $dev up
    done
}
main
