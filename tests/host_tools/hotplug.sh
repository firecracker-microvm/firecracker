#!/bin/bash
# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

while :; do
  [[ -d /sys/devices/system/cpu/cpu$1 ]] && break
done

for i in $(seq 1 $1); do
  echo 1 >/sys/devices/system/cpu/cpu$i/online
done

while :; do
  [[ $(nproc) == $((1 + $1)) ]] && break
done

/home/hotplug_time.o
