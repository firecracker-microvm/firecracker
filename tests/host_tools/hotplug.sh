#!/bin/bash
# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

while :; do
  [[ -d /sys/devices/system/cpu/cpu1 ]] && break
done

readarray -t offline_cpus < <(lscpu -p=cpu --offline | sed '/^#/d')

for cpu_idx in ${offline_cpus[@]}; do
  echo 1 | tee cpu*/online
done

/home/hotplug_time.o
