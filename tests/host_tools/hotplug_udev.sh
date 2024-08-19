#!/bin/bash
# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

while :; do
  [[ $(nproc) == $((1 + $1)) ]] && break
done

/home/hotplug_time.o
