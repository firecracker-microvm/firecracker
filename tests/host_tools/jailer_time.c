// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This is used by `performance/test_jailer.py`

#include <stdio.h>
#include <time.h>

int main(int argc, char** argv) {
  // print current time in us
  struct timespec now = {0};
  clock_gettime(CLOCK_MONOTONIC, &now);
  unsigned long long current_ns = (unsigned long long)now.tv_sec * 1000000000 + (unsigned long long)now.tv_nsec;
  unsigned long long current_us = current_ns / 1000;
  printf("%llu\n", current_us);

  // print the --start-time-us value
  printf("%s", argv[4]);
}
