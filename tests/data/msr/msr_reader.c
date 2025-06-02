// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Helper script used to read MSR values from ranges known to contain MSRs.

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

void print_msr(int msr_fd, uint64_t msr) {
  uint64_t value;
  if (pread(msr_fd, &value, sizeof(value), msr) == sizeof(value))
    printf("0x%llx,0x%llx\n", msr, value);
}

int main() {
  int msr_fd = open("/dev/cpu/0/msr", O_RDONLY);
  if (msr_fd < 0)
    return -1;

  printf("MSR_ADDR,VALUE\n");
  for (uint64_t msr = 0; msr <= 0xFFF; msr++)
    print_msr(msr_fd, msr);
  for (uint64_t msr = 0x10000; msr <= 0x10FFF; msr++)
    print_msr(msr_fd, msr);
  for (uint64_t msr = 0xC0000000; msr <= 0xC0011030; msr++)
    print_msr(msr_fd, msr);

  print_msr(msr_fd, 0x400000000);
  print_msr(msr_fd, 0x2000000000);
  print_msr(msr_fd, 0x4000000000);
  print_msr(msr_fd, 0x8000000000);
  print_msr(msr_fd, 0x1000000000000);
  print_msr(msr_fd, 0x3c000000000000);
  print_msr(msr_fd, 0x80000000000000);
  print_msr(msr_fd, 0x40000000000000);
}
