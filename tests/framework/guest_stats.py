# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Classes for querying guest stats inside microVMs.
"""


class ByteUnit:
    """Represents a byte unit that can be converted to other units."""

    value_bytes: int

    def __init__(self, value_bytes: int):
        self.value_bytes = value_bytes

    @classmethod
    def from_kib(cls, value_kib: int):
        """Creates a ByteUnit from a value in KiB."""
        if value_kib < 0:
            raise ValueError("value_kib must be non-negative")
        return ByteUnit(value_kib * 1024)

    def bytes(self) -> int:
        """Returns the value in B."""
        return self.value_bytes

    def kib(self) -> float:
        """Returns the value in KiB as a decimal."""
        return self.value_bytes / 1024

    def mib(self) -> float:
        """Returns the value in MiB as a decimal."""
        return self.value_bytes / (1 << 20)

    def gib(self) -> float:
        """Returns the value in GiB as a decimal."""
        return self.value_bytes / (1 << 30)


class Meminfo:
    """Represents the contents of /proc/meminfo inside the guest"""

    mem_total: ByteUnit
    mem_free: ByteUnit
    mem_available: ByteUnit
    buffers: ByteUnit
    cached: ByteUnit

    def __init__(self):
        self.mem_total = ByteUnit(0)
        self.mem_free = ByteUnit(0)
        self.mem_available = ByteUnit(0)
        self.buffers = ByteUnit(0)
        self.cached = ByteUnit(0)


class MeminfoGuest:
    """Queries /proc/meminfo inside the guest"""

    def __init__(self, vm):
        self.vm = vm

    def get(self) -> Meminfo:
        """Returns the contents of /proc/meminfo inside the guest"""
        meminfo = Meminfo()
        for line in self.vm.ssh.check_output("cat /proc/meminfo").stdout.splitlines():
            parts = line.split()
            if parts[0] == "MemTotal:":
                meminfo.mem_total = ByteUnit.from_kib(int(parts[1]))
            elif parts[0] == "MemFree:":
                meminfo.mem_free = ByteUnit.from_kib(int(parts[1]))
            elif parts[0] == "MemAvailable:":
                meminfo.mem_available = ByteUnit.from_kib(int(parts[1]))
            elif parts[0] == "Buffers:":
                meminfo.buffers = ByteUnit.from_kib(int(parts[1]))
            elif parts[0] == "Cached:":
                meminfo.cached = ByteUnit.from_kib(int(parts[1]))

        return meminfo
