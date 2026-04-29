# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Guest distro detection and distro-specific properties."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GuestDistro:
    """Distro-specific guest properties, inferred from rootfs filename."""

    hostname: str
    ssh_service: str
    os_release_token: str
    shell_prompt: str

    @classmethod
    def from_rootfs(cls, rootfs_path: Path) -> "GuestDistro":
        """Return a guest distro object based on the rootfs name"""
        name = rootfs_path.stem.lower()
        if "ubuntu" in name:
            hostname = "ubuntu-fc-uvm"
            return cls(
                hostname=hostname,
                ssh_service="ssh.service",
                os_release_token="ID=ubuntu",
                shell_prompt=f"{hostname}:~#",
            )
        if "amazon" in name or "al2023" in name:
            hostname = "al2023-fc-uvm"
            return cls(
                hostname=hostname,
                ssh_service="sshd.service",
                os_release_token='ID="amzn"',
                shell_prompt=f"[root@{hostname} ~]#",
            )
        raise ValueError(f"Unknown guest distro for rootfs: {rootfs_path}")
