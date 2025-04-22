# Linux kernel patches for direct map removal

The Linux kernel patches in this directory are distributed under the `GPL-2.0`
licence (see the full licence text at [GPL-2.0](./GPL-2.0)). The patches are
required by Firecracker's "Secret Freedom" feature that removes the VM memory
from the host direct map (see
[lore](https://lore.kernel.org/kvm/20250221160728.1584559-1-roypat@amazon.co.uk/)
for more details). The patches are not yet merged upstream.
