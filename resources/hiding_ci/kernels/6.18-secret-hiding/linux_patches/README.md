# Linux kernel patches for direct map removal

The Linux kernel patches in this directory and its subdirectories are
distributed under the `GPL-2.0` licence (see the full licence text at
[GPL-2.0](./GPL-2.0)). The patches are required by Firecracker's "Secret
Freedom" feature that removes the VM memory from the host direct map (see
[lore](https://lore.kernel.org/kvm/20250221160728.1584559-1-roypat@amazon.co.uk/)
for more details). The patches are not yet merged upstream.

`70-rep-movsb-alias/` is unrelated to secret hiding: it fixes a host kernel
performance bug on AMD Zen 3/Zen 4, where `rep movsb` (and with it every
`copy_from_user()`/`copy_to_user()` on these FSRM CPUs) degrades to one byte per
cycle whenever the destination is 1..15 bytes ahead of the source modulo 4K. The
TCP sender's copy into skb page frags lands in that window for a whole stream at
a time, which makes host-to-guest TCP throughput bimodal on the AMD CI hosts.
The two patches add `X86_BUG_REP_MOVSB_ALIAS` and use `rep movsq` for those
copies on affected CPUs; other CPUs are unchanged.
