### DISCLAIMER

Please keep this document in mind when using these guest kernel configuration
files.

Firecracker as a virtual machine monitor is designed and built for use with
specific goals, so these kernel configurations are tuned to be secure and to use
the host's resources as optimally as possible, specifically allowing for as many
guests to be running concurrently as possible (high density).

For example, one of the mechanisms to improve density is to reduce virtual
memory areas of the guest. This decreases the page table size and improves
available memory on the host for other guests to occupy. As Firecracker is
intended for ephemeral compute (short-lived environments, not intended to run
indefinitely), a Firecracker guest is not expected to require large memory
sizes.

One interesting use-case where this can be seen to cause odd side affects is one
where golang's race detector for aarch64 expected a 48-bit space, but the
guest's kernel config enforced 39-bit. See
[Firecracker issue #3514](https://github.com/firecracker-microvm/firecracker/issues/3514).
