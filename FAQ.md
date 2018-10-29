# Firecracker Frequently Asked Questions

## Troubleshooting

`Q1:`
*I tried using an initrd for boot but it doesn't seem to be used.
Is initrd supported?*  
`A1:`
Right now initrd is not supported in Firecracker. You can track issue
[#228](https://github.com/aws/PRIVATE-firecracker/issues/208).

`Q2:`
*Firecracker is not showing any output on the console.*  
`A2:`
In order to debug the issue, you will first have to check the response of the
`InstanceStart` API request. You can find examples in
[README.md](https://github.com/aws/PRIVATE-firecracker/blob/master/README.md)
in the "Power-On the MicroVM" section. If the result is:

- **Error**: Submit a new issue with the label "Support: Failure".
- **Success**: If the boot was successful, you should get a response with 204
  as the status code.

  If you have no output in the console, most likely you will have to update the
  kernel command line. By default, Firecracker starts with the serial console
  disabled for boot time performance reasons. Example of a kernel valid command
  line that enables the serial console:
  `console=ttyS0 reboot=k panic=1 pci=off nomodules`, which goes in the
  `boot_args` field of the `/boot-source` Firecracker API resource.

`Q3:`
*How can we configure multiple Ethernet devices through the kernel command
line?*  
`A3:`
The `ip=` boot param in the linux kernel only actually supports configuring a
single interface. Multiple interfaces can be set up in Firecracker using the
API, but guest IP configuration at boot time through boot arguments can only be
done for a single interface.

`Q4:`
*Each Firecracker opens 20+ file descriptors. Is this an issue?*  
`A4:`
The relatively high FD usage is expected and correct. Firecracker heavily
relies on event file descriptors to drive device emulation.

`Q5:`
*We are trying to create two network interfaces, `eth0` and `eth1` by calling
`/network-interfaces/0` and `/network-interfaces/1`. In our script, we would
bring up interface `eth0` before `eth1`. Then both interfaces would be created
with the correct MAC addresses. But if we swap the ordering of the calls by
first calling `/network-interfaces/1` and then `/network-interfaces/0`, the MAC
addresses of `eth0` and `eth1` will be swapped. Is this expected behavior?
Should we always setup the `eth` device in the same order the network-interface
API is called?*  
`A5:`
The `0` and `1` in the `/network-interfaces` path are the API identifiers of
the `network-interfaces` HTTP resources. For now these are only used for
resource management in the API and have nothing to do with `eth0` and `eth1`.
The id that you pass through the API call path is used for example to separate
an update of an existing network interface from creating a new interface. In
short, this is expected behavior and the ids from the path are not tied to the
ids of the actual network interfaces.

`Q6`:
*We are seeing page allocation failures from Firecracker in the `dmesg` output.
Example:*
```
[80427.988646] fc_vmm: page allocation failure: order:6, mode:0x140c0c0
(GFP_KERNEL|__GFP_COMP|__GFP_ZERO), nodemask=(null)
[80427.989567] fc_vmm cpuset=27d8fd00-a29a-4745-b518-e6a4e6cd69dd mems_allowed=0
```
`A6`:
The host is running out of memory. KVM is attempting to do an allocation of
2^`order` bytes (in this case, 6) and there aren't sufficient contiguous pages.
Possible mitigations are:
- Track the failing allocations in the `dmesg` output and rebuild the host
  kernel so as to use `vmalloc` instead of `kmalloc` for them.
- Reduce memory pressure on the host.
