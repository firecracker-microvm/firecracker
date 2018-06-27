# Firecracker Frequently Asked Questions

## Troubleshooting

`Q1:`
*I tried using an initrd for boot but it doesn't seem to be used for the boot.
Is initrd supported?*  
`A1:`
Right now initrd is not supported in Firecracker. You can track the
[#228](https://github.com/aws/PRIVATE-firecracker/issues/208) issue.

`Q2:`
*Firecracker is not showing any output on the console.*  
`A2:`
In order to debug the issue, you will first have to check the output of the GET
request on Instance Start. You can find examples in
[README.md](https://github.com/aws/PRIVATE-firecracker/blob/master/README.md) in
the "Power-On the MicroVM" section. If the result of the GET is:  

- **Error**: Submit a new issue with the label "Support: Failure".
- **Success**: If the boot was successful, you should see an output like
  `{"action_id":"start","action_type":"InstanceStart","timestamp":0}`.

If you have no output in the console, most likely you will have to update the
kernel command line. By default, Firecracker starts with the serial console
disabled for boot time performance reasons. Example of a kernel valid command
line that enables the serial console:
`console=ttyS0 noapic reboot=k panic=1 pci=off nomodules`, which goes in the
`boot_args` field of the `/boot-source` Firecracker API resource.

`Q3:`
*How can we pass multiple Ethernet devices through kernel command line?*  
`A3:`
The "ip=" boot param in the linux kernel only actually supports configuring a
single interface. Multiple interfaces can be set up in Firecracker using the
API, but guest IP configuration at boot time through boot arguments can only be
done for a single interface.

`Q4:`
*Each Firecracker opens 20+ file descriptors. Is this an issue?*  
`A4:`
The relatively high FD usage is expected and correct. Firecracker heavily relies
on event file descriptors to drive device emulation. There is nothing you as a
Firecracker user can do to reduce the number of used file descriptors.

`Q5:`
*We are trying to create two network interfaces, `eth0` and `eth1` by calling
`/network-interfaces/0` and `/network-interfaces/1`. In our script, we would
bring up interface `eth0` before `eth1`. Then both interfaces would be created
with the correct MAC addresses. But if we swap the ordering of the calls by
first calling `/network-interfaces/1` and then `/network-interfaces/0`, the MAC
addresses of `eth0` and `eth1` will be swapped. Is this expected behavior?
Should we always setup the eth device in the same order the network-interface
API is called?*  
`A5:`
The `0` and `1` in the `/network-interface` path are the API identifiers of the
network-interface HTTP resources. For now these are only used for resource
management in the API and have nothing to do with `eth0` and `eth1`. The id that
you pass through the API call path is used for example to separate an update of
an existing network-interface from creating a new interface. In short, this is
expected behavior and the ids from the path are not exactly tied to the ids of
the actual network interfaces.
