# GDB Server Runbook

The GDB server on Firecracker wears the purpose of providing the necessary means for debugging any type of guests running on top of the VMM, without being limited to the kernel version, whether it represents a type of unikernel or simply a Linux kernel.

The current version may only be run on top of microVMs configured with 1 vCPU on a x86 architecture. The behavior is otherwise undefined.

## Server Side

Enabling the debugging process is independent of the way in which the user chooses to configure the microVM for boot and it can be done through a command line option passed to the Firecracker executable: --debugger. Therefore, whether you choose to run:
```
./firecracker --api-sock /tmp/firecracker.socket --config-file <path_to_config_file> --debugger
```
or
```
./firecracker --api-sock /tmp/firecracker.socket --debugger, followed by the specific API requests,
```
you will be greeted by the following prompt:
```
Waiting for a GDB connection on "0.0.0.0:8443"...
```
Now the server waits for a GDB client - found either on the same machine or a remote one - to initiate the communication.

## Client Side

Assuming we are on the same machine, from a different terminal, we can now launch the GDB client, specifying the path to the kernel image file (not stripped) that was used for microVM configuration:

**_ubuntu@host:~$ gdb \<path\_to\_kernel\_image\>_**

In order to attach to the running GDB server session, we use the target remote mode:

**_(gdb) target remote 127.0.0.1:8443_**

In the command line interface, the first command after establishing the connection should be:

**_(gdb) continue_**

At this point, the guest is hanging at the entry point of the executable. Typically, that is, on Linux kernels with default memory layout, the entry point coincides with address 0x1000000.

**The default behavior in an IDE like Eclipse or VSCode is to automatically issue a continue command at the beginning of the session, therefore this last step can be skipped in those environments.**

In this mode, commands like run and attach are not supported. Now you can simply start debugging as you normally would when attached to a user-space process. A list of known supported commands is:
```
(gdb) continue
(gdb) break <address>/<function symbol>
(gdb) clear <address>/<function symbol>
(gdb) next/nexti
(gdb) step/stepi
(gdb) finish
(gdb) info breakpoints
(gdb) info registers
(gdb) backtrace/where
(gdb) x/<count><format><size> <address>
(gdb) print/<format> $<register>
(gdb) disassemble
```
The list is not exhaustive; other commands and variants may be usable as the client performs a great deal of processing on its own based on the data it extracts from the executable and the primitives exposed by the server.

_When using a command which takes an address as argument (e.g., break, clear, examine) you must take into consideration a slight limitation of a kernel in the early boot process: up until the moment when the kernel properly sets up the page tables, it doesn’t have the notion of virtual addresses, therefore, when using/accessing a location in the early stages of the kernel boot, make sure you use a physical address, not a linear/virtual one. This drawback also affects the use of commands like next or finish, and binary-to-sources mapping. These may not properly function before switching the page tables. Generally, on a Linux kernel, this stage is bounded by the setting of the CR3 register, shortly after the call of the \_\_startup\_64 routine. Once execution reaches this point, you will be able to use symbols or virtual addresses._

_A simple way of figuring out the physical address is by looking at the program headers of the kernel image; these can be obtained with the following command:_

**_readelf -l \<path\_to\_kernel\_image>_**

_You will find that obtaining the corresponding physical address only requires subtracting an offset from the linear one. For example, by default, a Linux kernel is loaded at address 0x1000000 (physical), while the virtual address (the one you will see in the binary dump) is 0xffffffff81000000._

_A breakpoint set at a virtual address in the early boot code will be ignored; same applies for breakpoints set at physical addresses later in the boot/execution stages._

Below we are taking a look at an example session showcasing the various aspects of the above-mentioned limitation:

```
(gdb) target remote 127.0.0.1:8443
0x0000000000000000 in ?? ()

(gdb) continue
0x0000000001000000 in ?? ()

# Setting a breakpoint at the physical address corresponding to the __startup_64 function symbol
(gdb) b *0x10001f0
Breakpoint 1 at 0x10001f0

(gdb) next
Cannot find bounds of current function

# Setting a breakpoint at a location right after the page tables have been set up; we must use the virtual address
(gdb) b *0xffffffff8100005d
Breakpoint 2 at 0xffffffff8100005d

# Setting a breakpoint directly at a symbol. This is only possible because boot_cpu_init is called much later in the boot #process
(gdb) b boot_cpu_init
Breakpoint 3 at 0xffffffff81cde9b1

# While in early boot, symbol information will not be available
(gdb) continue
Breakpoint 1, 0x00000000010001f0 in ?? ()

# We passed the border; symbol information becomes available. From this point on, it is safe to use virtual addresses #or symbols only
(gdb) continue
Breakpoint 2, 0xffffffff8100005d in secondary_startup_64 ()

(gdb) continue

Breakpoint 3, 0xffffffff81cde9b1 in boot_cpu_init ()

(gdb) next
0xffffffff8104b8e0 in cpumask_set_cpu ()

(gdb) quit
```

In order to have a binary-to-sources mapping you may use command _directory \<path\_to\_kernel\_sources\>_
