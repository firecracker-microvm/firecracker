# Actions API Request

Firecracker microVMs can execute actions that can be triggered via `PUT`
requests on the `/actions` resource.

Details about the required fields can be found in the
[swagger definition](../../src/api_server/swagger/firecracker.yaml).

## InstanceStart

The `InstanceStart` action powers on the microVM and starts the guest OS. It
does not have a payload. It can only be successfully called once.

### InstanceStart Example

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/actions" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"action_type\": \"InstanceStart\"
         }"
```

## FlushMetrics

The `FlushMetrics` action flushes the metrics on user demand.

### FlushMetrics Example

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/actions" \
    -H  "accept: application/json" \
    -H  "Content-Type: application/json" \
    -d "{
             \"action_type\": \"FlushMetrics\"
    }"
```

## SendCtrlAltDel

This action will send the CTRL+ALT+DEL key sequence to the microVM. By
convention, this sequence has been used to trigger a soft reboot and, as such,
most Linux distributions perform an orderly shutdown and reset upon receiving
this keyboard input. Since Firecracker exits on CPU reset, `SendCtrlAltDel`
can be used to trigger a clean shutdown of the microVM.

For this action, Firecracker emulates a standard AT keyboard, connected via an
i8042 controller. Driver support for both these devices needs to be present in
the guest OS. For Linux, that means the guest kernel needs
`CONFIG_SERIO_I8042` and `CONFIG_KEYBOARD_ATKBD`.

**Note1**: at boot time, the Linux driver for i8042 spends
a few tens of milliseconds probing the device. This can be disabled by using
these kernel command line parameters:

```i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd```

**Note2** This action is only supported on `x86_64` architecture.

### SendCtrlAltDel Example

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/actions" \
    -H  "accept: application/json" \
    -H  "Content-Type: application/json" \
    -d "{
             \"action_type\": \"SendCtrlAltDel\"
    }"
```

## PressGPIOPowerOff

This action will inject GPIO Pin 3 keypress to the microvm. With specified configuration,
gpio-keys driver could generate `KEY_POWER` button event based on this gpio changes.
If udev rules(`70-power-switch.rules`) add the `power-switch` tag to the selected device,
then when a `KEY_POWER` keypress is received, systemd-logind will initiate a shutdown in
guest os. Since Firecracker exits on CPU reset, `PressGPIOPowerOff` can be used to trigger
a clean shutdown of the microVM.

For this action, Firecracker adds an emulated GPIO Pl061 controller and gpio-keys node
in microvm.
Driver support for both these devices needs to be present in the guest OS. For Linux,
that means the guest kernel needs `CONFIG_GPIO_PL061`, `CONFIG_KEYBOARD_GPIO` and
`CONFIG_KEYBOARD_GPIO_POLLED`.

**Note1**: we must check `/lib/udev/rules.d/70-power-switch.rules` in the
fs and add one following line in it if it doesn't exist.

```bash
SUBSYSTEM=="input", KERNEL=="event*", SUBSYSTEMS=="platform", ATTRS{keys}=="116",
TAG+="power-switch"
```

**Note2** This action is only supported on `aarch64` architecture.

### PressGPIOPowerOff Example

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/actions" \
    -H  "accept: application/json" \
    -H  "Content-Type: application/json" \
    -d "{
             \"action_type\": \"PressGPIOPowerOff\"
    }"
```
