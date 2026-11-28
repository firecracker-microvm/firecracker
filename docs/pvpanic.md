# Guest panic reporting with pvpanic

Firecracker provides an optional MMIO pvpanic device on KVM microVMs. It
implements the register interface described by the
[QEMU pvpanic specification](https://www.qemu.org/docs/master/specs/pvpanic.html),
allowing a guest driver to report a kernel panic to the host. The device is not
supported on Nitro Enclaves.

## Configuration

Enable the device before boot with `PUT /pvpanic`:

```sh
curl --unix-socket /tmp/firecracker.socket -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"panic_action":"pause"}' http://localhost/pvpanic
```

The supported `panic_action` values are:

| Action  | Behavior on a reported panic                      |
| ------- | ------------------------------------------------- |
| `none`  | Report the panic without pausing guest execution. |
| `pause` | Report the panic and pause the microVM.           |

An empty object `{}` enables the device with `none`. This action does **not**
disable the device. Only the lowercase strings `none` and `pause` are accepted;
unknown fields, non-object configurations and null actions are rejected.

For configuration-file boot, add the following entry to the full microVM JSON:

```json
{
  "pvpanic": {"panic_action": "pause"}
}
```

Omitting `pvpanic`, or setting it to `null` in the full configuration, leaves
the device disabled. Repeated pre-boot PUT requests replace the configuration.
`PUT /pvpanic` is rejected after boot or successful snapshot load, including
while the microVM is paused. There is no runtime action update, hotplug or
DELETE operation. `GET /vm/config` reports `pvpanic: null` when disabled and the
effective action object when enabled.

## Guest requirements and discovery

Linux introduced pvpanic support in 3.10. To use Firecracker's MMIO device, the
guest needs an MMIO-capable driver. Configure kernels with that driver as
follows:

- Before the 5.13 driver split: `CONFIG_PVPANIC=y`.
- From 5.13: `CONFIG_PVPANIC=y` and `CONFIG_PVPANIC_MMIO=y`.

The driver can also be built as a module, which must be loaded before expecting
panic reports. Vendor kernels may backport changes; check the actual driver and
configuration rather than relying only on the version number.

On x86_64, discovery requires guest ACPI support: Firecracker exposes `QEMU0001`
with an MMIO resource. On aarch64, discovery uses the FDT compatible string
`qemu,pvpanic-mmio`. The MMIO address is allocated dynamically when the device
is enabled.

## Host notification and pause behavior

The first `PANICKED` event successfully signaled to the VMM produces one
`Guest kernel panicked` warning, sets `vmm.guest_panic_count` to 1 and attempts
to flush metrics. Configure a [metrics output](metrics.md) to receive that
metric. It is a 0/1 latch, not a cumulative panic count, and metrics
serialization does not reset it. Further `PANICKED` writes to that device
instance are ignored. A failed eventfd notification does not consume the
allowance or request a pause.

Firecracker logs `CRASH_LOADED` without setting the panic metric or pausing the
guest, regardless of the configured action. This event does not consume the
`PANICKED` reporting allowance. If a write contains both known panic bits,
`PANICKED` takes precedence.

For `pause`, the panicking vCPU completes its MMIO access and requests a
self-pause; the eventfd notifies the VMM to coordinate pausing all vCPUs. The
VMM marks the microVM Paused after the vCPU pause operation succeeds. A pause
failure stops the microVM. The handoff is asynchronous: this does not atomically
freeze all vCPUs and I/O at the instant the register is written.

In API mode, after the current event batch completes, the main loop serves API
requests while paused instead of polling device and periodic metrics events.
This does not guarantee that all background I/O workers stop atomically.
`GET /`, `GET /vm/config`, `FlushMetrics`, snapshot creation and Resume remain
available. An orchestrator can observe the metric, confirm the Paused state, and
request a [snapshot](snapshotting/snapshot-support.md#creating-snapshots).
Firecracker does not automatically write a dump or snapshot on panic.

In `--no-api` mode, a panic-induced pause parks the main loop and leaves the
Firecracker process alive. There is no API Resume or snapshot creation endpoint
in that mode; an external supervisor must terminate the process when
appropriate.

## Snapshot restore

The snapshot stores the configured action and MMIO resources. Restore reuses the
saved MMIO resources, creates a new notification eventfd and rearms panic
reporting; it does not reboot the guest or reset a same-process
`guest_panic_count` latch.

By default, `PUT /snapshot/load` preserves the saved action. To replace it, add
an optional override to the load request:

```json
{
  "snapshot_path": "/snapshot",
  "mem_backend": {"backend_type": "File", "backend_path": "/memory"},
  "resume_vm": false,
  "pvpanic_override": {"panic_action": "none"}
}
```

Omitting `pvpanic_override`, or providing `null`, preserves the saved action.
The override must be an object with an explicit `panic_action`; `{}` is invalid.
It changes only an existing device's action and is rejected with HTTP 400 if the
snapshot has no pvpanic device. It cannot create or remove a device.

The action is replaced before device restoration and guest execution, including
when `resume_vm` is true. The original snapshot file is unchanged. A
subsequently created snapshot saves the effective action. `GET /vm/config`
reports that action after load, and pre-boot PUT configuration is no longer
allowed even when the restored microVM has not yet resumed.
