# Device

The Device-API following functionality matrix indicates which devices are
required for an API call to be usable.

**O** - Optional: The device (column) **is not required** for a Firecracker
microVM API call to succeed. If the device (column) is omitted from a uVM
definition, a call to one of the [API Endpoints](#api-endpoints) will succeed.

**R** - Required: The device (column) **is required** for a Firecracker microVM
API call to succeed. If the device (column) is omitted from a uVM definition, a
call to one of the [API Endpoints](#api-endpoints) will fail with a 400 -
BadRequest - HTTP response.

## API Endpoints

| Endpoint                  | keyboard | serial console | virtio-block | vhost-user-block | virtio-net | virtio-vsock | virtio-rng |
| ------------------------- | :------: | :------------: | :----------: | :--------------: | :--------: | :----------: | :--------: |
| `boot-source`             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `cpu-config`              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `drives/{id}`             |    O     |       O        |    **R**     |      **R**       |     O      |      O       |     O      |
| `logger`                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `machine-config`          |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `metrics`                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `mmds`                    |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
| `mmds/config`             |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
| `network-interfaces/{id}` |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
| `snapshot/create`         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `snapshot/load`           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `vm`                      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `vsock`                   |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `entropy`                 |    O     |       O        |      O       |        O         |     O      |      O       |   **R**    |

## Input Schema

All input schema fields can be found in the [Swagger](https://swagger.io)
specification:
[firecracker.yaml](./../src/firecracker/swagger/firecracker.yaml).

| Schema                    | Property              | keyboard | serial console | virtio-block | vhost-user-block | virtio-net | virtio-vsock | virtio-rng |
| ------------------------- | --------------------- | :------: | :------------: | :----------: | :--------------: | :--------: | :----------: | :--------: |
| `BootSource`              | boot_args             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | initrd_path           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | kernel_image_path     |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `CpuConfig`               | cpuid_modifiers       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | msr_modifiers         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | reg_modifiers         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `CpuTemplate`             | enum                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `CreateSnapshotParams`    | mem_file_path         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | snapshot_path         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | snapshot_type         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | version               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `Drive`                   | drive_id \*           |    O     |       O        |    **R**     |      **R**       |     O      |      O       |     O      |
|                           | is_read_only          |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |
|                           | is_root_device \*     |    O     |       O        |    **R**     |      **R**       |     O      |      O       |     O      |
|                           | partuuid \*           |    O     |       O        |    **R**     |      **R**       |     O      |      O       |     O      |
|                           | path_on_host          |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |
|                           | rate_limiter          |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |
|                           | socket                |    O     |       O        |      O       |      **R**       |     O      |      O       |     O      |
| `InstanceActionInfo`      | action_type           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `LoadSnapshotParams`      | enable_diff_snapshots |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | mem_file_path         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | mem_backend           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | snapshot_path         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | resume_vm             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `Logger`                  | level                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | log_path              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | show_level            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | show_log_origin       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `MachineConfiguration`    | cpu_template          |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | smt                   |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | mem_size_mib          |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | track_dirty_pages     |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
|                           | vcpu_count            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `Metrics`                 | metrics_path          |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `MmdsConfig`              | network_interfaces    |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | version               |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | ipv4_address          |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
| `NetworkInterface`        | guest_mac             |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | host_dev_name         |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | iface_id              |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | rx_rate_limiter       |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | tx_rate_limiter       |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
| `PartialDrive`            | drive_id              |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |
|                           | path_on_host          |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |
| `PartialNetworkInterface` | iface_id              |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | rx_rate_limiter       |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | tx_rate_limiter       |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
| `RateLimiter`             | bandwidth             |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | ops                   |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |
| `TokenBucket` \*\*        | one_time_burst        |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |
|                           | refill_time           |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |
|                           | size                  |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |
| `TokenBucket` \*\*        | one_time_burst        |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | refill_time           |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
|                           | size                  |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |
| `Vm`                      | state                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |
| `Vsock`                   | guest_cid             |    O     |       O        |      O       |        O         |     O      |    **R**     |     O      |
|                           | uds_path              |    O     |       O        |      O       |        O         |     O      |    **R**     |     O      |
|                           | vsock_id              |    O     |       O        |      O       |        O         |     O      |    **R**     |     O      |
| `EntropyDevice`           | rate_limiter          |    O     |       O        |      O       |        O         |     O      |      O       |   **R**    |

\* `Drive`'s `drive_id`, `is_root_device` and `partuuid` can be configured by
either virtio-block or vhost-user-block devices.

\*\* The `TokenBucket` can be configured with any combination of virtio-net,
virtio-block and virtio-rng devices.

## Output Schema

All output schema fields can be found in the [Swagger](https://swagger.io)
specification:
[firecracker.yaml](./../src/firecracker/swagger/firecracker.yaml).

| Schema                 | Property          | keyboard | serial console | virtio-block | vhost-user-block | virtio-net | virtio-vsock |
| ---------------------- | ----------------- | :------: | :------------: | :----------: | :--------------: | :--------: | :----------: |
| `Error`                | fault_message     |    O     |       O        |      O       |        O         |     O      |      O       |
| `InstanceInfo`         | app_name          |    O     |       O        |      O       |        O         |     O      |      O       |
|                        | id                |    O     |       O        |      O       |        O         |     O      |      O       |
|                        | state             |    O     |       O        |      O       |        O         |     O      |      O       |
|                        | vmm_version       |    O     |       O        |      O       |        O         |     O      |      O       |
| `MachineConfiguration` | cpu_template      |    O     |       O        |      O       |        O         |     O      |      O       |
|                        | smt               |    O     |       O        |      O       |        O         |     O      |      O       |
|                        | mem_size_mib      |    O     |       O        |      O       |        O         |     O      |      O       |
|                        | track_dirty_pages |    O     |       O        |      O       |        O         |     O      |      O       |
|                        | vcpu_count        |    O     |       O        |      O       |        O         |     O      |      O       |

## Known device limitations

If more than 64 devices are configured for a VM in total on aarch64, only first
64 of them are functional
([related issue](https://github.com/firecracker-microvm/firecracker/issues/4207)).

## Instance Actions

All instance actions can be found in the [Swagger](https://swagger.io)
specification:
[firecracker.yaml](./../src/firecracker/swagger/firecracker.yaml).

| Action           | keyboard | serial console | virtio-block | vhost-user-block | virtio-net | virtio-vsock |
| ---------------- | :------: | :------------: | :----------: | :--------------: | :--------: | :----------: |
| `FlushMetrics`   |    O     |       O        |      O       |        O         |     O      |      O       |
| `InstanceStart`  |    O     |       O        |      O       |        O         |     O      |      O       |
| `SendCtrlAltDel` |  **R**   |       O        |      O       |        O         |     O      |      O       |
