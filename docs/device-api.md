# Device-API Functionality

The Device-API following functionality matrix indicates which devices are
required for an API call to be usable.

**O** - Optional: The device (column) **is not required** for a Firecracker
microVM API call to succeed. If the device (column) is omitted from a uVM
definition, a call to one of the [API Endpoints](#api-endpoints) will succeed.

**R** - Required: The device (column) **is required** for a Firecracker microVM
API call to succeed. If the device (column) is omitted from a uVM definition,
a call to one of the [API Endpoints](#api-endpoints) will return a result that
depends on the device (see [issue #2173](https://github.com/firecracker-microvm/firecracker/issues/2173)).

- API calls related to `drives/{id}` result in 400 - BadRequest - HTTP response
  if the block device identified by `id` was not previously configured.
- API calls related to `network-interfaces/{id}` result in 400 - BadRequest -
  HTTP response if the network device identified by `id` was not previously
  configured.

## API Endpoints

| Endpoint                  | keyboard | serial console | virtio-block |   virtio-net   | virtio-vsock |
| ------------------------- | :------: | :------------: | :----------: | :------------: | :----------: |
| `boot-source`             |    O     |       O        |      O       |       O        |      O       |
| `drives/{id}`             |    O     |       O        |    **R**     |       O        |      O       |
| `logger`                  |    O     |       O        |      O       |       O        |      O       |
| `machine-config`          |    O     |       O        |      O       |       O        |      O       |
| `metrics`                 |    O     |       O        |      O       |       O        |      O       |
| `mmds`                    |    O     |       O        |      O       |     **R**      |      O       |
| `mmds/config`             |    O     |       O        |      O       | O<sup>\*</sup> |      O       |
| `network-interfaces/{id}` |    O     |       O        |      O       |     **R**      |      O       |
| `snapshot/create`         |    O     |       O        |      O       |       O        |      O       |
| `snapshot/load`           |    O     |       O        |      O       |       O        |      O       |
| `vm`                      |    O     |       O        |      O       |       O        |      O       |
| `vsock`                   |    O     |       O        |      O       |       O        |      O       |

<sup>\*</sup>: See [issue #2174](https://github.com/firecracker-microvm/firecracker/issues/2174)

## Input Schema

All input schema fields can be found in the [Swagger](https://swagger.io)
specification: [firecracker.yaml](./../src/api_server/swagger/firecracker.yaml).

| Schema                     | Property              | keyboard | serial console | virtio-block | virtio-net | virtio-vsock |
| -------------------------- | --------------------- | :------: | :------------: | :----------: | :--------: | :----------: |
| `BootSource`               | boot_args             |    O     |       O        |      O       |     O      |      O       |
|                            | initrd_path           |    O     |       O        |      O       |     O      |      O       |
|                            | kernel_image_path     |    O     |       O        |      O       |     O      |      O       |
| `CpuTemplate`              | enum                  |    O     |       O        |      O       |     O      |      O       |
| `CreateSnapshotParams`     | mem_file_path         |    O     |       O        |      O       |     O      |      O       |
|                            | snapshot_path         |    O     |       O        |      O       |     O      |      O       |
|                            | snapshot_type         |    O     |       O        |      O       |     O      |      O       |
|                            | version               |    O     |       O        |      O       |     O      |      O       |
| `Drive`                    | drive_id              |    O     |       O        |    **R**     |     O      |      O       |
|                            | is_read_only          |    O     |       O        |    **R**     |     O      |      O       |
|                            | is_root_device        |    O     |       O        |    **R**     |     O      |      O       |
|                            | partuuid              |    O     |       O        |    **R**     |     O      |      O       |
|                            | path_on_host          |    O     |       O        |    **R**     |     O      |      O       |
|                            | rate_limiter          |    O     |       O        |    **R**     |     O      |      O       |
| `InstanceActionInfo`       | action_type           |    O     |       O        |      O       |     O      |      O       |
| `LoadSnapshotParams`       | enable_diff_snapshots |    O     |       O        |      O       |     O      |      O       |
|                            | mem_file_path         |    O     |       O        |      O       |     O      |      O       |
|                            | snapshot_path         |    O     |       O        |      O       |     O      |      O       |
| `Logger`                   | level                 |    O     |       O        |      O       |     O      |      O       |
|                            | log_path              |    O     |       O        |      O       |     O      |      O       |
|                            | show_level            |    O     |       O        |      O       |     O      |      O       |
|                            | show_log_origin       |    O     |       O        |      O       |     O      |      O       |
| `MachineConfiguration`     | cpu_template          |    O     |       O        |      O       |     O      |      O       |
|                            | ht_enabled            |    O     |       O        |      O       |     O      |      O       |
|                            | mem_size_mib          |    O     |       O        |      O       |     O      |      O       |
|                            | track_dirty_pages     |    O     |       O        |      O       |     O      |      O       |
|                            | vcpu_count            |    O     |       O        |      O       |     O      |      O       |
| `Metrics`                  | metrics_path          |    O     |       O        |      O       |     O      |      O       |
| `MmdsConfig`               | ipv4_address          |    O     |       O        |      O       |   **R**    |      O       |
| `NetworkInterface`         | allow_mmds_requests   |    O     |       O        |      O       |   **R**    |      O       |
|                            | guest_mac             |    O     |       O        |      O       |   **R**    |      O       |
|                            | host_dev_name         |    O     |       O        |      O       |   **R**    |      O       |
|                            | iface_id              |    O     |       O        |      O       |   **R**    |      O       |
|                            | rx_rate_limiter       |    O     |       O        |      O       |   **R**    |      O       |
|                            | tx_rate_limiter       |    O     |       O        |      O       |   **R**    |      O       |
| `PartialDrive`             | drive_id              |    O     |       O        |    **R**     |     O      |      O       |
|                            | path_on_host          |    O     |       O        |    **R**     |     O      |      O       |
| `PartialNetworkInterface`  | iface_id              |    O     |       O        |      O       |   **R**    |      O       |
|                            | rx_rate_limiter       |    O     |       O        |      O       |   **R**    |      O       |
|                            | tx_rate_limiter       |    O     |       O        |      O       |   **R**    |      O       |
| `RateLimiter`              | bandwidth             |    O     |       O        |      O       |   **R**    |      O       |
|                            | ops                   |    O     |       O        |    **R**     |     O      |      O       |
| `TokenBucket`<sup>\*</sup> | one_time_burst        |    O     |       O        |    **R**     |     O      |      O       |
|                            | refill_time           |    O     |       O        |    **R**     |     O      |      O       |
|                            | size                  |    O     |       O        |    **R**     |     O      |      O       |
| `TokenBucket`<sup>\*</sup> | one_time_burst        |    O     |       O        |      O       |   **R**    |      O       |
|                            | refill_time           |    O     |       O        |      O       |   **R**    |      O       |
|                            | size                  |    O     |       O        |      O       |   **R**    |      O       |
| `Vm`                       | state                 |    O     |       O        |      O       |     O      |      O       |
| `Vsock`                    | guest_cid             |    O     |       O        |      O       |     O      |    **R**     |
|                            | uds_path              |    O     |       O        |      O       |     O      |    **R**     |
|                            | vsock_id              |    O     |       O        |      O       |     O      |    **R**     |

<sup>\*</sup>: The `TokenBucket` can be configured with either the virtio-net or virtio-block drivers, or both.

## Output Schema

All output schema fields can be found in the [Swagger](https://swagger.io)
specification: [firecracker.yaml](./../src/api_server/swagger/firecracker.yaml).

| Schema                 | Property          | keyboard | serial console | virtio-block | virtio-net | virtio-vsock |
| ---------------------- | ----------------- | :------: | :------------: | :----------: | :--------: | :----------: |
| `Error`                | fault_message     |    O     |       O        |      O       |     O      |      O       |
| `InstanceInfo`         | app_name          |    O     |       O        |      O       |     O      |      O       |
|                        | id                |    O     |       O        |      O       |     O      |      O       |
|                        | state             |    O     |       O        |      O       |     O      |      O       |
|                        | vmm_version       |    O     |       O        |      O       |     O      |      O       |
| `MachineConfiguration` | cpu_template      |    O     |       O        |      O       |     O      |      O       |
|                        | ht_enabled        |    O     |       O        |      O       |     O      |      O       |
|                        | mem_size_mib      |    O     |       O        |      O       |     O      |      O       |
|                        | track_dirty_pages |    O     |       O        |      O       |     O      |      O       |
|                        | vcpu_count        |    O     |       O        |      O       |     O      |      O       |

## Instance Actions

All instance actions can be found in the [Swagger](https://swagger.io)
specification: [firecracker.yaml](./../src/api_server/swagger/firecracker.yaml).

| Action           | keyboard | serial console | virtio-block | virtio-net | virtio-vsock |
| ---------------- | :------: | :------------: | :----------: | :--------: | :----------: |
| `FlushMetrics`   |    O     |       O        |      O       |     O      |      O       |
| `InstanceStart`  |    O     |       O        |      O       |     O      |      O       |
| `SendCtrlAltDel` |  **R**   |       O        |      O       |     O      |      O       |
