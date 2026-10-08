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

The matrix covers device requirements only. A
[Nitro Sandbox](nitro-sandboxes/README.md) also rejects some endpoints and
fields whatever devices it has, for example hot-unplug (a `DELETE` with
`UnplugParams`) and `pcie_hotplug_ports`. For what a sandbox supports, see
[Feature support](nitro-sandboxes/comparison-with-kvm.md#feature-support).

## API Endpoints

| Endpoint                  | keyboard | serial console | virtio-block | vhost-user-block | virtio-net | virtio-vsock | virtio-rng | virtio-pmem | virtio-mem | virtio-balloon |
| ------------------------- | :------: | :------------: | :----------: | :--------------: | :--------: | :----------: | :--------: | :---------: | :--------: | :------------: |
| `/`                       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `balloon`                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `balloon/hinting/start`   |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `balloon/hinting/status`  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `balloon/hinting/stop`    |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `balloon/statistics`      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `boot-source`             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `cpu-config`              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `drives/{id}`             |    O     |       O        |    **R**     |      **R**       |     O      |      O       |     O      |      O      |     O      |       O        |
| `enclave`                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `hotplug/memory`          |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |
| `logger`                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `machine-config`          |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `metrics`                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `mmds`                    |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
| `mmds/config`             |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
| `network-interfaces/{id}` |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
| `snapshot/create`         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `snapshot/load`           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `version`                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `vm`                      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `vm/config`               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `vsock`                   |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `entropy`                 |    O     |       O        |      O       |        O         |     O      |      O       |   **R**    |      O      |     O      |       O        |
| `pmem/{id}`               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
| `serial`                  |    O     |     **R**      |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |

## Input Schema

All input schema fields can be found in the [Swagger](https://swagger.io)
specification:
[firecracker.yaml](./../src/firecracker/swagger/firecracker.yaml).

| Schema                    | Property                 | keyboard | serial console | virtio-block | vhost-user-block | virtio-net | virtio-vsock | virtio-rng | virtio-pmem | virtio-mem | virtio-balloon |
| ------------------------- | ------------------------ | :------: | :------------: | :----------: | :--------------: | :--------: | :----------: | :--------: | :---------: | :--------: | :------------: |
| `Balloon`                 | amount_mib               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                           | deflate_on_oom           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                           | stats_polling_interval_s |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                           | free_page_hinting        |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                           | free_page_reporting      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `BalloonStartCmd`         | acknowledge_on_stop      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `BalloonStatsUpdate`      | stats_polling_interval_s |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `BalloonUpdate`           | amount_mib               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `BootSource`              | boot_args                |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | initrd_path              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | kernel_image_path        |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `BlockTopology`           | physical_block_exp       |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | alignment_offset         |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | min_io_size              |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | opt_io_size              |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `CpuConfig`               | cpuid_modifiers          |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | msr_modifiers            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | reg_modifiers            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | kvm_capabilities         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | vcpu_features            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `CpuTemplate`             | enum                     |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `SnapshotCreateParams`    | mem_file_path            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | snapshot_path            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | snapshot_type            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | sync_snapshot_files      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `Drive`                   | drive_id \*              |    O     |       O        |    **R**     |      **R**       |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | is_read_only             |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | is_root_device \*        |    O     |       O        |    **R**     |      **R**       |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | partuuid \*              |    O     |       O        |    **R**     |      **R**       |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | path_on_host             |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | rate_limiter             |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | socket                   |    O     |       O        |      O       |      **R**       |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | cache_type \*            |    O     |       O        |    **R**     |      **R**       |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | discard                  |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | io_engine                |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | num_queues               |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | image_format             |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | blk_size                 |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | topology                 |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | dmb_size_mib \*\*\*      |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `DriveOverride`           | drive_id                 |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | path_on_host             |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `EnclaveConfig` \*\*\*\*  | cpu_accounting           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | cpu_ids                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | cpu_overcommit           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | debug_mode               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | direct_mode              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | hotplug_mode             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | numa_nodes               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `EnclaveNumaNode`         | mem_size_mib             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | parent_numa              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | vcpu_count               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `InstanceActionInfo`      | action_type              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `SnapshotLoadParams`      | track_dirty_pages        |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | mem_file_path            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | mem_backend              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | snapshot_path            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | resume_vm                |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | enable_diff_snapshots    |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | clock_realtime           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | huge_pages               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | network_overrides        |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | vsock_override           |    O     |       O        |      O       |        O         |     O      |    **R**     |     O      |      O      |     O      |       O        |
|                           | drive_overrides          |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | pmem_overrides           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
| `Logger`                  | level                    |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | log_path                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | show_level               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | show_log_origin          |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | module                   |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `MachineConfiguration`    | cpu_template             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | smt                      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | mem_size_mib             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | track_dirty_pages        |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | vcpu_count               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | huge_pages               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | pcie_hotplug_ports       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `MemoryBackend`           | backend_type             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | backend_path             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `Metrics`                 | metrics_path             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | emit_id                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | properties               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `MmdsConfig`              | network_interfaces       |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | version                  |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | ipv4_address             |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | imds_compat              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `MmdsContentsObject`      | (any)                    |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
| `NetworkInterface`        | guest_mac                |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | host_dev_name            |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | iface_id                 |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | mtu                      |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | rx_rate_limiter          |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | tx_rate_limiter          |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | dmb_size_mib \*\*\*      |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
| `NetworkOverride`         | iface_id                 |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | host_dev_name            |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
| `PartialDrive`            | drive_id                 |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | path_on_host             |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | rate_limiter             |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `PartialNetworkInterface` | iface_id                 |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | rx_rate_limiter          |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | tx_rate_limiter          |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
| `RateLimiter`             | bandwidth                |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | ops                      |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `TokenBucket` \*\*        | one_time_burst           |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | refill_time              |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | size                     |    O     |       O        |    **R**     |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `TokenBucket` \*\*        | one_time_burst           |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | refill_time              |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
|                           | size                     |    O     |       O        |      O       |        O         |   **R**    |      O       |     O      |      O      |     O      |       O        |
| `UnplugParams`            | force \*                 |    O     |       O        |    **R**     |      **R**       |   **R**    |      O       |     O      |    **R**    |     O      |       O        |
| `Vm`                      | state                    |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `Vsock`                   | guest_cid                |    O     |       O        |      O       |        O         |     O      |    **R**     |     O      |      O      |     O      |       O        |
|                           | uds_path                 |    O     |       O        |      O       |        O         |     O      |    **R**     |     O      |      O      |     O      |       O        |
|                           | vsock_id                 |    O     |       O        |      O       |        O         |     O      |    **R**     |     O      |      O      |     O      |       O        |
|                           | dmb_size_mib \*\*\*      |    O     |       O        |      O       |        O         |     O      |    **R**     |     O      |      O      |     O      |       O        |
| `VsockOverride`           | uds_path                 |    O     |       O        |      O       |        O         |     O      |    **R**     |     O      |      O      |     O      |       O        |
| `EntropyDevice`           | rate_limiter             |    O     |       O        |      O       |        O         |     O      |      O       |   **R**    |      O      |     O      |       O        |
| `Pmem`                    | id                       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
|                           | path_on_host             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
|                           | root_device              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
|                           | read_only                |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
|                           | rate_limiter             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
| `PmemOverride`            | id                       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
|                           | path_on_host             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
| `PartialPmem`             | id                       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
|                           | rate_limiter             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |    **R**    |     O      |       O        |
| `SerialDevice`            | serial_out_path          |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                           | rate_limiter             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `MemoryHotplugConfig`     | total_size_mib           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |
|                           | slot_size_mib            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |
|                           | block_size_mib           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |
| `MemoryHotplugSizeUpdate` | requested_size_mib       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |

\* `Drive`'s `drive_id`, `cache_type`, `is_root_device` and `partuuid` can be
configured by either virtio-block or vhost-user-block devices. `UnplugParams` is
the optional body of a `DELETE` on `drives/{id}`, `network-interfaces/{id}` or
`pmem/{id}`, which [hot-unplugs](device-hotplug.md#hot-unplugging-a-device) that
device; its `force` needs only the device being removed.

\*\* The `TokenBucket` can be configured with any combination of virtio-net,
virtio-block, virtio-pmem, virtio-rng and serial devices.

\*\*\* `dmb_size_mib` applies only to a device of a
[Nitro Sandbox](nitro-sandboxes/README.md) in confidential mode; see
[DMB size](nitro-sandboxes/features.md#dmb-size). A KVM microVM, a direct-mode
sandbox and a vhost-user block device reject it.

\*\*\*\* `EnclaveConfig` configures a [Nitro Sandbox](nitro-sandboxes/README.md)
and needs no device.

## Output Schema

All output schema fields can be found in the [Swagger](https://swagger.io)
specification:
[firecracker.yaml](./../src/firecracker/swagger/firecracker.yaml).

| Schema                 | Property                 | keyboard | serial console | virtio-block | vhost-user-block | virtio-net | virtio-vsock | virtio-rng | virtio-pmem | virtio-mem | virtio-balloon |
| ---------------------- | ------------------------ | :------: | :------------: | :----------: | :--------------: | :--------: | :----------: | :--------: | :---------: | :--------: | :------------: |
| `Balloon`              | amount_mib               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | deflate_on_oom           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | stats_polling_interval_s |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | free_page_hinting        |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | free_page_reporting      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `BalloonHintingStatus` | host_cmd                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | guest_cmd                |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `BalloonStats`         | target_pages             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | actual_pages             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | target_mib               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | actual_mib               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | swap_in                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | swap_out                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | major_faults             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | minor_faults             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | free_memory              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | total_memory             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | available_memory         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | disk_caches              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | hugetlb_allocations      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | hugetlb_failures         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | oom_kill                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | alloc_stall              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | async_scan               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | direct_scan              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | async_reclaim            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
|                        | direct_reclaim           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |     **R**      |
| `Error`                | fault_message            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `EnclaveConfig`        | cpu_accounting           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | cpu_ids                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | cpu_overcommit           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | debug_mode               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | direct_mode              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | hotplug_mode             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | numa_nodes               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `EnclaveNumaNode`      | mem_size_mib             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | parent_numa              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | vcpu_count               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `FirecrackerVersion`   | firecracker_version      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `FullVmConfiguration`  | balloon                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | boot-source              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | cpu-config               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | drives                   |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | entropy                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | logger                   |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | machine-config           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | memory-hotplug           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | metrics                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | mmds-config              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | network-interfaces       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | pmem                     |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | vsock                    |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | enclave                  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `InstanceInfo`         | app_name                 |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | id                       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | state                    |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | vmm_version              |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `MachineConfiguration` | cpu_template             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | smt                      |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | mem_size_mib             |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | track_dirty_pages        |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | vcpu_count               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | huge_pages               |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
|                        | pcie_hotplug_ports       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `MemoryHotplugStatus`  | total_size_mib           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |
|                        | slot_size_mib            |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |
|                        | block_size_mib           |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |
|                        | plugged_size_mib         |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |
|                        | requested_size_mib       |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |   **R**    |       O        |

## Instance Actions

All instance actions can be found in the [Swagger](https://swagger.io)
specification:
[firecracker.yaml](./../src/firecracker/swagger/firecracker.yaml).

| Action           | keyboard | serial console | virtio-block | vhost-user-block | virtio-net | virtio-vsock | virtio-rng | virtio-pmem | virtio-mem | virtio-balloon |
| ---------------- | :------: | :------------: | :----------: | :--------------: | :--------: | :----------: | :--------: | :---------: | :--------: | :------------: |
| `FlushMetrics`   |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `InstanceStart`  |    O     |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |
| `SendCtrlAltDel` |  **R**   |       O        |      O       |        O         |     O      |      O       |     O      |      O      |     O      |       O        |

The `keyboard` requirement for `SendCtrlAltDel` applies to x86_64, which
emulates an i8042 keyboard controller. On aarch64 the action instead drives a
PL061 GPIO power button (exposed to the guest as `gpio-keys`); see
[actions](api_requests/actions.md#sendctrlaltdel).
