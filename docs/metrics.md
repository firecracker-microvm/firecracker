# Firecracker Metrics Configuration

For the metrics capability, Firecracker uses a single Metrics system. This
system can be configured either by: a) sending a `PUT` API Request to the
`/metrics` path: or b) using the `--metrics-path` CLI option.

Note the metrics configuration is **not** part of the guest configuration and is
not restored from a snapshot.

## Prerequisites

In order to configure the Metrics, first you have to create the resource that
will be used for storing the metrics:

```bash
# Create the required named pipe:
mkfifo metrics.fifo

# The Metrics system also works with usual files:
touch metrics.file
```

## Configuring the system via CLI

When launching Firecracker, use the CLI option to set the metrics file.

```bash
./firecracker --metrics-path metrics.fifo
```

## Configuring the system via API

You can configure the Metrics system by sending the following API command:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/metrics" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -d "{
             \"metrics_path\": \"metrics.fifo\"
    }"
```

Details about this configuration can be found in the
[swagger definition](../src/firecracker/swagger/firecracker.yaml).

The metrics are written to the `metrics_path` in JSON format.

## Flushing the metrics

The metrics get flushed in two ways:

- without user intervention every 60 seconds;
- upon user demand, by issuing a `FlushMetrics` request. You can find how to use
  this request in the [actions API](api_requests/actions.md).

If the path provided is a named pipe, you can use the script below to read from
it:

```shell
metrics=metrics.fifo

while true
do
    if read line <$metrics; then
        echo $line
    fi
done

echo "Reader exiting"

```

Otherwise, if the path points to a normal file, you can simply do:

```shell script
cat metrics.file
```

## Metrics emitted by Firecracker

The metrics emitted by Firecracker are in JSON format. Below are the keys
present in each metrics json object emitted by Firecracker:

```
"api_server"
"balloon"
"block"
"deprecated_api"
"entropy"
"get_api_requests"
"i8042"
"latencies_us"
"logger"
"mmds"
"net"
"patch_api_requests"
"put_api_requests"
"rtc"
"seccomp"
"signals"
"uart"
"vcpu"
"vhost_user_block"
"vmm"
"vsock"
```

Below table explains where Firecracker metrics are defined :

| Metrics key                                                                                                                                                                               | Device                                                                        | Additional comments                                                                                                                                                                                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| balloon                                                                                                                                                                                   | [BalloonDeviceMetrics](../src/vmm/src/devices/virtio/balloon/metrics.rs)      | Represent metrics for the Balloon device.                                                                                                                                                               |
| block                                                                                                                                                                                     | [BlockDeviceMetrics](../src/vmm/src/devices/virtio/block/virtio/metrics.rs)   | Represent aggregate metrics for Virtio Block device.                                                                                                                                                    |
| block\_{block_drive_id}                                                                                                                                                                   | [BlockDeviceMetrics](../src/vmm/src/devices/virtio/block/virtio/metrics.rs)   | Represent Virtio Block device metrics for the endpoint `"/drives/{drive_id}"` e.g. `"block_rootfs":` represent metrics for the endpoint `"/drives/rootfs"`                                              |
| i8042                                                                                                                                                                                     | [I8042DeviceMetrics](../src/vmm/src/devices/legacy/i8042.rs)                  | Represent Metrics specific to the i8042 device.                                                                                                                                                         |
| net                                                                                                                                                                                       | [NetDeviceMetrics](../src/vmm/src/devices/virtio/net/metrics.rs)              | Represent aggregate metrics for Virtio Net device.                                                                                                                                                      |
| net\_{iface_id}                                                                                                                                                                           | [NetDeviceMetrics](../src/vmm/src/devices/virtio/net/metrics.rs)              | Represent Virtio Net device metrics for the endpoint `"/network-interfaces/{iface_id}"` e.g. `net_eth0` represent metrics for the endpoint `"/network-interfaces/eth0"`                                 |
| rtc                                                                                                                                                                                       | [RTCDeviceMetrics](../src/vmm/src/devices/legacy/serial.rs)                   | Represent Metrics specific to the RTC device. `Note`: this is emitted only on `aarch64`.                                                                                                                |
| uart                                                                                                                                                                                      | [SerialDeviceMetrics](../src/vmm/src/devices/legacy/serial.rs)                | Represent Metrics specific to the serial device.                                                                                                                                                        |
| vhost_user\_{dev}\_{dev_id}                                                                                                                                                               | [VhostUserDeviceMetrics](../src/vmm/src/devices/virtio/vhost_user_metrics.rs) | Represent Vhost-user device metrics for the device `dev` and device id `dev_id`. e.g. `"vhost_user_block_rootfs":` represent metrics for vhost-user block device having the endpoint `"/drives/rootfs"` |
| vsock                                                                                                                                                                                     | [VsockDeviceMetrics](../src/vmm/src/devices/virtio/vsock/metrics.rs)          | Represent Metrics specific to the vsock device.                                                                                                                                                         |
| entropy                                                                                                                                                                                   | [EntropyDeviceMetrics](../src/vmm/src/devices/virtio/rng/metrics.rs)          | Represent Metrics specific to the entropy device.                                                                                                                                                       |
| "api_server"<br>"deprecated_api"<br>"get_api_requests"<br>"latencies_us"<br>"logger"<br>"mmds"<br>"patch_api_requests"<br>"put_api_requests"<br>"seccomp"<br>"signals"<br>"vcpu"<br>"vmm" | [metrics.rs](../src/vmm/src/logger/metrics.rs)                                | Rest of the metrics are defined in the same file metrics.rs.                                                                                                                                            |

Note: Firecracker emits all the above metrics regardless of the presense of that
component i.e. even if `vsock` device is not attached to the Microvm,
Firecracker will still emit the Vsock metrics with key as `vsock` and value of
all metrics defined in `VsockDeviceMetrics` as `0`.

### Units for Firecracker metrics:

Units for Firecracker metrics are embedded in their name.<br/> Below pseudo code
should be to extract units from Firecracker metrics name:<br/> Note: An example
of full_key for below logic is `"vcpu.exit_io_in_agg.min_us"`

```
    if substring "_bytes" or "_bytes_count" is present in any subkey of full_key
        Unit is "Bytes"
    else substring "_ms" is present in any subkey of full_key
        Unit is "Milliseconds"
    else substring "_us" is present in any subkey of full_key
        Unit is "Microseconds"
    else
        Unit is "Count"
```
