# Firecracker Metrics Configuration

For the metrics capability, Firecracker uses a single Metrics system.
This system can be configured by sending a `PUT` API Request to the
`/metrics` path.

## Prerequisites

In order to configure the Metrics, first you have to create the resource
that will be used for storing the metrics:

```bash
# Create the required named pipe:
mkfifo metrics.fifo

# The Metrics system also works with usual files:
touch metrics.file
```

## Configuring the system

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
[swagger definition](../../src/api_server/swagger/firecracker.yaml).

The metrics are written to the `metrics_path` in JSON format.

## Flushing the metrics

The metrics get flushed in two ways:

* without user intervention every 60 seconds;
* upon user demand, by issuing a `FlushMetrics` request. You can
find how to use this request in the [actions API](../api_requests/actions.md).

If the path provided is a named pipe, you can use the script below to
read from it:

```shell script
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
