# Logger and Metrics API Requests

The Logger can be configured by sending a `PUT` API Request to the `/logger`
path.
The Metrics system can be configured by sending a `PUT` API Request to the
`/metrics` path.
You can configure none, one or both of these systems as they are not
interdependent.

A minimal configuration example for these resources is the following:

```bash
# Create the required named pipes.
mkfifo logs.fifo
mkfifo metrics.fifo

# The logger and metrics systems also work with usual files.
touch logs.fifo
touch metrics.fifo

# Configure the Logger.
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/logger" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -d "{
             \"log_path\": \"logs.fifo\"
    }"

# Configure the Metrics system.
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/metrics" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -d "{
             \"metrics_path\": \"metrics.fifo\"
    }"
```

Details about the required and optional fields can be found in the
[swagger definition](../../src/api_server/swagger/firecracker.yaml).

The `logs.fifo` file stores the human readable logs (i.e errors,
warnings etc) while the `metrics.fifo` file stores the metrics
in JSON format. The metrics get flushed in two ways:

* without user intervention every 60 seconds
* upon user demand by issuing a [FlushMetrics][1] request.

If the paths provided are named pipes, you can use the script below to
read from them:

```shell script
logs=logs.fifo

while true
do
    if read line <$logs; then
        echo $line
    fi
done

echo "Reader exiting"

```

otherwise, if the paths point to normal files, you can simply do:

```shell script
cat logs.fifo
cat metrics.fifo
```
