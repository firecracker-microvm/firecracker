# Firecracker logger Configuration

For the logging capability, Firecracker uses a single Logger object.
The Logger can be configured either by sending a `PUT` API Request to
the `/logger` path or by command line. You can configure the Logger
only once (by using one of these options) and once configured, you
can not update it.

## Prerequisites

In order to configure the Logger, first you have to create the resource
that will be used for logging:

```bash
# Create the required named pipe:
mkfifo logs.fifo

# The logger also works with usual files:
touch logs.file
```

## Using the API socket for configuration

You can configure the Logger by sending the following API command:

```bash
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/logger" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -d "{
             "log_path": "logs.fifo",
             "level": "Warning",
             "show_level": false,
             "show_log_origin": false
    }"
```

Details about the required and optional fields can be found in the
[swagger definition](../../src/api_server/swagger/firecracker.yaml).

## Using command line parameters for configuration

If you want to configure the Logger on startup and without using the
API socket, you can do that by passing the parameter `--log-path` to
the Firecracker process:

```bash
./firecracker --api-sock /tmp/firecracker.socket --log-path
<path_to_the_logging_fifo_or_file>
```

The other Logger fields have, in this case, the default values:
`Level -> Warning`, `show_level -> false`, `show_log_origin -> false`.
For configuring these too, you can also pass the following optional
parameters: `--level <log_level>`, `--show-level`, `--show-log-origin`:

```bash
./firecracker --api-sock /tmp/firecracker.socket --log-path
logs.fifo --level Error --show-level --show-log-origin
```

## Reading from the logging destination

The `logs.fifo` pipe will store the human readable logs, e.g. errors,
warnings etc.(depending on the level).

If the path provided is a named pipe, you can use the script below to
read from it:

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

Otherwise, if the path points to a normal file, you can simply do:

```shell script
cat logs.file
```
