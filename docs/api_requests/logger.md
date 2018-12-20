# Logger API Request
The Logger can be configured by sending a `PUT` API Request to the `/logger`
path.

Details about the required fields can be found in the
[swagger definition](../../api_server/swagger/firecracker.yaml).

## LogDirtyPages Option
When the `LogDirtyPages` option is specified in the `options` field, every 60
seconds a metric with the guest dirty pages count is emitted.
The `dirty_pages` number represents the number of pages in the guest memory
that have been dirtied since the last call to `KVM_GET_DIRTY_LOG`.
See the
[KVM documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
for details.

### Logger Configuration Example with LogDirtyPages

```bash
# Create the required named pipes.
mkfifo logs.fifo
mkfifo metrics.fifo

# Configure the Logger.
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT "http://localhost/logger" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -d "{
            \"log_fifo\": \"logs.fifo\",
            \"metrics_fifo\": \"metrics.fifo\",
            \"options\": [\"LogDirtyPages\"]
    }"
```

Every 60 seconds the metric `dirty_pages` is going to be updated.
To check the count of dirty pages in the guest, grep after `dirty_pages` in the
`metrics.fifo` named pipe.

```bash
$ grep -Eo "\"dirty_pages\":[[:digit:]]+" metrics.fifo
"dirty_pages":0
"dirty_pages":49319
"dirty_pages":1126
```
