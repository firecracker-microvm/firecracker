# Firecracker performance benchmarking

## Overview

Performance benchmarking is available for the following emulated devices:
- [net device](../tests/integration_tests/performance/test_net_performance.py) - using iperf3
- [block device](../tests/integration_tests/performance/test_blk_performance.py) - using fio
  
The benchmarks are part of the integration testing but are not run by the normal
CI pipeline due to the long duration and isolation requirements.

## Manually running the benchmarks

Spawn a shell in the development container:
```bash
    sudo tools/devtool shell -p -r
```
The *-r* switch will create a ramdisk in /mnt/ramdisk that will be mounted
in the container as /srv. This is required for the block device test to not be
affected by the I/O latency of a normal disk. 
If you want to asses the block performance on top of a host disk device remove
the *-r* flag.

### Network device benchmark
Run the network performance test:
```bash
    cd tests
    pytest -E benchmark integration_tests/performance/test_net_performance.py
```

Some results will be shown as soon as each test case is completed and after
completion of all test cases the results will be written to **test_net_performance.json**.

```bash
    cat test_net_performance.json
```

```json
[
    {
        "test": "tcp-h2g-100",
        "tput": 93.17,
        "retransmits": 0
    },
    {
        "test": "tcp-g2h-100",
        "tput": 94.6,
        "retransmits": 0
    },
  
    {
        "test": "udp-h2g-100",
        "tput": 95.39,
        "lost": 0,
        "pps": 1526.27,
        "jitter": 0.05
    },
    {
        "test": "udp-g2h-100",
        "tput": 94.45,
        "lost": 0,
        "pps": 1511.26,
        "jitter": 0.02
    },
]
```

For TCP tests the metrics collected are throughtput(Mbps) and retransmits. For UDP: throughtput(Mbps),
lost packets(lost), packets per second(pps) and jitter.

### Block device benchmark
Run the block performance test:
```bash
    cd tests
    pytest -E benchmark integration_tests/performance/test_blk_performance.py
```

The output JSON will be in this format:

```json
[
    {
        "test": "65536-randread",
        "read_iops_min": 54630,
        "read_iops_mean": 76745,
        "read_iops_max": 99391,
        "read_bw_min": 3414.38,
        "read_bw_mean": 4796.63,
        "read_bw_max": 6211.95,
        "write_iops_min": 0,
        "write_iops_mean": 0,
        "write_iops_max": 0,
        "write_bw_min": 0.0,
        "write_bw_mean": 0.0,
        "write_bw_max": 0.0
    },
    {
        "test": "4096-randread",
        "read_iops_min": 58848,
        "read_iops_mean": 63385,
        "read_iops_max": 67142,
        "read_bw_min": 229.88,
        "read_bw_mean": 247.6,
        "read_bw_max": 262.27,
        "write_iops_min": 0,
        "write_iops_mean": 0,
        "write_iops_max": 0,
        "write_bw_min": 0.0,
        "write_bw_mean": 0.0,
        "write_bw_max": 0.0
    },
```

Collected metrics:
- test name is formatted as blocksize-mode, where mode is the fio test mode
- read_iops(min, mean, max) - read operations per second
- read_bw(min, mean, max) - read bandwidth in MBytes per second
- write_iops(min, mean, max) - write operations per second
- write_bw(min, mean, max) - write bandwidth in MBytes per second

More test modes and metrics are available in fio and they can be enabled by adding
them in the test:

```python
# Block device size in MB.
BLOCK_DEVICE_SIZE = 2048
# Iteration duration in seconds.
ITERATION_DURATION = 120

FIO_BLOCK_SIZES = [65536, 4096, 1024, 512]
FIO_TEST_MODES = ["randread", "randrw", "read", "readwrite"]

FIO_RESULT_OPS = ["read", "write"]
FIO_RESULT_METRICS = ["iops", "bw"]
FIO_RESULT_VALUES = ["min", "mean", "max"]
```


## Known issues

There are a couple of issues you should expect when running the benchmark:
- result variance for multiple runs on the same hardware
- high result variance when running performance tests along with 
other intensive workloads
  
