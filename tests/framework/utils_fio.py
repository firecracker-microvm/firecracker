# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""File containing utility methods for fio-based performance tests"""

import json
import os
from enum import Enum
from pathlib import Path

from framework.utils import CmdBuilder

DEFAULT_RUNTIME_SEC = 30
DEFAULT_WARMUP_SEC = 10


class Mode(str, Enum):
    """
    Modes of fio operation
    """

    # Sequential reads.
    READ = "read"
    # Sequential writes.
    WRITE = "write"
    # Sequential trims (Linux block devices and SCSI character devices only).
    TRIM = "trim"
    # RANDOM reads.
    RANDREAD = "randread"
    # RANDOM writes.
    RANDWRITE = "randwrite"
    # RANDOM trims (Linux block devices and SCSI character devices only).
    RANDTRIM = "randtrim"
    # SEQUENTial mixed reads and writes.
    READWRITE = "readwrite"
    # RANDOM mixed reads and writes.
    RANDRW = "randrw"


class Engine(str, Enum):
    """
    Fio backend engines
    """

    LIBAIO = "libaio"
    PSYNC = "psync"


def build_cmd(
    file_path: str,
    file_size_mb: str | None,
    block_size: int,
    mode: Mode,
    num_jobs: int,
    io_engine: Engine,
    runtime: int | None = DEFAULT_RUNTIME_SEC,
    warmup_time: int | None = DEFAULT_WARMUP_SEC,
    write_logs: bool = True,
) -> str:
    """Build fio cmd"""

    cmd = (
        CmdBuilder("fio")
        .with_arg(f"--name={mode.value}-{block_size}")
        .with_arg(f"--filename={file_path}")
    )

    if file_size_mb:
        cmd = cmd.with_arg(f"--size={file_size_mb}M")

    cmd = cmd.with_arg(f"--bs={block_size}")

    if runtime and warmup_time:
        cmd = (
            cmd.with_arg("--time_based=1")
            .with_arg(f"--runtime={runtime}")
            .with_arg(f"--ramp_time={warmup_time}")
        )

    cmd = (
        cmd.with_arg(f"--rw={mode.value}")
        .with_arg("--direct=1")
        .with_arg("--randrepeat=0")
        .with_arg(f"--ioengine={io_engine.value}")
        .with_arg("--iodepth=32")
        .with_arg(f"--numjobs={num_jobs}")
        # Set affinity of the entire fio process to a set of vCPUs equal
        # in size to number of workers
        .with_arg(f"--cpus_allowed={','.join(str(i) for i in range(num_jobs))}")
        # Instruct fio to pin one worker per vcpu
        .with_arg("--cpus_allowed_policy=split")
        .with_arg("--output-format=json+")
        .with_arg("--output=./fio.json")
    )

    if write_logs:
        cmd = cmd.with_arg("--log_avg_msec=1000").with_arg(
            f"--write_bw_log={mode.value}"
        )
        # Latency measurements only make sence for psync engine
        if io_engine == Engine.PSYNC:
            cmd = cmd.with_arg(f"--write_lat_log={mode}")

    return cmd.build()


class LogType(Enum):
    """Fio log types"""

    BW = "_bw"
    CLAT = "_clat"


def process_log_files(root_dir: str, log_type: LogType) -> ([[str]], [[str]]):
    """
    Parses fio logs which have a form of:
    1000, 2007920, 0, 0, 0
    1000, 2005276, 1, 0, 0
    2000, 1996240, 0, 0, 0
    2000, 1993861, 1, 0, 0
    ...
    where the first column is the timestamp, second is the bw/clat and third is the direction

    The logs directory will look smth like this:
    readwrite_bw.1.log
    readwrite_bw.2.log
    readwrite_clat.1.log
    readwrite_clat.2.log
    readwrite_lat.1.log
    readwrite_lat.2.log
    readwrite_slat.1.log
    readwrite_slat.2.log

    job0         job1
    read write   read write
    [..] [..]    [..] [..]
     |     |      |     |
     |   --|-------  ----
     |   | ------|   |
    [[], []]   [[], []]
     reads      writes

    The output is 2 arrays: array of reads and array of writes
    """
    paths = []
    for item in os.listdir(root_dir):
        if item.endswith(".log") and log_type.value in item:
            paths.append(Path(root_dir / item))

    if not paths:
        return [], []

    reads = []
    writes = []
    for path in sorted(paths):
        lines = path.read_text("UTF-8").splitlines()
        read_values = []
        write_values = []
        for line in lines:
            # See https://fio.readthedocs.io/en/latest/fio_doc.html#log-file-formats
            _, value, direction, _ = line.split(",", maxsplit=3)
            value = int(value.strip())

            match direction.strip():
                case "0":
                    read_values.append(value)
                case "1":
                    write_values.append(value)
                case _:
                    assert False

        reads.append(read_values)
        writes.append(write_values)
    return reads, writes


def process_json_files(root_dir: str) -> ([[int]], [[int]]):
    """
    Reads `bw_bytes` values from fio*.json files and
    packs them into 2 arrays of bw_reads and bw_writes.
    Each entrly is an array in itself of `jobs` per file.
    """
    paths = []
    for item in os.listdir(root_dir):
        if item.endswith(".json") and "fio" in item:
            paths.append(Path(root_dir / item))

    bw_reads = []
    bw_writes = []
    for path in sorted(paths):
        data = json.loads(path.read_text("UTF-8"))
        reads = []
        writes = []
        for job in data["jobs"]:
            if "read" in job:
                reads.append(job["read"]["bw_bytes"])
            if "write" in job:
                writes.append(job["write"]["bw_bytes"])
        bw_reads.append(reads)
        bw_writes.append(writes)
    return bw_reads, bw_writes
