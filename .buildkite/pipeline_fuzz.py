#!/usr/bin/env python3
# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate the Buildkite pipeline that fuzzes every target under fuzz/."""

from pathlib import Path

from common import BKPipeline

BKPipeline.parser.add_argument(
    "--duration",
    type=int,
    default=8 * 60 * 60,
    help="how long to fuzz each target, in seconds",
)
# One x86 and one Arm instance
BKPipeline.parser.set_defaults(
    instances=["m5n.metal", "m6g.metal"],
    platforms=[("al2023", "linux_6.1")],
)

pipeline = BKPipeline(with_build_step=False)
duration = pipeline.args.duration

SUFFIX = "_fuzz_target.rs"
targets = sorted(
    path.name[: -len(SUFFIX)] for path in Path("fuzz/src/bin").glob(f"*{SUFFIX}")
)
assert targets, "no fuzz targets found, run this from the repository root"
for target in targets:
    pipeline.build_group(
        f"fuzz-{target}",
        f"./tools/devtool -y fuzz run {target} -- -V {duration}",
        artifact_paths=[f"fuzz/out_{target}/*", f"fuzz/out_{target}/fuzzer*/stderr"],
        # Time out an hour after fuzzing is meant to end
        timeout_in_minutes=duration // 60 + 60,
        depends_on_build=False,
    )

print(pipeline.to_json())
