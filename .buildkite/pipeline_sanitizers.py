#!/usr/bin/env python3
# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite pipelines dynamically."""

from common import BKPipeline

pipeline = BKPipeline(with_build_step=False)

pipeline.build_group_per_arch(
    "sanitizers",
    pipeline.devtool_test(
        devtool_opts="--no-build",
        pytest_opts="integration_tests/build/test_sanitizers.py",
    ),
)

print(pipeline.to_json())
