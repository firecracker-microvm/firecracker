#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite pipelines dynamically"""

from common import BKPipeline, get_changed_files, run_all_tests

# Buildkite default job priority is 0. Setting this to 1 prioritizes PRs over
# scheduled jobs and other batch jobs.
DEFAULT_PRIORITY = 1

pipeline = BKPipeline(
    with_build_step=False,
    timeout_in_minutes=45,
    # some non-blocking tests are performance, so make sure they get ag=1 instances
    priority=DEFAULT_PRIORITY + 1,
    agents={"ag": 1},
)

pipeline.build_group(
    "❓ Optional",
    pipeline.devtool_test(
        devtool_opts="--performance -c 1-10 -m 0",
        pytest_opts="integration_tests/ -m 'no_block_pr and not nonci' --log-cli-level=INFO",
    ),
)
if not run_all_tests(get_changed_files()):
    pipeline.steps = []
print(pipeline.to_json())
