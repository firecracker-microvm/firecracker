#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite pipelines dynamically"""

from common import COMMON_PARSER, group, pipeline_to_json

# Buildkite default job priority is 0. Setting this to 1 prioritizes PRs over
# scheduled jobs and other batch jobs.
DEFAULT_PRIORITY = 1

args = COMMON_PARSER.parse_args()

defaults = {
    "instances": args.instances,
    "platforms": args.platforms,
    # buildkite step parameters
    "timeout_in_minutes": 45,
    "env": dict(args.step_env),
    # some non-blocking tests are performance, so make sure they get ag=1 instances
    "priority": DEFAULT_PRIORITY + 1,
    "agent_tags": ["ag=1"],
}
defaults.update(args.step_param)

optional_grp = group(
    "❓ Optional",
    "./tools/devtool -y test -c 1-10 -m 0 -- ../tests/integration_tests/ -m no_block_pr --log-cli-level=INFO",
    **defaults,
)

pipeline = {"steps": [optional_grp]}
print(pipeline_to_json(pipeline))
