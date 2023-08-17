#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite pipelines dynamically"""

from common import (
    COMMON_PARSER,
    get_changed_files,
    group,
    overlay_dict,
    pipeline_to_json,
    run_all_tests,
)

# Buildkite default job priority is 0. Setting this to 1 prioritizes PRs over
# scheduled jobs and other batch jobs.
DEFAULT_PRIORITY = 1

args = COMMON_PARSER.parse_args()

defaults = {
    "instances": args.instances,
    "platforms": args.platforms,
    # buildkite step parameters
    "timeout_in_minutes": 45,
    # some non-blocking tests are performance, so make sure they get ag=1 instances
    "priority": DEFAULT_PRIORITY + 1,
    "agents": {"ag": 1},
}
defaults = overlay_dict(defaults, args.step_param)


optional_grp = group(
    "❓ Optional",
    "./tools/devtool -y test -c 1-10 -m 0 -- ../tests/integration_tests/ -m 'no_block_pr and not nonci' --log-cli-level=INFO",
    **defaults,
)

changed_files = get_changed_files("main")
pipeline = {"steps": [optional_grp]} if run_all_tests(changed_files) else {"steps": []}
print(pipeline_to_json(pipeline))
