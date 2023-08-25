#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite nightly security pipelines dynamically"""

from common import COMMON_PARSER, group, overlay_dict, pipeline_to_json

args = COMMON_PARSER.parse_args()

defaults = {
    "instances": args.instances,
    "platforms": args.platforms,
}
defaults = overlay_dict(defaults, args.step_param)


vulnerabilities_grp = group(
    "🛡️ Vulnerabilities",
    "./tools/devtool -y test -- ../tests/integration_tests/security/test_vulnerabilities.py -m 'no_block_pr and not nonci'",
    **defaults,
)

fingerprint_grp = group(
    "🖐️ Fingerprint",
    "./tools/devtool -y test -- ../tests/integration_tests/functional/test_cpu_template_helper.py -m nonci -k test_fingerprint_change",
    **defaults,
)


pipeline = {"steps": [vulnerabilities_grp, fingerprint_grp]}
print(pipeline_to_json(pipeline))
