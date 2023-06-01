#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite CPU Template pipelines dynamically"""

import argparse
from enum import Enum

from common import DEFAULT_PLATFORMS, group, pipeline_to_json


class BkStep(str, Enum):
    """
    Commonly used BuildKite step keywords
    """

    LABEL = "label"
    TIMEOUT = "timeout"
    COMMAND = "commands"
    ARTIFACTS = "artifact_paths"


cpu_template_test = {
    "rdmsr": {
        BkStep.COMMAND: [
            "tools/devtool -y test -- -s -ra -m nonci -n4 --log-cli-level=INFO integration_tests/functional/test_cpu_features.py -k 'test_cpu_rdmsr' "
        ],
        BkStep.LABEL: "📖 rdmsr",
        "instances": ["m5d.metal", "m6a.metal", "m6i.metal"],
        "platforms": DEFAULT_PLATFORMS,
    },
    "cpuid_wrmsr": {
        "snapshot": {
            BkStep.COMMAND: [
                "tools/devtool -y test -- -s -ra -m nonci -n4 --log-cli-level=INFO integration_tests/functional/test_cpu_features.py -k 'test_cpu_wrmsr_snapshot or test_cpu_cpuid_snapshot'",
                "mkdir -pv tests/snapshot_artifacts_upload/{instance}_{os}_{kv}",
                "sudo mv tests/snapshot_artifacts/* tests/snapshot_artifacts_upload/{instance}_{os}_{kv}",
            ],
            BkStep.LABEL: "📸 create snapshots",
            BkStep.ARTIFACTS: "tests/snapshot_artifacts_upload/**/*",
            BkStep.TIMEOUT: 30,
        },
        "restore": {
            BkStep.COMMAND: [
                "buildkite-agent artifact download tests/snapshot_artifacts_upload/{instance}_{os}_{kv}/**/* .",
                "mv tests/snapshot_artifacts_upload/{instance}_{os}_{kv} tests/snapshot_artifacts",
                "tools/devtool -y test -- -s -ra -m nonci -n4 --log-cli-level=INFO integration_tests/functional/test_cpu_features.py -k 'test_cpu_wrmsr_restore or test_cpu_cpuid_restore'",
            ],
            BkStep.LABEL: "📸 load snapshot artifacts created on {instance} {snapshot_os} {snapshot_kv} to {restore_instance} {restore_os} {restore_kv}",
            BkStep.TIMEOUT: 30,
        },
        "cross_instances": {
            "m5d.metal": ["m6i.metal"],
            "m6i.metal": ["m5d.metal"],
        },
        "instances": ["m5d.metal", "m6i.metal", "m6a.metal"],
    },
    "aarch64_cpu_templates": {
        BkStep.COMMAND: [
            "tools/devtool -y test -- -s -ra -m nonci --log-cli-level=INFO integration_tests/functional/test_cpu_features_aarch64.py"
        ],
        BkStep.LABEL: "📖 cpu templates",
        "instances": ["m6g.metal", "c7g.metal"],
        "platforms": [("al2_armpatch", "linux_5.10")],
    },
}


def group_single(tests):
    """
    Generate a group step with specified parameters for each instance
    and kernel combination
    https://buildkite.com/docs/pipelines/group-step
    """
    group_step = group(
        label=tests[BkStep.LABEL],
        command=tests[BkStep.COMMAND],
        instances=tests["instances"],
        platforms=tests["platforms"],
        artifacts=["./test_results/**/*"],
    )
    return [group_step]


def group_snapshot_restore(test_step):
    """
    Generate a group step with specified parameters for each instance
    and kernel combination and handle "wait" command between steps
    https://buildkite.com/docs/pipelines/group-step
    """
    groups = []

    groups.append(
        group(
            label=test_step["snapshot"][BkStep.LABEL],
            command=test_step["snapshot"][BkStep.COMMAND],
            instances=test_step["instances"],
            platforms=DEFAULT_PLATFORMS,
            timeout=test_step["snapshot"][BkStep.TIMEOUT],
            artifacts=test_step["snapshot"][BkStep.ARTIFACTS],
        )
    )
    groups.append("wait")
    snapshot_restore_combinations = []
    for dp in DEFAULT_PLATFORMS:
        for src_instance in test_step["instances"]:
            for dst_instance in [src_instance] + test_step["cross_instances"].get(
                src_instance, []
            ):
                snapshot_restore_combinations.append(
                    ((dp, src_instance), (dp, dst_instance))
                )

    steps = []
    for combination in snapshot_restore_combinations:
        (snapshot_os, snapshot_kv), snapshot_instance = combination[0]
        (restore_os, restore_kv), restore_instance = combination[1]
        restore_commands = [
            command.format(instance=snapshot_instance, os=snapshot_os, kv=snapshot_kv)
            for command in test_step["restore"][BkStep.COMMAND]
        ]
        restore_label = test_step["restore"][BkStep.LABEL].format(
            instance=snapshot_instance,
            snapshot_os=snapshot_os,
            snapshot_kv=snapshot_kv,
            restore_instance=restore_instance,
            restore_os=restore_os,
            restore_kv=restore_kv,
        )
        steps.append(
            {
                BkStep.COMMAND: restore_commands,
                BkStep.LABEL: restore_label,
                BkStep.TIMEOUT: test_step["restore"][BkStep.TIMEOUT],
                "agents": [
                    f"instance={restore_instance}",
                    f"kv={restore_kv}",
                    f"os={restore_os}",
                ],
            }
        )

    groups.append({"group": "📸 restores snapshots", "steps": steps})
    return groups


def main():
    """
    Generate group template required to trigger pipelines for
    the requested CPU template test.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--test",
        required=True,
        choices=list(cpu_template_test),
        help="CPU template test",
    )
    test_args = parser.parse_args()

    if test_args.test == "rdmsr":
        test_group = group_single(cpu_template_test[test_args.test])
    elif test_args.test == "cpuid_wrmsr":
        test_group = group_snapshot_restore(cpu_template_test[test_args.test])
    elif test_args.test == "aarch64_cpu_templates":
        test_group = group_single(cpu_template_test[test_args.test])

    pipeline = {"steps": test_group}
    print(pipeline_to_json(pipeline))


if __name__ == "__main__":
    main()
