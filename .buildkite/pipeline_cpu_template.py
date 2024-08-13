#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite CPU Template pipelines dynamically"""

from enum import Enum

from common import DEFAULT_INSTANCES, DEFAULT_PLATFORMS, BKPipeline, group


class BkStep(str, Enum):
    """
    Commonly used BuildKite step keywords
    """

    LABEL = "label"
    TIMEOUT = "timeout"
    COMMAND = "command"
    ARTIFACTS = "artifact_paths"


cpu_template_test = {
    "rdmsr": {
        BkStep.COMMAND: [
            "tools/devtool -y test --no-build -- -s -ra -m nonci -n4 --log-cli-level=INFO integration_tests/functional/test_cpu_features.py -k 'test_cpu_rdmsr' "
        ],
        BkStep.LABEL: "📖 rdmsr",
        "instances": ["c5n.metal", "m5n.metal", "m6a.metal", "m6i.metal"],
        "platforms": DEFAULT_PLATFORMS,
    },
    "fingerprint": {
        BkStep.COMMAND: [
            "tools/devtool -y test --no-build -- -m no_block_pr integration_tests/functional/test_cpu_template_helper.py -k test_guest_cpu_config_change",
        ],
        BkStep.LABEL: "🖐️ fingerprint",
        "instances": DEFAULT_INSTANCES,
        "platforms": DEFAULT_PLATFORMS,
    },
    "cpuid_wrmsr": {
        "snapshot": {
            BkStep.COMMAND: [
                "tools/devtool -y test --no-build -- -s -ra -m nonci -n4 --log-cli-level=INFO integration_tests/functional/test_cpu_features.py -k 'test_cpu_wrmsr_snapshot or test_cpu_cpuid_snapshot'",
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
                "tools/devtool -y test --no-build -- -s -ra -m nonci -n4 --log-cli-level=INFO integration_tests/functional/test_cpu_features.py -k 'test_cpu_wrmsr_restore or test_cpu_cpuid_restore'",
            ],
            BkStep.LABEL: "📸 load snapshot artifacts created on {instance} {snapshot_os} {snapshot_kv} to {restore_instance} {restore_os} {restore_kv}",
            BkStep.TIMEOUT: 30,
        },
        "cross_instances": {
            "m5n.metal": ["c5n.metal", "m6i.metal"],
            "c5n.metal": ["m5n.metal", "m6i.metal"],
            "m6i.metal": ["m5n.metal", "c5n.metal"],
        },
        "instances": ["c5n.metal", "m5n.metal", "m6i.metal", "m6a.metal"],
    },
}


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


if __name__ == "__main__":
    BKPipeline.parser.add_argument(
        "--test",
        choices=list(cpu_template_test),
        help="CPU template test",
        action="append",
    )
    pipeline = BKPipeline()
    for test in pipeline.args.test or list(cpu_template_test):
        if test == "cpuid_wrmsr":
            groups = group_snapshot_restore(cpu_template_test[test])
            for grp in groups:
                pipeline.add_step(grp)
        else:
            test_data = cpu_template_test[test]
            pipeline.build_group(**test_data, artifacts=["./test_results/**/*"])
    print(pipeline.to_json())
