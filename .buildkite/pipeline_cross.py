#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite Cross Snapshot/Restore pipelines dynamically

1. Generate snapshots for each instance and kernel version
2. wait
3. Restore snapshots across instances and kernels
"""

import itertools

from common import DEFAULT_PLATFORMS, BKPipeline


def pack_snapshots(test_name, tarball):
    """Commands that tar the snapshots a test left in its results directory."""
    return [
        # punch holes in mem snapshot tiles and tar them so they are preserved in S3
        f"find test_results/{test_name} -type f -name mem |xargs -P4 -t -n1 fallocate -d",
        f"mv -v test_results/{test_name} snapshot_artifacts",
        "mkdir -pv snapshots",
        f"tar cSvf {tarball} snapshot_artifacts",
    ]


def restore_step(
    pipeline, per_instance, tarball, *, label, agents, depends_on, extra_pytest_opts=""
):
    """Step that restores the snapshots in a tarball with the restore test."""
    return {
        "command": [
            f"buildkite-agent artifact download {tarball} .",
            f"tar xSvf {tarball}",
            *pipeline.devtool_test(
                pytest_opts=f"-m nonci -n8 --dist worksteal {extra_pytest_opts} integration_tests/functional/test_snapshot_restore_cross_kernel.py",
            ),
        ],
        "label": label,
        "timeout": 30,
        "agents": agents,
        "depends_on": [depends_on],
        **per_instance,
    }


if __name__ == "__main__":
    pipeline = BKPipeline()
    per_instance = pipeline.per_instance.copy()
    per_instance.pop("instances")
    per_instance.pop("platforms")
    instances_x86_64 = [
        "m5n.metal",
        "m6i.metal",
        "m7i.metal-24xl",
        "m7i.metal-48xl",
        "m8i.metal-48xl",
        "m6a.metal",
        "m7a.metal-48xl",
    ]
    instances_aarch64 = ["m6g.metal", "m7g.metal", "m8g.metal-24xl", "m9g.metal-48xl"]
    restore_only_platforms = [("al2023", "linux_6.18")]
    x86_64_platforms = DEFAULT_PLATFORMS + restore_only_platforms
    commands = [
        *pipeline.devtool_test(
            devtool_opts="--no-archive",
            pytest_opts="-m nonci -n4 integration_tests/functional/test_snapshot_phase1.py",
        ),
        *pack_snapshots("test_snapshot_phase1", "snapshots/{instance}_{kv}.tar"),
    ]

    def create_step_key(instance, kv):
        """Buildkite key for a snapshot-create step.

        Keys may only contain [A-Za-z0-9_\\-:], so dots in instance names
        (m5n.metal) and kernel versions (linux_5.10) are sanitized to
        underscores. Tarball paths stay unchanged.
        """
        return f"snap-create-{instance}-{kv}".replace(".", "_")

    # Key each snapshot-create step so restore steps can depend on the
    # specific source snapshot they need, rather than waiting for every
    # snapshot-create step to finish. `build_group` doesn't sanitize
    # substituted key values, so we set the final key after it fans out.
    x86_create = pipeline.build_group(
        "snapshot-create",
        commands,
        timeout=30,
        artifact_paths="snapshots/**/*",
        instances=instances_x86_64,
        platforms=DEFAULT_PLATFORMS,
    )

    # https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md#where-can-i-resume-my-snapshots
    aarch64_platforms = [("al2023", "linux_6.1")]
    aarch64_create = pipeline.build_group(
        "snapshot-create-aarch64",
        commands,
        timeout=30,
        artifact_paths="snapshots/**/*",
        instances=instances_aarch64,
        platforms=aarch64_platforms,
    )
    for grp in (x86_create, aarch64_create):
        for s in grp["steps"]:
            s["key"] = create_step_key(s["agents"]["instance"], s["agents"]["kv"])

    # allow-list of what instances can be restored on what other instances (in
    # addition to itself). aarch64 is restricted to same-instance restores.
    supported = {
        "m5n.metal": ["m6i.metal"],
        "m6i.metal": ["m5n.metal"],
    }
    aarch64_all_platforms = aarch64_platforms + restore_only_platforms
    perms_aarch64 = itertools.product(
        instances_aarch64, aarch64_platforms, instances_aarch64, aarch64_all_platforms
    )

    perms_x86_64 = itertools.product(
        instances_x86_64, DEFAULT_PLATFORMS, instances_x86_64, x86_64_platforms
    )
    steps = []
    for (
        src_instance,
        (_, src_kv),
        dst_instance,
        (dst_os, dst_kv),
    ) in itertools.chain(perms_x86_64, perms_aarch64):
        # the integration tests already test src == dst, so we skip it
        if src_instance == dst_instance and src_kv == dst_kv:
            continue
        # newer -> older is not supported, and does not work
        if src_kv > dst_kv:
            continue
        # only test cross-kernel restore between adjacent kernel versions
        if src_kv == "linux_5.10" and dst_kv == "linux_6.18":
            continue
        if src_instance != dst_instance and dst_instance not in supported.get(
            src_instance, []
        ):
            continue

        pytest_keyword_for_instance = {
            "m5n.metal": "-k 'not None'",
            "m6i.metal": "-k 'not None'",
            "m6a.metal": "",
        }
        k_val = pytest_keyword_for_instance.get(dst_instance, "")
        steps.append(
            restore_step(
                pipeline,
                per_instance,
                f"snapshots/{src_instance}_{src_kv}.tar",
                label=f"snapshot-restore-src-{src_instance}-{src_kv}-dst-{dst_instance}-{dst_kv}",
                agents={"instance": dst_instance, "kv": dst_kv, "os": dst_os},
                depends_on=create_step_key(src_instance, src_kv),
                extra_pytest_opts=k_val,
            )
        )
    pipeline.add_step(
        {"group": "snapshot-restore-across-instances-and-kernels", "steps": steps}
    )
    print(pipeline.to_json())
