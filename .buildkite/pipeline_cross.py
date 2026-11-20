#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Buildkite Cross Snapshot/Restore pipelines dynamically

1. Generate snapshots for each instance and kernel version
2. wait
3. Restore snapshots across instances and kernels
4. Restore and re-snapshot on a newer kernel, then restore on the source kernel
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


def snapshot_roundtrip_steps(
    pipeline, per_instance, instances, source_platforms, create_step_key
):
    """Steps that take snapshots to the next newer host kernel and back.

    `source_platforms` are the platforms that create snapshots for `instances`.
    The source snapshots are created with `vcpu_registers` set to `Pin`.
    The middle step restores one on the newer kernel, runs the guest and
    re-snapshots it twice, so the new snapshot keeps the source kernel's vCPU
    register set.
    The final step restores that snapshot on the source kernel and runs the
    full checks.
    """
    resnapshot_test = "test_snap_resnapshot_from_artifacts"
    # A round-trip job with no snapshots must fail rather than report a skipped test.
    require_artifacts = "-o empty_parameter_set_mark=fail_at_collect"
    # DEFAULT_PLATFORMS lists kernels oldest first. Like the one-way restores,
    # only cross between adjacent versions.
    hops = [
        (source, middle)
        for source, middle in zip(DEFAULT_PLATFORMS, DEFAULT_PLATFORMS[1:])
        if source in source_platforms
    ]
    steps = []
    for instance, (source, middle) in itertools.product(instances, hops):
        source_os, source_kv = source
        middle_os, middle_kv = middle
        middle_key = f"snap-resnapshot-{instance}-{source_kv}-{middle_kv}".replace(
            ".", "_"
        )
        source_artifact = f"snapshots/{instance}_{source_kv}.tar"
        roundtrip_artifact = f"snapshots/{instance}_{source_kv}_{middle_kv}.tar"
        middle_step = {
            "command": [
                f"buildkite-agent artifact download {source_artifact} .",
                f"tar xSvf {source_artifact}",
                *pipeline.devtool_test(
                    devtool_opts="--no-archive",
                    pytest_opts=f"-m nonci -n4 {require_artifacts} integration_tests/functional/test_snapshot_resnapshot_cross_kernel.py",
                ),
                # Print the pin logs on successful runs, too.
                f"find test_results/{resnapshot_test} -type f "
                "-name 'restore-*-pin.log' -exec cat {} +",
                # The new snapshots replace the ones that were restored.
                "rm -rf snapshot_artifacts",
                *pack_snapshots(resnapshot_test, roundtrip_artifact),
            ],
            "label": f"snapshot-resnapshot-{instance}-{source_kv}-{middle_kv}",
            "key": middle_key,
            "timeout_in_minutes": 30,
            "agents": {"instance": instance, "kv": middle_kv, "os": middle_os},
            "depends_on": [create_step_key(instance, source_kv)],
            **per_instance,
            # Do not re-upload the source tarball. Keep logs even when the test fails
            # before it can produce the roundtrip tarball.
            "artifact_paths": [roundtrip_artifact, "./test_results/**/*.log"],
        }
        final_step = restore_step(
            pipeline,
            per_instance,
            roundtrip_artifact,
            label=f"snapshot-roundtrip-{instance}-{source_kv}-{middle_kv}-{source_kv}",
            agents={"instance": instance, "kv": source_kv, "os": source_os},
            depends_on=middle_key,
            extra_pytest_opts=f"--all-snapshot-artifacts {require_artifacts}",
        )
        steps.extend([middle_step, final_step])
    return steps


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

    pipeline.add_step(
        {
            "group": "snapshot-roundtrip-across-kernels",
            "steps": [
                *snapshot_roundtrip_steps(
                    pipeline,
                    per_instance,
                    instances_x86_64,
                    DEFAULT_PLATFORMS,
                    create_step_key,
                ),
                *snapshot_roundtrip_steps(
                    pipeline,
                    per_instance,
                    instances_aarch64,
                    aarch64_platforms,
                    create_step_key,
                ),
            ],
        }
    )
    print(pipeline.to_json())
