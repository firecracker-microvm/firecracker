# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance comparison of APF variants: exitless, fallback, and off.

Uses fast_page_fault_helper (in rootfs) for page faults and concurrent
CPU counter loops to measure vCPU throughput during faulting.

Four variants:
  - exitless: (SF_ON) ring buffers, no KVM exit
  - fallback: (SF_ON) KVM exit + APF ACCEPT, vCPU re-enters immediately
  - off:      (SF_ON) KVM exit, vCPU blocks on condvar until resolved
  - baseline: (SF_OFF) standard UFFD, kernel blocks in-kernel (no KVM exit)
"""

import os
import platform
import signal
import time

import pytest

NS_IN_MSEC = 1_000_000
MEM_MIB = 1024
ITERATIONS = 10

CPU_COUNTER_SCRIPT = r"""#!/bin/sh
i=0
trap 'echo $i > /tmp/cpu_ops_$1.out; exit 0' TERM
while true; do i=$((i+1)); done
"""


@pytest.mark.nonci
@pytest.mark.skipif(platform.machine() != "x86_64", reason="APF is x86_64 only")
@pytest.mark.parametrize("vcpus", [1, 4], ids=["1vcpu", "4vcpu"])
@pytest.mark.parametrize(
    "apf_variant",
    ["exitless", "fallback", "off", "baseline"],
    ids=["APF_EXITLESS", "APF_FALLBACK", "APF_OFF", "BASELINE"],
)
def test_apf_latency(
    microvm_factory,
    guest_kernel_linux_5_10,
    rootfs,
    secret_free,
    metrics,
    apf_variant,
    vcpus,
):
    """Measure post-restore fault latency and CPU throughput per APF variant.

    - exitless: ring buffer path, no KVM exits (fastest)
    - fallback: KVM exits with APF flag, VMM sends via socket + ACCEPT
    - off: KVM exits, VMM relays via socket, vCPU blocks on condvar (slowest)
    - baseline: standard UFFD without secret_free (kernel handles in-kernel)
    """
    # baseline requires SF_OFF; the other variants require SF_ON
    if apf_variant == "baseline" and secret_free:
        pytest.skip("baseline variant runs without secret_free")
    if apf_variant != "baseline" and not secret_free:
        pytest.skip("APF variants require secret_free")

    use_secret_free = apf_variant != "baseline"
    cpu_burners = max(1, vcpus - 1)

    # APF socket needed for exitless and fallback variants
    apf_socket = apf_variant in ("exitless", "fallback")
    # For fallback: enable APF capability but skip exitless ring setup
    no_exitless_env = apf_variant == "fallback"

    vm = microvm_factory.build(
        guest_kernel_linux_5_10,
        rootfs,
        monitor_memory=False,
    )
    vm.spawn(log_level="Info")
    vm.basic_config(vcpu_count=vcpus, mem_size_mib=MEM_MIB, secret_free=use_secret_free)
    vm.add_net_iface()
    vm.start()

    if cpu_burners > 0:
        vm.ssh.check_output(
            f"cat > /tmp/cpu_counter.sh << 'SCRIPT'\n{CPU_COUNTER_SCRIPT}SCRIPT\n"
            "chmod +x /tmp/cpu_counter.sh"
        )

    vm.ssh.check_output(
        "nohup /usr/local/bin/fast_page_fault_helper >/dev/null 2>&1 </dev/null &"
    )
    for i in range(cpu_burners):
        vm.ssh.check_output(
            f"rm -f /tmp/cpu_ops_{i}.out /tmp/cpu_pid_{i}; "
            f"nohup /tmp/cpu_counter.sh {i} >/dev/null 2>&1 </dev/null & "
            f"echo $! > /tmp/cpu_pid_{i}"
        )
    time.sleep(5)

    snapshot = vm.snapshot_full()
    vm.kill()

    metrics.set_dimensions(
        {
            "performance_test": "test_apf_latency",
            "apf_variant": apf_variant,
            "vcpus": str(vcpus),
            "cpu_burners": str(cpu_burners),
            "uffd_handler": "on_demand",
            **vm.dimensions,
        }
    )

    fault_samples = []
    ops_rate_samples = []

    # Set env var for fallback variant (skip exitless ring setup in VMM)
    if no_exitless_env:
        os.environ["FC_APF_NO_EXITLESS"] = "1"

    try:
        for microvm in microvm_factory.build_n_from_snapshot(
            snapshot,
            ITERATIONS,
            uffd_handler_name="on_demand",
            apf=apf_socket,
        ):
            microvm.memory_monitor = None

            microvm.ssh.check_output(
                "rm -f /tmp/fast_page_fault_helper.out /tmp/cpu_ops_*.out"
            )

            _, pid, _ = microvm.ssh.check_output("pidof fast_page_fault_helper")
            microvm.ssh.check_output(f"kill -s {signal.SIGUSR1} {pid}")

            _, duration, _ = microvm.ssh.check_output(
                "while [ ! -f /tmp/fast_page_fault_helper.out ]; do sleep 0.1; done;"
                " cat /tmp/fast_page_fault_helper.out"
            )
            fault_ms = int(duration) / NS_IN_MSEC
            fault_samples.append(fault_ms)
            metrics.put_metric("fault_latency", fault_ms, "Milliseconds")

            if cpu_burners > 0:
                microvm.ssh.check_output(
                    "for f in /tmp/cpu_pid_*; do "
                    "kill $(cat $f) 2>/dev/null; done || true"
                )
                time.sleep(0.5)
                total_ops = 0
                for i in range(cpu_burners):
                    try:
                        _, ops_str, _ = microvm.ssh.check_output(
                            f"cat /tmp/cpu_ops_{i}.out 2>/dev/null || echo 0"
                        )
                        total_ops += int(ops_str.strip())
                    except (ValueError, IndexError):
                        pass

                if fault_ms > 0:
                    ops_rate = total_ops / (fault_ms / 1000)
                    ops_rate_samples.append(ops_rate)
                    metrics.put_metric("cpu_ops_rate", ops_rate, "Count/Second")

    finally:
        os.environ.pop("FC_APF_NO_EXITLESS", None)

    # --- Print summary ---
    fault_avg = sum(fault_samples) / len(fault_samples)
    line = (
        f"\n  {apf_variant:10s} {vcpus}vcpu: "
        f"fault_latency avg={fault_avg:.1f} ms  "
        f"min={min(fault_samples):.1f}  max={max(fault_samples):.1f}"
    )
    if ops_rate_samples:
        rate_avg = sum(ops_rate_samples) / len(ops_rate_samples)
        line += f"  |  cpu_ops_rate avg={rate_avg:.0f} ops/s"
    print(line + f"  ({len(fault_samples)} samples)")
