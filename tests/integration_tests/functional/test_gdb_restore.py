# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""GDB debugging of a microVM *restored from a snapshot* (the e2b resume path).

Upstream Firecracker only wires GDB into the fresh-boot path; this exercises the
restore-path wiring added to `build_microvm_from_snapshot`. It boots a multi-vCPU
VM on the production kernel built with DWARF (KASLR *on*, as in prod), snapshots
it, restores into a new VM (file/UFFD-backed, 4K/2M hugetlb), recovers the KASLR
image slide *from the snapshot itself*, attaches GDB, and checks that we can set a
breakpoint and print kernel structures/memory across multiple vCPUs.

KASLR slide recovery: the kernel image is slid by a single offset, so
`slide = MSR_LSTAR - &entry_SYSCALL_64`, where `MSR_LSTAR` is read from the
snapshot's saved vcpu MSRs (via `snapshot-editor info-vmstate vcpu-states`) and
`&entry_SYSCALL_64` is the link-time address from the vmlinux symbols. Applied with
`add-symbol-file <vmlinux> -o <slide>`. This mirrors how resume-build recovers the
slide in prod.
"""

import base64
import platform
import re
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

import host_tools.cargo_build
from framework.microvm import HugePagesConfig, MicroVMFactory

# Production kernel (6.1.158) built with DWARF, KASLR on — same config as prod,
# only debug info added. Placed here by the test setup.
KERNEL = Path(__file__).parents[3] / "build/img/x86_64/vmlinux-6.1.158-dwarf"

GDB_TIMEOUT = 40


def _recover_slide(snapshot_editor, vmstate_path, vmlinux):
    """Recover the KASLR image slide from the snapshot. Uses MSR_LSTAR (the syscall
    entry, i.e. entry_SYSCALL_64 — kernel text, slid with the image) minus the
    link-time address of entry_SYSCALL_64. (IDTR/GDTR are mapped in the fixed
    cpu_entry_area, not slid with the image, so they can't be used.)"""
    out = subprocess.check_output(
        [
            str(snapshot_editor),
            "info-vmstate",
            "vcpu-states",
            "--vmstate-path",
            str(vmstate_path),
        ],
        text=True,
    )
    m = re.search(r"msr index=0xc0000082 data=0x([0-9a-fA-F]+)", out)  # MSR_LSTAR
    assert m, f"MSR_LSTAR not found in vmstate dump:\n{out[-2000:]}"
    lstar = int(m.group(1), 16)

    link = subprocess.check_output(
        f"readelf -sW {vmlinux} | awk '$NF==\"entry_SYSCALL_64\"{{print $2; exit}}'",
        shell=True,
        text=True,
    ).strip()
    assert link, "entry_SYSCALL_64 symbol not found in vmlinux"
    return lstar - int(link, 16)


def _spawn_gdb(gdb_socket, out_path, commands):
    """Drive gdb in batch mode against FC's gdbstub, writing all output to
    `out_path`. No symbol file on the command line — symbols are loaded in-script
    with the recovered slide. Polls for the socket (created inside FC's restore
    path, which then blocks for the connection)."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".gdb", delete=False, prefix="fc_gdb_restore_"
    ) as f:
        f.write(commands)
        gdb_script = f.name

    return subprocess.Popen(
        f"""
        until [ -S {gdb_socket} ]; do sleep 0.2; done;
        exec gdb -q -batch -x {gdb_script} > {out_path} 2>&1
        """,
        shell=True,
    )


def _prelude(slide, gdb_socket):
    """gdb commands to load slid symbols and connect."""
    return f"""
    set pagination off
    set confirm off
    add-symbol-file {KERNEL} -o {slide}
    target remote {gdb_socket}
    """


# Hugetlbfs guest memory is anonymous MAP_HUGETLB, which the File restore backend
# can't mmap — so the 2M case uses UFFD (also the production backing).
@pytest.mark.parametrize(
    "use_uffd,huge_pages",
    [
        (False, HugePagesConfig.NONE),
        (True, HugePagesConfig.NONE),
        (True, HugePagesConfig.HUGETLBFS_2MB),
    ],
    ids=["file-4k", "uffd-4k", "uffd-2M"],
)
@pytest.mark.skipif(
    platform.machine() != "x86_64", reason="restore-path GDB wiring is x86_64-only"
)
def test_gdb_restore(use_uffd, huge_pages, rootfs):
    """Restore a snapshot under GDB and debug the (KASLR-on) guest kernel."""
    bin_dir = host_tools.cargo_build.build_gdb()
    if use_uffd:
        host_tools.cargo_build.cargo(
            "build",
            f"--example uffd_on_demand_handler --features gdb "
            f"--target {host_tools.cargo_build.DEFAULT_TARGET}",
            env={"CARGO_TARGET_DIR": str(bin_dir.parents[1])},
        )
    vmfcty = MicroVMFactory(bin_dir)

    base = vmfcty.build(KERNEL, rootfs)
    base.memory_monitor = None
    base.spawn()
    base.basic_config(vcpu_count=2, mem_size_mib=512, huge_pages=huge_pages)
    base.add_net_iface()
    base.start()
    base.wait_for_ssh_up()
    snapshot = base.snapshot_full()
    slide = _recover_slide(bin_dir / "snapshot-editor", snapshot.vmstate, KERNEL)
    base.kill()

    uvm = vmfcty.build()
    uvm.memory_monitor = None
    uvm.spawn(validate_api=False)
    gdb_socket = Path(uvm.jailer.chroot_path(), "gdb.socket")
    gdb_out = Path(uvm.path) / "gdb_out.txt"

    gdb_commands = (
        _prelude(slide, gdb_socket)
        + """
    echo \\n=== STRUCT ===\\n
    print sizeof(struct task_struct)
    print init_task.pid
    print init_task.comm
    echo \\n=== MEMORY ===\\n
    x/2xg &init_task
    echo \\n=== THREADS ===\\n
    info threads
    echo \\n=== THREAD2-BT ===\\n
    thread 2
    bt
    echo \\n=== BREAKPOINT ===\\n
    thread 1
    break do_idle
    continue
    bt
    echo \\n=== DONE ===\\n
    kill
    """
    )
    gdb_proc = _spawn_gdb(gdb_socket, gdb_out, gdb_commands)

    uffd_handler_name = "on_demand" if use_uffd else None
    uvm.restore_from_snapshot(
        snapshot,
        resume=True,
        uffd_handler_name=uffd_handler_name,
        gdb_socket_path="gdb.socket",
    )

    timed_out = False
    try:
        gdb_proc.wait(timeout=GDB_TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        gdb_proc.kill()

    out = gdb_out.read_text() if gdb_out.exists() else "(no gdb output captured)"
    diag = f"\nslide={slide:#x} timed_out={timed_out}\n--- gdb output ---\n{out}"

    assert not timed_out, f"gdb did not finish in {GDB_TIMEOUT}s:{diag}"
    assert "=== DONE ===" in out, f"gdb script did not run to completion:{diag}"
    assert "swapper" in out, f"init_task.comm (swapper) not read:{diag}"
    assert "$1 = " in out, f"sizeof(struct task_struct) not resolved:{diag}"
    assert (
        "Breakpoint 1, " in out and "do_idle" in out
    ), f"breakpoint on do_idle not hit:{diag}"
    assert out.count("Vcpu ID:") >= 2, f"both vCPUs not enumerated by gdb:{diag}"
    assert (
        "#0 " in out.split("=== THREAD2-BT ===", 1)[-1]
    ), f"per-vCPU backtrace of vCPU 1 not resolved:{diag}"

    uvm.kill()


# A guest workload that continuously page-faults: repeatedly mmap an anonymous
# region and write every page, attributed to comm "python3". Throttled so it
# faults steadily without starving sshd.
_FAULTER_PY = b"""import mmap, time
ms = []
while True:
    m = mmap.mmap(-1, 4 * 1024 * 1024)
    m.write(b"x" * (4 * 1024 * 1024))
    ms.append(m)
    if len(ms) > 4:
        ms.pop(0)
    time.sleep(0.05)
"""


@pytest.mark.parametrize(
    "huge_pages",
    [HugePagesConfig.NONE, HugePagesConfig.HUGETLBFS_2MB],
    ids=["4k", "2M"],
)
@pytest.mark.skipif(
    platform.machine() != "x86_64", reason="restore-path GDB wiring is x86_64-only"
)
def test_gdb_restore_fault_attribution(huge_pages, rootfs):
    """Useful application: attribute guest page faults during restore to the
    responsible process and VMA — invisible to host/UFFD telemetry. Breaks
    handle_mm_fault on the restored (KASLR-on) VM and reads, per fault, the
    faulting process (vma->vm_mm->owner) + VMA + address from the SysV args."""
    bin_dir = host_tools.cargo_build.build_gdb()
    host_tools.cargo_build.cargo(
        "build",
        f"--example uffd_on_demand_handler --features gdb "
        f"--target {host_tools.cargo_build.DEFAULT_TARGET}",
        env={"CARGO_TARGET_DIR": str(bin_dir.parents[1])},
    )
    vmfcty = MicroVMFactory(bin_dir)

    # Two vCPUs on purpose: both hammer handle_mm_fault, so the gdb event loop has to
    # coalesce concurrent breakpoint hits and drain the stale debug events of the
    # force-paused siblings on each resume. This is the regression test for that drain
    # — without it the pause/resume handshake desyncs under the fault storm and the
    # connection drops.
    base = vmfcty.build(KERNEL, rootfs)
    base.memory_monitor = None
    base.spawn()
    base.basic_config(vcpu_count=2, mem_size_mib=512, huge_pages=huge_pages)
    base.add_net_iface()
    base.start()
    base.wait_for_ssh_up()

    b64 = base64.b64encode(_FAULTER_PY).decode()
    base.ssh.check_output(f"echo {b64} | base64 -d > /tmp/faulter.py")
    base.ssh.check_output("nohup python3 /tmp/faulter.py >/dev/null 2>&1 </dev/null &")
    time.sleep(3)
    snapshot = base.snapshot_full()
    slide = _recover_slide(bin_dir / "snapshot-editor", snapshot.vmstate, KERNEL)
    base.kill()

    uvm = vmfcty.build()
    uvm.memory_monitor = None
    uvm.spawn(validate_api=False)
    gdb_socket = Path(uvm.jailer.chroot_path(), "gdb.socket")
    gdb_out = Path(uvm.path) / "gdb_fault_out.txt"

    gdb_commands = (
        _prelude(slide, gdb_socket)
        + """
    break *handle_mm_fault
    set $i = 0
    while $i < 40
      continue
      set $vma = (struct vm_area_struct *)$rdi
      set $mm = $vma->vm_mm
      if $mm != 0
        set $task = $mm->owner
        if $task != 0
          printf "FAULT comm=%s pid=%d addr=0x%lx vma=0x%lx-0x%lx flags=0x%lx\\n", $task->comm, $task->pid, $rsi, $vma->vm_start, $vma->vm_end, $vma->vm_flags
        end
      end
      set $i = $i + 1
    end
    echo \\n=== DONE ===\\n
    kill
    """
    )
    gdb_proc = _spawn_gdb(gdb_socket, gdb_out, gdb_commands)
    uvm.restore_from_snapshot(
        snapshot,
        resume=True,
        uffd_handler_name="on_demand",
        gdb_socket_path="gdb.socket",
    )

    timed_out = False
    try:
        gdb_proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        timed_out = True
        gdb_proc.kill()

    out = gdb_out.read_text() if gdb_out.exists() else "(no gdb output captured)"
    diag = f"\nslide={slide:#x} timed_out={timed_out}\n--- gdb output ---\n{out}"

    assert not timed_out, f"gdb did not finish in 120s:{diag}"
    assert "=== DONE ===" in out, f"gdb script did not run to completion:{diag}"

    faults = [ln for ln in out.splitlines() if ln.startswith("FAULT comm=")]
    print("\nGuest faults attributed during restore (sample):")
    print("\n".join(faults[:8]))
    assert len(faults) >= 10, f"too few faults captured ({len(faults)}):{diag}"
    assert any(
        "comm=python3" in ln for ln in faults
    ), f"workload process not attributed:{diag}"
    vmas = re.findall(r"vma=0x([0-9a-f]+)-0x([0-9a-f]+)", out)
    assert vmas and all(
        int(s, 16) < int(e, 16) for s, e in vmas
    ), f"no valid VMA ranges captured:{diag}"

    uvm.kill()
