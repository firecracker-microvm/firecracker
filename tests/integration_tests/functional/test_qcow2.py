# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exercise independent qemu-img QCOW2 images through real guest block I/O."""

import fcntl
import hashlib
import json
import os
from pathlib import Path

import pytest
from tenacity import Retrying, stop_after_delay, wait_fixed

from framework.artifacts import (
    ACPI_GUEST_KERNELS,
    pin_guest_kernel,
    pin_pci,
)
from framework.utils import check_output, get_threads, run_cmd
from framework.utils_vsock import (
    ECHO_SERVER_PORT,
    VSOCK_UDS_PATH,
    start_guest_echo_server,
    vsock_connect_to_guest,
)
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend
from host_tools.cargo_build import run_seccompiler_bin

CLUSTER_SIZE = 64 * 1024
DISK_SIZE = 4 * 1024 * 1024
GUEST_DATA = "/dev/shm/qcow2-data"


@pytest.fixture(autouse=True)
def qcow2_functional_api_checks(microvm_factory):
    """Judge functional requests by their results and data, allowing slow storage."""
    microvm_factory.kwargs["time_api_requests"] = False


def _convert(source, target, *, compressed=False, compat="1.1"):
    """Generate a self-contained image without using the implementation under test."""
    check_output(
        [
            "qemu-img",
            "convert",
            *(["-c"] if compressed else []),
            "-f",
            "raw",
            "-O",
            "qcow2",
            "-o",
            f"cluster_size={CLUSTER_SIZE},compat={compat}",
            str(source),
            str(target),
        ]
    )


def _image(vm, name, seed=0, *, compressed=False, compat="1.1", size=DISK_SIZE):
    """Create allocated nonzero clusters, a sparse middle, and a nonzero last sector."""
    raw = Path(vm.fsfiles) / f"{name}.raw"
    image = raw.with_suffix(".qcow2")
    pattern = bytes((index + seed) % 255 + 1 for index in range(255))
    allocated = (pattern * (2 * CLUSTER_SIZE // len(pattern) + 1))[: 2 * CLUSTER_SIZE]
    expected = bytearray(size)
    expected[: len(allocated)] = allocated
    expected[-512:] = (pattern * 3)[:512]
    with raw.open("wb") as output:
        output.truncate(size)
        output.write(allocated)
        output.seek(size - 512)
        output.write(expected[-512:])
    _convert(raw, image, compressed=compressed, compat=compat)
    return image, expected


def _assert_guest_data(vm, expected, device="/dev/vdb", *, cpu=None):
    """Read every sector directly, also leaving device-written dirty memory in tmpfs."""
    prefix = "" if cpu is None else f"taskset -c {cpu} "
    _, stdout, _ = vm.ssh.check_output(
        f"{prefix}dd if={device} of={GUEST_DATA} bs=65536 iflag=direct status=none"
        f" && sha256sum {GUEST_DATA}"
    )
    assert stdout.split()[0] == hashlib.sha256(expected).hexdigest()


def _write_pattern(
    vm, expected, offset, length, seed, *, flush=True
):  # pylint: disable=too-many-arguments
    """Write nonzero sector-aligned data, including allocations within sparse clusters."""
    payload = bytes((index + seed) % 251 + 1 for index in range(length))
    source = Path(vm.fsfiles) / "qcow2-write.bin"
    source.write_bytes(payload)
    vm.ssh.scp_put(str(source), "/dev/shm/qcow2-write")
    conv = "notrunc,fsync" if flush else "notrunc"
    vm.ssh.check_output(
        "dd if=/dev/shm/qcow2-write of=/dev/vdb bs=512"
        f" seek={offset // 512} count={length // 512}"
        f" oflag=direct conv={conv} status=none"
    )
    expected[offset : offset + length] = payload


def _check_closed_image(image, expected):
    """Validate metadata and logical contents after all Firecracker handles are closed."""
    check_output(["qemu-img", "check", "-f", "qcow2", str(image)])
    raw = image.with_suffix(".checked.raw")
    check_output(
        ["qemu-img", "convert", "-f", "qcow2", "-O", "raw", str(image), str(raw)]
    )
    assert raw.read_bytes() == expected


def _deny_storage_syscall(vm, syscall="fsync"):
    """Inject EIO for a storage syscall in this VM's failure tests."""
    filter_path = Path(vm.fsfiles) / "sync-error.json"
    filter_path.write_text(
        json.dumps(
            {
                thread: {
                    "default_action": "allow",
                    "filter_action": {"errno": 5},
                    "filter": [{"syscall": syscall}],
                }
                for thread in ["vmm", "api", "vcpu", "blk_worker"]
            }
        )
    )
    bpf_path = filter_path.with_suffix(".bpf")
    run_seccompiler_bin(bpf_path=bpf_path, json_path=filter_path)
    vm.create_jailed_resource(bpf_path)
    vm.jailer.extra_args["seccomp-filter"] = bpf_path.name


@pin_pci(False)
@pin_vm_backend(VM_BACKEND_KVM)
def test_qcow2_discard_storage_failure(uvm, io_engine, num_queues):
    """A failed hole punch keeps the discard queue usable and the image consistent."""
    _deny_storage_syscall(uvm, "fallocate")
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    image, expected = _image(uvm, "discard-error")
    uvm.add_drive(
        "qcow2",
        image,
        image_format="Qcow2",
        io_engine=io_engine,
        num_queues=num_queues,
        cache_type="Writeback",
        discard=True,
    )
    uvm.start()
    before = image.stat().st_blocks
    for _ in range(2):
        uvm.ssh.check_output(
            f"blkdiscard -f -o {CLUSTER_SIZE} -l {CLUSTER_SIZE} /dev/vdb"
        )
        expected[CLUSTER_SIZE : 2 * CLUSTER_SIZE] = bytes(CLUSTER_SIZE)
        _assert_guest_data(uvm, expected)
        assert image.stat().st_blocks >= before
    uvm.snapshot_full()
    uvm.kill()
    result = run_cmd(["qemu-img", "check", "-f", "qcow2", "--output=json", str(image)])
    assert result.returncode in (0, 3), (result.stdout, result.stderr)
    assert json.loads(result.stdout).get("corruptions", 0) == 0


def _assert_queue_mode(vm, num_queues, drive_id="qcow2", *, io_engine=None):
    assert (f"fc_q0_{drive_id}" in get_threads(vm.firecracker_pid)) == (
        num_queues is not None
    )
    if io_engine is not None:
        drive = next(
            drive
            for drive in vm.api.vm_config.get().json()["drives"]
            if drive["drive_id"] == drive_id
        )
        assert drive["io_engine"] == io_engine


@pytest.mark.parametrize("compat", ["0.10", "1.1"], ids=["v2", "v3"])
@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("internal_snapshot", [False, True])
@pin_pci(False)
@pin_vm_backend(VM_BACKEND_KVM)
def test_qcow2_writable_io_and_discard(
    uvm, io_engine, num_queues, compat, compressed, internal_snapshot
):
    """Guest COW writes and discard preserve QEMU images, snapshots and physical space."""
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    image, expected = _image(uvm, "discard", compat=compat, compressed=compressed)
    original = bytes(expected)
    if internal_snapshot:
        check_output(["qemu-img", "snapshot", "-c", "before-discard", str(image)])
    uvm.add_drive(
        "qcow2",
        image,
        image_format="Qcow2",
        io_engine=io_engine,
        num_queues=num_queues,
        cache_type="Writeback",
        discard=True,
    )
    uvm.start()
    _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
    _, stdout, _ = uvm.ssh.check_output("cat /sys/block/vdb/queue/discard_max_bytes")
    assert int(stdout) > 0
    _, stdout, _ = uvm.ssh.check_output("blockdev --getsize64 /dev/vdb")
    assert int(stdout) == DISK_SIZE
    _assert_guest_data(uvm, expected)
    _write_pattern(uvm, expected, 4 * CLUSTER_SIZE, 16 * CLUSTER_SIZE, 73)
    for offset, length in [
        (512, 512),
        (CLUSTER_SIZE - 512, CLUSTER_SIZE + 1024),
        (CLUSTER_SIZE - 512, CLUSTER_SIZE + 1024),
        (DISK_SIZE - 512, 512),
    ]:
        uvm.ssh.check_output(f"blkdiscard -f -o {offset} -l {length} /dev/vdb")
        expected[offset : offset + length] = bytes(length)
        _assert_guest_data(uvm, expected)
    _write_pattern(uvm, expected, CLUSTER_SIZE - 512, 2 * CLUSTER_SIZE + 1024, 31)
    _write_pattern(uvm, expected, 8 * CLUSTER_SIZE + 512, 4096, 47)
    _write_pattern(uvm, expected, DISK_SIZE - 4096, 4096, 59)
    _assert_guest_data(uvm, expected)
    before = image.stat()
    uvm.ssh.check_output(
        f"blkdiscard -f -o {4 * CLUSTER_SIZE} -l {16 * CLUSTER_SIZE} /dev/vdb"
        " && blockdev --flushbufs /dev/vdb"
    )
    expected[4 * CLUSTER_SIZE : 20 * CLUSTER_SIZE] = bytes(16 * CLUSTER_SIZE)
    after = image.stat()
    assert before.st_blocks - after.st_blocks >= 14 * CLUSTER_SIZE // 512
    assert after.st_size == before.st_size
    _assert_guest_data(uvm, expected)
    _write_pattern(uvm, expected, 4 * CLUSTER_SIZE, 16 * CLUSTER_SIZE, 91)
    assert image.stat().st_size <= before.st_size + 2 * CLUSTER_SIZE
    uvm.snapshot_full()
    uvm.kill()
    _check_closed_image(image, expected)
    if internal_snapshot:
        check_output(["qemu-img", "snapshot", "-a", "before-discard", str(image)])
        _check_closed_image(image, original)


def _assert_readonly_multiqueue(vm, expected):
    """Verify shared read-only data, queue workers, and negotiated write protection."""
    _assert_queue_mode(vm, 2)
    assert "fc_q1_qcow2" in get_threads(vm.firecracker_pid)
    _assert_queue_mode(vm, 1, drive_id="shared")
    _, stdout, _ = vm.ssh.check_output("ls -d /sys/block/vdb/mq/*")
    queues = stdout.split()
    assert len(queues) == 2
    for queue in queues:
        _, stdout, _ = vm.ssh.check_output(f"cat {queue}/cpu_list")
        cpu = int(stdout.strip().split(",", 1)[0].split("-", 1)[0])
        _assert_guest_data(vm, expected, device="/dev/vdb", cpu=cpu)
    for device in ["/dev/vdb", "/dev/vdc"]:
        _assert_guest_data(vm, expected, device=device)
        _, stdout, _ = vm.ssh.check_output(f"blockdev --getro {device}")
        assert int(stdout) == 1
        rc, _, stderr = vm.ssh.run(
            f"dd if=/dev/zero of={device} bs=512 count=1 oflag=direct status=none"
        )
        assert rc != 0
        assert "Operation not permitted" in stderr


@pin_pci(False)
def test_qcow2_live_truncation(uvm, io_engine, num_queues):
    """Missing allocated bytes fail guest I/O without changing valid or sparse reads."""
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    image, expected = _image(uvm, "truncated")
    _, stdout, _ = check_output(
        ["qemu-img", "map", "--output=json", "-f", "qcow2", str(image)]
    )
    tail = next(
        extent
        for extent in json.loads(stdout)
        if extent["start"] <= DISK_SIZE - 512 < extent["start"] + extent["length"]
    )
    assert tail["data"] and tail["present"]
    host_offset = tail["offset"] + DISK_SIZE - 512 - tail["start"]
    uvm.add_drive(
        "qcow2", image, image_format="Qcow2", io_engine=io_engine, num_queues=num_queues
    )
    uvm.start()
    _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
    _assert_guest_data(uvm, expected)

    os.truncate(image, host_offset + 511)
    rc, _, stderr = uvm.ssh.run(
        "dd if=/dev/vdb of=/dev/shm/truncated-read bs=512"
        f" skip={DISK_SIZE // 512 - 1} count=1 iflag=direct status=none"
    )
    assert rc != 0
    assert "Input/output error" in stderr
    # An I/O error must leave the queue able to allocate and read another cluster.
    offset = 8 * CLUSTER_SIZE
    _write_pattern(uvm, expected, offset, 4096, 97)
    _, stdout, _ = uvm.ssh.check_output(
        f"dd if=/dev/vdb bs=512 skip={offset // 512} count=8"
        " iflag=direct status=none | sha256sum"
    )
    assert (
        stdout.split()[0]
        == hashlib.sha256(expected[offset : offset + 4096]).hexdigest()
    )


@pin_pci(False)
def test_qcow2_parallel_writes_flush_and_discard(uvm, io_engine, num_queues):
    """Concurrent partial-cluster writes survive flush, discard, and subsequent reuse."""
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    image, expected = _image(uvm, "parallel", compressed=True)
    uvm.add_drive(
        "qcow2",
        image,
        image_format="Qcow2",
        io_engine=io_engine,
        num_queues=num_queues,
        cache_type="Writeback",
        discard=True,
    )
    uvm.start()
    _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
    payload = bytes(index % 251 + 1 for index in range(CLUSTER_SIZE))
    source = Path(uvm.fsfiles) / "qcow2-parallel.bin"
    source.write_bytes(payload)
    uvm.ssh.scp_put(str(source), "/dev/shm/qcow2-parallel")

    # Separate writes fill one compressed cluster, then one previously sparse cluster.
    for offset in [0, 8 * CLUSTER_SIZE]:
        commands = []
        for index in range(4):
            commands.append(
                "dd if=/dev/shm/qcow2-parallel of=/dev/vdb bs=16384"
                f" skip={index} seek={offset // 16384 + index} count=1"
                f" oflag=direct conv=notrunc status=none & p{index}=$!"
            )
        commands.append(
            'wait "$p0" && wait "$p1" && wait "$p2" && wait "$p3"'
            " && blockdev --flushbufs /dev/vdb"
        )
        uvm.ssh.check_output("; ".join(commands))
        expected[offset : offset + CLUSTER_SIZE] = payload
        _assert_guest_data(uvm, expected)

    offset = 8 * CLUSTER_SIZE
    uvm.ssh.check_output(f"blkdiscard -f -o {offset} -l {CLUSTER_SIZE} /dev/vdb")
    expected[offset : offset + CLUSTER_SIZE] = bytes(CLUSTER_SIZE)
    _assert_guest_data(uvm, expected)
    _write_pattern(uvm, expected, offset + 512, 4096, 83)
    _assert_guest_data(uvm, expected)
    uvm.kill()
    _check_closed_image(image, expected)


@pin_pci(False)
def test_qcow2_unclean_shutdown(uvm, io_engine, num_queues):
    """Published L2 tables retain their refcounts after Firecracker is killed."""
    image = Path(uvm.fsfiles) / "unclean.qcow2"
    check_output(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-o",
            "cluster_size=512",
            str(image),
            "4M",
        ]
    )
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    uvm.add_drive(
        "qcow2", image, image_format="Qcow2", io_engine=io_engine, num_queues=num_queues
    )
    uvm.start()
    expected = bytearray(DISK_SIZE)
    for offset in (512, 2 * 1024 * 1024 - 512, 3 * 1024 * 1024):
        _write_pattern(uvm, expected, offset, 65536, 73, flush=False)
    uvm.kill()

    result = run_cmd(["qemu-img", "check", "-f", "qcow2", "--output=json", str(image)])
    # Unflushed writes can leak clusters, but must not publish unowned metadata.
    assert result.returncode in (0, 3), (result.stdout, result.stderr)
    assert json.loads(result.stdout).get("corruptions", 0) == 0


@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pin_pci(True)
@pytest.mark.parametrize("cache_type", ["Unsafe", "Writeback"])
@pytest.mark.parametrize("force", [False, True], ids=["graceful", "forced"])
@pin_vm_backend(VM_BACKEND_KVM)
def test_qcow2_pci_unplug(
    uvm, microvm_factory, io_engine, num_queues, cache_type, force
):
    """Unplug flushes dirty mappings and releases locks before and after restore."""
    uvm.spawn()
    uvm.basic_config(pcie_hotplug_ports=1)
    uvm.add_net_iface()
    uvm.start()
    vm = uvm

    for phase in range(2):
        image, expected = _image(vm, f"hotplug-{phase}")
        vm.add_drive(
            "qcow2",
            image,
            image_format="Qcow2",
            io_engine=io_engine,
            num_queues=num_queues,
            cache_type=cache_type,
            discard=True,
        )
        for attempt in Retrying(
            stop=stop_after_delay(10), wait=wait_fixed(0.1), reraise=True
        ):
            with attempt:
                rc, _, _ = vm.ssh.run(
                    "dd if=/dev/vdb of=/dev/null bs=512 count=1 iflag=direct status=none"
                )
                assert rc == 0
        _assert_queue_mode(vm, num_queues, io_engine=io_engine)
        _assert_guest_data(vm, expected)
        _write_pattern(vm, expected, 6 * CLUSTER_SIZE + 512, 4096, 73, flush=False)
        vm.ssh.check_output(f"blkdiscard -f -o 512 -l {CLUSTER_SIZE} /dev/vdb")
        expected[512 : 512 + CLUSTER_SIZE] = bytes(CLUSTER_SIZE)
        _assert_guest_data(vm, expected)

        if phase:
            snapshot = vm.snapshot_full()
            vm.kill()
            vm = microvm_factory.build_from_snapshot(snapshot)
            image = Path(vm.chroot()) / Path(vm.disks["qcow2"]).name
            _assert_queue_mode(vm, num_queues, io_engine=io_engine)
            _assert_guest_data(vm, expected)
            _write_pattern(
                vm, expected, 10 * CLUSTER_SIZE + 512, 4096, 131, flush=False
            )
            _assert_guest_data(vm, expected)

        vm.api.drive.delete("qcow2", force=force)
        for attempt in Retrying(
            stop=stop_after_delay(15), wait=wait_fixed(0.1), reraise=True
        ):
            with attempt:
                assert "qcow2" not in {
                    drive["drive_id"]
                    for drive in vm.api.vm_config.get().json()["drives"]
                }
                rc, _, _ = vm.ssh.run("test ! -b /dev/vdb")
                assert rc == 0
        _assert_queue_mode(vm, None)
        del vm.disks["qcow2"]
        with image.open("rb") as probe:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _check_closed_image(image, expected)


@pin_pci(False)
@pin_vm_backend(VM_BACKEND_KVM)
def test_qcow2_snapshot_sync_failure(uvm, io_engine, num_queues):
    """A failed disk sync rejects snapshots without losing the paused device or its data."""
    _deny_storage_syscall(uvm)
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    image, expected = _image(uvm, "sync-error")
    uvm.add_drive(
        "qcow2",
        image,
        image_format="Qcow2",
        io_engine=io_engine,
        num_queues=num_queues,
        cache_type="Writeback",
    )
    uvm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/" + VSOCK_UDS_PATH)
    uvm.start()
    _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
    uds_path = start_guest_echo_server(uvm)
    with vsock_connect_to_guest(uds_path, ECHO_SERVER_PORT) as connection:
        connection.settimeout(5)
        connection.sendall(b"x")
        assert connection.recv(1) == b"x"
        for attempt in range(2):
            _write_pattern(
                uvm, expected, (6 + attempt) * CLUSTER_SIZE + 512, 4096, 23, flush=False
            )
            uvm.pause()
            with pytest.raises(
                RuntimeError,
                match=r"QCOW2 (metadata writeback|sync) error:.*os error 5",
            ):
                uvm.api.snapshot_create.put(
                    mem_file_path="failed_mem",
                    snapshot_path="failed_state",
                    snapshot_type="Full",
                    sync_snapshot_files=False,
                )
            assert not (Path(uvm.chroot()) / "failed_state").exists()
            uvm.resume()
            _assert_guest_data(uvm, expected)
            connection.sendall(b"x")
            assert connection.recv(1) == b"x"
    uvm.kill()
    # Every fsync is denied, so shutdown cannot promise durability of the cached mappings.
    result = run_cmd(["qemu-img", "check", "-f", "qcow2", "--output=json", str(image)])
    assert result.returncode in (0, 3), (result.stdout, result.stderr)
    assert json.loads(result.stdout).get("corruptions", 0) == 0


@pin_guest_kernel(ACPI_GUEST_KERNELS)
@pin_pci(True)
@pytest.mark.parametrize("vm_backend", ["kvm"], indirect=True)
def test_qcow2_force_unplug_sync_failure(uvm, io_engine, num_queues):
    """A failed forced unplug retains the running device, its lock, and usable queues."""
    _deny_storage_syscall(uvm)
    uvm.spawn()
    uvm.basic_config(pcie_hotplug_ports=1)
    uvm.add_net_iface()
    uvm.start()
    image, expected = _image(uvm, "unplug-sync-error")
    uvm.add_drive(
        "qcow2",
        image,
        image_format="Qcow2",
        io_engine=io_engine,
        num_queues=num_queues,
        cache_type="Writeback",
    )
    for attempt in Retrying(
        stop=stop_after_delay(10), wait=wait_fixed(0.1), reraise=True
    ):
        with attempt:
            rc, _, _ = uvm.ssh.run(
                "dd if=/dev/vdb of=/dev/null bs=512 count=1 iflag=direct status=none"
            )
            assert rc == 0
    _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
    _write_pattern(uvm, expected, 6 * CLUSTER_SIZE + 512, 4096, 73, flush=False)
    config = uvm.api.vm_config.get().json()
    assert uvm.state == "Running"

    for attempt in range(2):
        with pytest.raises(
            RuntimeError,
            match=r"QCOW2 (metadata writeback|sync) error:.*os error 5",
        ):
            uvm.api.drive.delete("qcow2", force=True)
        assert uvm.state == "Running"
        assert uvm.api.vm_config.get().json() == config
        _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
        with image.open("rb") as probe:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _assert_guest_data(uvm, expected)
        _write_pattern(
            uvm, expected, (8 + attempt) * CLUSTER_SIZE + 512, 4096, 47, flush=False
        )
        _assert_guest_data(uvm, expected)
    uvm.kill()


@pytest.mark.parametrize("cache_type", ["Unsafe", "Writeback"])
@pin_vm_backend(VM_BACKEND_KVM)
def test_qcow2_full_and_diff_snapshot(
    uvm, microvm_factory, io_engine, num_queues, cache_type
):
    """Full/diff restore preserves dirty reads, writable data, and negotiated discard."""
    uvm.spawn()
    uvm.basic_config(track_dirty_pages=True)
    uvm.add_net_iface()
    image, expected = _image(uvm, "snapshot")
    uvm.add_drive(
        "qcow2",
        image,
        image_format="Qcow2",
        io_engine=io_engine,
        num_queues=num_queues,
        cache_type=cache_type,
        discard=True,
    )
    uvm.start()
    _write_pattern(uvm, expected, 6 * CLUSTER_SIZE + 512, 4096, 23, flush=False)
    _assert_guest_data(uvm, expected)
    full = uvm.snapshot_full(mem_path="full_mem", vmstate_path="full_state")
    uvm.kill()
    _check_closed_image(image, expected)

    restored = microvm_factory.build(pci=uvm.pci_enabled)
    restored.spawn()
    restored.restore_from_snapshot(full, resume=True)
    _assert_queue_mode(restored, num_queues, io_engine=io_engine)
    _, stdout, _ = restored.ssh.check_output(f"sha256sum {GUEST_DATA}")
    assert stdout.split()[0] == hashlib.sha256(expected).hexdigest()
    _assert_guest_data(restored, expected)
    restored.ssh.check_output(f"blkdiscard -f -o 512 -l {CLUSTER_SIZE} /dev/vdb")
    expected[512 : 512 + CLUSTER_SIZE] = bytes(CLUSTER_SIZE)
    _assert_guest_data(restored, expected)

    base = restored.snapshot_full(mem_path="base_mem", vmstate_path="base_state")
    restored.resume()
    _write_pattern(
        restored,
        expected,
        12 * CLUSTER_SIZE - 512,
        CLUSTER_SIZE + 1024,
        79,
        flush=False,
    )
    restored.ssh.check_output(
        f"blkdiscard -f -o {CLUSTER_SIZE} -l {CLUSTER_SIZE} /dev/vdb"
    )
    expected[CLUSTER_SIZE : 2 * CLUSTER_SIZE] = bytes(CLUSTER_SIZE)
    _assert_guest_data(restored, expected)
    diff = restored.snapshot_diff(mem_path="diff_mem", vmstate_path="diff_state")
    restored.kill()
    _check_closed_image(image, expected)
    snapshot = diff.rebase_snapshot(
        base, use_snapshot_editor=True, binary_dir=uvm.fc_binary_path.parent
    )
    resumed = microvm_factory.build(pci=uvm.pci_enabled)
    resumed.spawn()
    resumed.restore_from_snapshot(snapshot, resume=True)
    _assert_queue_mode(resumed, num_queues, io_engine=io_engine)
    _, stdout, _ = resumed.ssh.check_output(f"sha256sum {GUEST_DATA}")
    assert stdout.split()[0] == hashlib.sha256(expected).hexdigest()
    _assert_guest_data(resumed, expected)
    resumed.ssh.check_output(f"blkdiscard -f -o {DISK_SIZE - 512} -l 512 /dev/vdb")
    expected[-512:] = bytes(512)
    _write_pattern(resumed, expected, 20 * CLUSTER_SIZE + 512, 4096, 131)
    _assert_guest_data(resumed, expected)
    resumed.snapshot_full()
    resumed.kill()
    _check_closed_image(image, expected)


@pin_pci(False)
@pin_vm_backend(VM_BACKEND_KVM)
def test_qcow2_patch_dirty_image(uvm, microvm_factory, io_engine, num_queues):
    """PATCH keeps dirty state on no-op/error and flushes the old image before replacing it."""
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    original, original_data = _image(uvm, "original")
    replacement, replacement_data = _image(
        uvm, "replacement", seed=83, size=2 * DISK_SIZE
    )
    alias = Path(uvm.fsfiles) / "original-alias.qcow2"
    os.link(original, alias)
    invalid = Path(uvm.fsfiles) / "invalid.qcow2"
    invalid.write_bytes(b"not a QCOW2 image" * 256)
    uvm.add_drive(
        "qcow2",
        original,
        image_format="Qcow2",
        io_engine=io_engine,
        num_queues=num_queues,
        cache_type="Writeback",
    )
    uvm.start()
    _write_pattern(uvm, original_data, 8 * CLUSTER_SIZE + 512, 4096, 19, flush=False)
    threads = get_threads(uvm.firecracker_pid).get("fc_q0_qcow2")
    uvm.api.drive.patch(
        drive_id="qcow2", path_on_host=uvm.create_jailed_resource(alias)
    )
    assert get_threads(uvm.firecracker_pid).get("fc_q0_qcow2") == threads
    _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
    _assert_guest_data(uvm, original_data)

    with pytest.raises(RuntimeError, match="QCOW2|qcow2"):
        uvm.api.drive.patch(
            drive_id="qcow2", path_on_host=uvm.create_jailed_resource(invalid)
        )
    _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
    _assert_guest_data(uvm, original_data)
    _write_pattern(uvm, original_data, 10 * CLUSTER_SIZE - 512, 8192, 41, flush=False)
    uvm.api.drive.patch(
        drive_id="qcow2", path_on_host=uvm.create_jailed_resource(replacement)
    )
    uvm.disks["qcow2"] = replacement
    for attempt in Retrying(
        stop=stop_after_delay(10), wait=wait_fixed(0.1), reraise=True
    ):
        with attempt:
            _, stdout, _ = uvm.ssh.check_output("blockdev --getsize64 /dev/vdb")
            assert int(stdout) == len(replacement_data)
    _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
    _assert_guest_data(uvm, replacement_data)
    _write_pattern(uvm, replacement_data, len(replacement_data) - 512, 512, 67)
    _assert_guest_data(uvm, replacement_data)
    snapshot = uvm.snapshot_full()
    uvm.kill()
    _check_closed_image(original, original_data)
    _check_closed_image(replacement, replacement_data)
    restored = microvm_factory.build_from_snapshot(snapshot)
    _assert_queue_mode(restored, num_queues, io_engine=io_engine)
    _, stdout, _ = restored.ssh.check_output("blockdev --getsize64 /dev/vdb")
    assert int(stdout) == len(replacement_data)
    _assert_guest_data(restored, replacement_data)
    _write_pattern(restored, replacement_data, len(replacement_data) - 512, 512, 97)
    _assert_guest_data(restored, replacement_data)
    restored_image = Path(restored.chroot()) / Path(restored.disks["qcow2"]).name
    restored.kill()
    _check_closed_image(restored_image, replacement_data)


@pytest.mark.parametrize("feature", ["backing", "external", "encrypted", "extended-l2"])
@pin_pci(False)
def test_qcow2_rejects_unsupported_images(uvm, io_engine, num_queues, feature):
    """PUT and live PATCH reject unsupported QEMU images without modifying their files."""
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    original, expected = _image(uvm, "supported")
    raw = original.with_suffix(".raw")
    image = Path(uvm.fsfiles) / "unsupported.qcow2"
    external = Path(uvm.fsfiles) / "external.raw"
    options, error = {
        "backing": (
            f"backing_file={raw.name},backing_fmt=raw",
            "qcow2 backing files are not permitted",
        ),
        "external": (
            f"data_file={external.name},data_file_raw=on",
            "qcow2 external data files are not permitted",
        ),
        "encrypted": (
            "encrypt.format=luks,encrypt.key-secret=key,encrypt.iter-time=1",
            "qcow2 encryption method 2 is not supported",
        ),
        "extended-l2": ("extended_l2=on", "Unrecognized incompatible feature"),
    }[feature]
    check_output(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            *(
                ["--object", "secret,id=key,data=test-password"]
                if feature == "encrypted"
                else []
            ),
            "-o",
            options,
            str(image),
            str(DISK_SIZE),
        ],
        cwd=image.parent,
    )
    protected = [image, raw] + ([external] if external.exists() else [])
    for dependency in protected[1:]:
        uvm.create_jailed_resource(dependency)
    digests = {
        path: hashlib.sha256(path.read_bytes()).hexdigest() for path in protected
    }
    config = uvm.api.vm_config.get().json()
    for read_only in [False, True]:
        with pytest.raises(RuntimeError, match=error):
            uvm.add_drive(
                "rejected",
                image,
                image_format="Qcow2",
                io_engine=io_engine,
                is_read_only=read_only,
            )
        assert uvm.api.vm_config.get().json() == config
        with image.open("rb") as probe:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    uvm.add_drive(
        "qcow2",
        original,
        image_format="Qcow2",
        io_engine=io_engine,
        num_queues=num_queues,
        cache_type="Writeback",
    )
    uvm.start()
    _write_pattern(uvm, expected, 8 * CLUSTER_SIZE + 512, 4096, 43, flush=False)
    config = uvm.api.vm_config.get().json()
    with pytest.raises(RuntimeError, match=error):
        uvm.api.drive.patch(
            drive_id="qcow2", path_on_host=uvm.create_jailed_resource(image)
        )
    assert uvm.api.vm_config.get().json() == config
    with image.open("rb") as probe:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    _assert_queue_mode(uvm, num_queues, io_engine=io_engine)
    _assert_guest_data(uvm, expected)
    _write_pattern(uvm, expected, 10 * CLUSTER_SIZE + 512, 4096, 71)
    _assert_guest_data(uvm, expected)
    uvm.kill()
    assert {
        path: hashlib.sha256(path.read_bytes()).hexdigest() for path in protected
    } == digests
    _check_closed_image(original, expected)


@pin_pci(False)
@pin_vm_backend(VM_BACKEND_KVM)
def test_qcow2_readonly_multiqueue_restore(uvm, microvm_factory):
    """Shared read-only guest queues preserve write protection across restore."""
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    image, expected = _image(uvm, "readonly")
    image_alias = Path(uvm.fsfiles) / "readonly-alias.qcow2"
    os.link(image, image_alias)
    uvm.add_drive("qcow2", image, image_format="Qcow2", is_read_only=True, num_queues=2)
    uvm.add_drive(
        "shared", image_alias, image_format="Qcow2", is_read_only=True, num_queues=1
    )
    uvm.start()
    _assert_readonly_multiqueue(uvm, expected)
    replacement, replacement_data = _image(uvm, "readonly-replacement", seed=91)
    with pytest.raises(RuntimeError, match="multiple queues|multi-queue"):
        uvm.api.drive.patch(
            drive_id="qcow2", path_on_host=uvm.create_jailed_resource(replacement)
        )
    _assert_guest_data(uvm, expected, device="/dev/vdb")
    snapshot = uvm.snapshot_full()
    uvm.kill()
    _check_closed_image(image, expected)
    _check_closed_image(replacement, replacement_data)
    restored = microvm_factory.build(pci=uvm.pci_enabled)
    restored.spawn()
    restored.restore_from_snapshot(snapshot, resume=True)
    _assert_readonly_multiqueue(restored, expected)
    restored.kill()
    _check_closed_image(image, expected)


def test_qcow2_root_squashfs_boot(uvm, io_engine, num_queues):
    """Boot the real squashfs root from QCOW2 and read its full logical contents directly."""
    image = Path(uvm.fsfiles) / "rootfs.qcow2"
    _convert(uvm.rootfs_file, image)
    uvm.spawn()
    uvm.basic_config(add_root_device=False)
    uvm.add_net_iface()
    uvm.add_drive(
        "rootfs",
        image,
        is_root_device=True,
        is_read_only=True,
        image_format="Qcow2",
        io_engine=io_engine,
        num_queues=num_queues,
    )
    uvm.start()
    _assert_queue_mode(uvm, num_queues, drive_id="rootfs", io_engine=io_engine)
    expected = uvm.rootfs_file.read_bytes()
    _assert_guest_data(uvm, expected, device="/dev/vda")
    uvm.ssh.check_output("test -r /etc/os-release && test -d /proc/1")
    uvm.kill()
    _check_closed_image(image, expected)
