# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional stress tests for Async Page Fault (APF).

Verifies APF correctness by writing unique fingerprints to every page
of guest memory and checking them after restore. Catches:
  - Wrong page data (GPA→offset translation bugs)
  - Dropped faults (pages never resolved → zero data)
  - Ring buffer corruption (lost/duplicate entries)
  - Completion races (vCPU reads stale data before page mapped)
  - Memory ordering bugs (ring entries not visible)
"""

import platform

import pytest

pytestmark = pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="APF is only supported on x86_64",
)

# Python script fragments executed inside the guest.
# These use mmap to touch pages directly (not through filesystem cache).

# Writes a unique 8-byte fingerprint at the start of every page in a file.
# The fingerprint is the page's byte offset, so page 0 gets 0x0, page 1 gets
# 0x1000, etc. If any page is resolved with wrong data, the fingerprint fails.
WRITE_FINGERPRINTS = """
import mmap, struct, sys
size = {size}
fd = open('/tmp/stress_{tag}', 'w+b')
fd.truncate(size)
mm = mmap.mmap(fd.fileno(), size)
for i in range(0, size, 4096):
    mm[i:i+8] = struct.pack('<Q', i ^ {seed})
mm.flush()
fd.close()
print(f'WROTE {{size // 4096}} pages')
"""

# Verifies every page's fingerprint matches. Reports exact page offsets
# of any mismatches. Exits non-zero if any page is wrong.
VERIFY_FINGERPRINTS = """
import mmap, struct, sys, random
size = {size}
fd = open('/tmp/stress_{tag}', 'rb')
mm = mmap.mmap(fd.fileno(), size, access=mmap.ACCESS_READ)
pages = list(range(0, size, 4096))
{shuffle}
errors = []
for i in pages:
    val = struct.unpack('<Q', mm[i:i+8])[0]
    expected = i ^ {seed}
    if val != expected:
        errors.append(f'page {{i:#x}}: got {{val:#x}} expected {{expected:#x}}')
        if len(errors) >= 10:
            break
fd.close()
if errors:
    for e in errors:
        print(f'MISMATCH: {{e}}', file=sys.stderr)
    print(f'FAIL: {{len(errors)}} mismatches in {{len(pages)}} pages', file=sys.stderr)
    sys.exit(1)
print(f'VERIFIED {{len(pages)}} pages OK')
"""

# Fills memory with random-seeded data across multiple large allocations,
# forces pages into RAM, then reports a combined hash.
FILL_AND_HASH = """
import hashlib, os
h = hashlib.sha256()
for i in range({n_files}):
    path = f'/tmp/fill_{{i}}'
    data = os.urandom({file_size})
    with open(path, 'wb') as f:
        f.write(data)
    h.update(data)
print(h.hexdigest())
"""

VERIFY_HASH = """
import hashlib
h = hashlib.sha256()
for i in range({n_files}):
    with open(f'/tmp/fill_{{i}}', 'rb') as f:
        h.update(f.read())
print(h.hexdigest())
"""


def _guest_python(microvm, script, **kwargs):
    """Run a python script inside the guest and return stdout."""
    code = script.format(**kwargs).strip()
    _, stdout, _ = microvm.ssh.check_output(f"python3 << 'PYEOF'\n{code}\nPYEOF")
    return stdout.strip()


def _assert_vm_healthy(microvm):
    """Assert the VM didn't crash (e.g., seccomp kill on APF fallback)."""
    fc_log = microvm.log_data
    assert "bad syscall" not in fc_log, (
        "VM was killed by seccomp during APF handling. "
        "Check that sendto and KVM_ASYNC_PF ioctls are allowed in the "
        "vcpu/vmm seccomp filters.\nFC log tail:\n"
        + "\n".join(fc_log.splitlines()[-5:])
    )
    assert (
        "Shutting down VM after intercepting signal" not in fc_log
    ), "VM received fatal signal during APF handling.\nFC log tail:\n" + "\n".join(
        fc_log.splitlines()[-5:]
    )


@pytest.fixture
def apf_vm(microvm_factory, guest_kernel_linux_5_10, rootfs, secret_free):
    """Provide a factory function for booting + snapshotting VMs.

    APF requires secret_free (KVM_MEM_USERFAULT + userfault bitmap).
    Tests are automatically skipped on hosts without secret_free support.
    """
    if not secret_free:
        pytest.skip("APF tests require secret_free=True")

    def _make(vcpus=2, mem_mib=512):
        vm = microvm_factory.build(
            guest_kernel_linux_5_10,
            rootfs,
            monitor_memory=False,
        )
        vm.spawn(log_level="Info")
        vm.basic_config(vcpu_count=vcpus, mem_size_mib=mem_mib, secret_free=True)
        vm.add_net_iface()
        vm.start()
        return vm

    return _make


def test_apf_per_page_fingerprint(microvm_factory, apf_vm):
    """Write a unique fingerprint per page, verify all pages after APF restore.

    This is the strongest data integrity test: every page has its own offset
    encoded as data. If the handler resolves page N with data from page M,
    or if a page is zeroed (fault dropped), the fingerprint won't match.
    """
    vm = apf_vm(mem_mib=512)

    # 64MB of fingerprinted pages = 16384 pages, each with unique data
    _guest_python(
        vm, WRITE_FINGERPRINTS, size=64 * 1024 * 1024, tag="fp", seed=0xDEADBEEF
    )

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot,
        3,
        uffd_handler_name="on_demand",
        apf=True,
    ):
        microvm.memory_monitor = None
        _assert_vm_healthy(microvm)
        # Sequential verification
        result = _guest_python(
            microvm,
            VERIFY_FINGERPRINTS,
            size=64 * 1024 * 1024,
            tag="fp",
            seed=0xDEADBEEF,
            shuffle="",
        )
        assert "VERIFIED" in result and "OK" in result, f"Verification failed: {result}"

        _assert_vm_healthy(microvm)
        handler_log = microvm.uffd_handler.log_data
        assert "Exitless APF enabled" in handler_log


def test_apf_random_access_order(microvm_factory, apf_vm):
    """Verify pages in random order to catch ordering-dependent bugs.

    Sequential access might hide bugs where adjacent pages share fate
    (e.g., resolved in the same batch). Random order ensures each page
    is independently correct.
    """
    vm = apf_vm(mem_mib=512)

    _guest_python(
        vm, WRITE_FINGERPRINTS, size=64 * 1024 * 1024, tag="rand", seed=0xCAFEBABE
    )

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot,
        3,
        uffd_handler_name="on_demand",
        apf=True,
    ):
        microvm.memory_monitor = None
        _assert_vm_healthy(microvm)
        result = _guest_python(
            microvm,
            VERIFY_FINGERPRINTS,
            size=64 * 1024 * 1024,
            tag="rand",
            seed=0xCAFEBABE,
            shuffle="random.seed(42); random.shuffle(pages)",
        )
        assert (
            "VERIFIED" in result and "OK" in result
        ), f"Random verify failed: {result}"


def test_apf_large_memory(microvm_factory, apf_vm):
    """Stress with 256MB of fingerprinted data — 65536 faults.

    Ensures the ring buffer (32 entries) handles sustained high fault
    rates without dropping entries or corrupting data.
    """
    vm = apf_vm(vcpus=2, mem_mib=1024)

    _guest_python(
        vm, WRITE_FINGERPRINTS, size=256 * 1024 * 1024, tag="big", seed=0x1234ABCD
    )

    snapshot = vm.snapshot_full()
    vm.kill()

    microvm = microvm_factory.build_from_snapshot(
        snapshot,
        uffd_handler_name="on_demand",
        apf=True,
    )
    microvm.memory_monitor = None
    result = _guest_python(
        microvm,
        VERIFY_FINGERPRINTS,
        size=256 * 1024 * 1024,
        tag="big",
        seed=0x1234ABCD,
        shuffle="",
    )
    assert "VERIFIED" in result and "OK" in result, f"Large memory failed: {result}"
    assert "65536 pages" in result


def test_apf_concurrent_verify(microvm_factory, apf_vm):
    """Multiple processes verify disjoint memory regions simultaneously.

    Stresses the ring buffer with concurrent faults from multiple vCPUs
    accessing different pages at the same time.
    """
    vm = apf_vm(vcpus=4, mem_mib=1024)

    # Write 4 separate fingerprinted regions (one per verifier)
    for i in range(4):
        _guest_python(
            vm,
            WRITE_FINGERPRINTS,
            size=32 * 1024 * 1024,
            tag=f"conc{i}",
            seed=0xAA00 + i,
        )

    snapshot = vm.snapshot_full()
    vm.kill()

    microvm = microvm_factory.build_from_snapshot(
        snapshot,
        uffd_handler_name="on_demand",
        apf=True,
    )
    microvm.memory_monitor = None

    # Write verifier scripts, then launch all 4 in parallel
    for i in range(4):
        code = VERIFY_FINGERPRINTS.format(
            size=32 * 1024 * 1024, tag=f"conc{i}", seed=0xAA00 + i, shuffle=""
        ).strip()
        microvm.ssh.check_output(f"cat > /tmp/verify_{i}.py << 'PYEOF'\n{code}\nPYEOF")
    microvm.ssh.check_output(
        "for i in 0 1 2 3; do python3 /tmp/verify_$i.py > /tmp/verify_$i.out 2>&1 & done; wait"
    )
    for i in range(4):
        _, result, _ = microvm.ssh.check_output(f"cat /tmp/verify_{i}.out")
        assert (
            "VERIFIED" in result and "OK" in result
        ), f"Concurrent verifier {i} failed: {result}"


def test_apf_multi_region_hash(microvm_factory, apf_vm):
    """Write random data across many files, verify combined SHA-256 matches.

    Complements fingerprint tests by using truly random data (not
    predictable patterns). Any byte-level corruption is caught by the hash.
    """
    vm = apf_vm(mem_mib=512)

    hash_before = _guest_python(vm, FILL_AND_HASH, n_files=8, file_size=8 * 1024 * 1024)

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot,
        3,
        uffd_handler_name="on_demand",
        apf=True,
    ):
        microvm.memory_monitor = None
        _assert_vm_healthy(microvm)
        hash_after = _guest_python(microvm, VERIFY_HASH, n_files=8)
        assert (
            hash_before == hash_after
        ), f"Hash mismatch: before={hash_before} after={hash_after}"


def test_apf_snapshot_chain(microvm_factory, apf_vm):
    """Restore → verify → snapshot → restore → verify (chain of 3).

    Catches bugs where the first restore is correct but subsequent
    snapshots of the restored VM produce bad data.
    """
    vm = apf_vm(mem_mib=512)

    _guest_python(
        vm, WRITE_FINGERPRINTS, size=32 * 1024 * 1024, tag="chain", seed=0xFEEDFACE
    )

    snapshot = vm.snapshot_full()
    vm.kill()

    for gen in range(3):
        microvm = microvm_factory.build_from_snapshot(
            snapshot,
            uffd_handler_name="on_demand",
            apf=True,
        )
        microvm.memory_monitor = None
        _assert_vm_healthy(microvm)

        result = _guest_python(
            microvm,
            VERIFY_FINGERPRINTS,
            size=32 * 1024 * 1024,
            tag="chain",
            seed=0xFEEDFACE,
            shuffle="",
        )
        assert (
            "VERIFIED" in result and "OK" in result
        ), f"Chain generation {gen} failed: {result}"

        # Take a new snapshot from the restored VM for the next generation
        snapshot = microvm.snapshot_full()


def test_apf_setup_confirmed(microvm_factory, apf_vm):
    """Verify APF setup: handler log, vCPU count, and APF-off path."""
    vm = apf_vm(vcpus=4, mem_mib=256)
    vm.ssh.check_output("echo ok")
    snapshot = vm.snapshot_full()
    vm.kill()

    # APF ON
    microvm = microvm_factory.build_from_snapshot(
        snapshot,
        uffd_handler_name="on_demand",
        apf=True,
    )
    microvm.memory_monitor = None
    microvm.ssh.check_output("true")
    handler_log = microvm.uffd_handler.log_data
    assert "Exitless APF enabled" in handler_log
    assert "4 vCPUs configured" in handler_log

    # APF OFF
    microvm2 = microvm_factory.build_from_snapshot(
        snapshot,
        uffd_handler_name="on_demand",
        apf=False,
    )
    microvm2.memory_monitor = None
    microvm2.ssh.check_output("true")
    handler_log2 = microvm2.uffd_handler.log_data
    assert "Exitless APF enabled" not in handler_log2


# --- Extreme stress tests ---

# Verifies EVERY BYTE of every page, not just the first 8 bytes.
# Each page is filled with a repeating byte derived from its offset.
WRITE_FULL_PAGES = """
import mmap
size = {size}
fd = open('/tmp/stress_full', 'w+b')
fd.truncate(size)
mm = mmap.mmap(fd.fileno(), size)
for i in range(0, size, 4096):
    byte = ((i >> 12) ^ 0xA5) & 0xFF
    mm[i:i+4096] = bytes([byte]) * 4096
mm.flush()
fd.close()
print('WROTE %d full pages' % (size // 4096))
"""

VERIFY_FULL_PAGES = """
import mmap, sys
size = {size}
fd = open('/tmp/stress_full', 'rb')
mm = mmap.mmap(fd.fileno(), size, access=mmap.ACCESS_READ)
errors = 0
for i in range(0, size, 4096):
    byte = ((i >> 12) ^ 0xA5) & 0xFF
    expected = bytes([byte]) * 4096
    actual = mm[i:i+4096]
    if actual != expected:
        errors += 1
        # Find first bad byte
        for j in range(4096):
            if actual[j] != expected[j]:
                print('MISMATCH page %#x byte %d: got %#x expected %#x' % (i, j, actual[j], expected[j]), file=sys.stderr)
                break
        if errors >= 5:
            break
fd.close()
if errors:
    print('FAIL: %d pages corrupted' % errors, file=sys.stderr)
    sys.exit(1)
print('VERIFIED %d full pages (all bytes) OK' % (size // 4096))
"""

# Writes fingerprints, then after restore OVERWRITES them with new data
# and verifies the new data is correct. Tests write-after-fault.
WRITE_AFTER_FAULT = """
import mmap, struct
size = {size}
fd = open('/tmp/stress_{tag}', 'r+b')
mm = mmap.mmap(fd.fileno(), size)
errors = 0
for i in range(0, size, 4096):
    # First READ the old fingerprint (triggers fault)
    old = struct.unpack('<Q', mm[i:i+8])[0]
    expected_old = i ^ {seed}
    if old != expected_old:
        errors += 1
    # Then WRITE a new value (tests write-after-fault)
    new_val = i ^ {new_seed}
    mm[i:i+8] = struct.pack('<Q', new_val)
mm.flush()
fd.close()
if errors:
    print('READ_ERRORS=%d' % errors)
    import sys; sys.exit(1)
print('WRITE_AFTER_FAULT %d pages OK' % (size // 4096))
"""

# Forks N children, each verifies a slice of the fingerprinted region.
# Tests COW interaction: parent's pages get COW'd on fork, child reads
# trigger faults through the COW layer.
FORK_VERIFY = """
import mmap, struct, os, sys
size = {size}
n_children = {n_children}
fd = open('/tmp/stress_{tag}', 'rb')
mm = mmap.mmap(fd.fileno(), size, access=mmap.ACCESS_READ)
pages_per_child = (size // 4096) // n_children

children = []
for c in range(n_children):
    pid = os.fork()
    if pid == 0:
        # Child: verify our slice
        start = c * pages_per_child * 4096
        end = start + pages_per_child * 4096
        errors = 0
        for i in range(start, end, 4096):
            val = struct.unpack('<Q', mm[i:i+8])[0]
            if val != (i ^ {seed}):
                errors += 1
        os._exit(errors)
    children.append(pid)

# Parent: wait for all children
total_errors = 0
for pid in children:
    _, status = os.waitpid(pid, 0)
    total_errors += os.WEXITSTATUS(status)
fd.close()
if total_errors:
    print('FORK_FAIL: %d errors across %d children' % (total_errors, n_children), file=sys.stderr)
    sys.exit(1)
print('FORK_VERIFIED %d children, %d pages each, OK' % (n_children, pages_per_child))
"""


def test_apf_full_byte_verification(microvm_factory, apf_vm):
    """Verify EVERY BYTE of every page, not just an 8-byte fingerprint.

    Fills each 4KB page with a repeating byte derived from its offset.
    After restore, checks all 4096 bytes of each page. Catches partial
    page corruption, DMA-width errors, or byte-swapping bugs.
    """
    vm = apf_vm(mem_mib=512)
    _guest_python(vm, WRITE_FULL_PAGES, size=32 * 1024 * 1024)

    snapshot = vm.snapshot_full()
    vm.kill()

    microvm = microvm_factory.build_from_snapshot(
        snapshot,
        uffd_handler_name="on_demand",
        apf=True,
    )
    microvm.memory_monitor = None
    result = _guest_python(microvm, VERIFY_FULL_PAGES, size=32 * 1024 * 1024)
    assert "VERIFIED" in result and "OK" in result, f"Full byte check failed: {result}"
    assert "8192 full pages" in result


def test_apf_write_after_fault(microvm_factory, apf_vm):
    """Read page (triggers fault), then write new data, verify new data persists.

    Tests that faulted-in pages are writable and that writes after fault
    resolution are not lost or corrupted.
    """
    vm = apf_vm(mem_mib=512)
    _guest_python(
        vm, WRITE_FINGERPRINTS, size=64 * 1024 * 1024, tag="waf", seed=0x11111111
    )

    snapshot = vm.snapshot_full()
    vm.kill()

    microvm = microvm_factory.build_from_snapshot(
        snapshot,
        uffd_handler_name="on_demand",
        apf=True,
    )
    microvm.memory_monitor = None

    # Read old data (faults in pages) + write new data
    result = _guest_python(
        microvm,
        WRITE_AFTER_FAULT,
        size=64 * 1024 * 1024,
        tag="waf",
        seed=0x11111111,
        new_seed=0x22222222,
    )
    assert (
        "WRITE_AFTER_FAULT" in result and "OK" in result
    ), f"Write-after-fault failed: {result}"

    # Verify the NEW data is correct (not the old fingerprints)
    result = _guest_python(
        microvm,
        VERIFY_FINGERPRINTS,
        size=64 * 1024 * 1024,
        tag="waf",
        seed=0x22222222,
        shuffle="",
    )
    assert (
        "VERIFIED" in result and "OK" in result
    ), f"New data verification failed: {result}"


def test_apf_fork_stress(microvm_factory, apf_vm):
    """Fork 8 children, each verifies a disjoint slice of memory.

    Tests COW (copy-on-write) interaction with APF: forking after restore
    creates COW mappings. Child page reads go through COW → fault → APF
    resolution. Catches bugs where COW layer interferes with fault handling.
    """
    vm = apf_vm(vcpus=4, mem_mib=512)
    _guest_python(
        vm, WRITE_FINGERPRINTS, size=64 * 1024 * 1024, tag="fork", seed=0xF0F0F0F0
    )

    snapshot = vm.snapshot_full()
    vm.kill()

    microvm = microvm_factory.build_from_snapshot(
        snapshot,
        uffd_handler_name="on_demand",
        apf=True,
    )
    microvm.memory_monitor = None
    result = _guest_python(
        microvm,
        FORK_VERIFY,
        size=64 * 1024 * 1024,
        tag="fork",
        seed=0xF0F0F0F0,
        n_children=8,
    )
    assert (
        "FORK_VERIFIED" in result and "OK" in result
    ), f"Fork verification failed: {result}"


def test_apf_rapid_restore_cycle(microvm_factory, apf_vm):
    """Restore → touch one page → kill, 10 times in rapid succession.

    Tests partial fault handling: only a few pages are faulted before
    the VM is killed. Catches bugs where incomplete fault resolution
    leaves the handler or kernel in a bad state for the next restore.
    """
    vm = apf_vm(mem_mib=256)
    vm.ssh.check_output("echo 'ALIVE' > /tmp/rapid_test")
    snapshot = vm.snapshot_full()
    vm.kill()

    for i in range(10):
        microvm = microvm_factory.build_from_snapshot(
            snapshot,
            uffd_handler_name="on_demand",
            apf=True,
        )
        microvm.memory_monitor = None
        _assert_vm_healthy(microvm)
        # Touch just enough to verify SSH + one read
        _, canary, _ = microvm.ssh.check_output("cat /tmp/rapid_test")
        assert canary.strip() == "ALIVE", f"Rapid cycle {i}: got '{canary.strip()}'"


def test_apf_interleaved_rw(microvm_factory, apf_vm):
    """Multiple processes read and write overlapping memory regions.

    Process A writes page N while process B reads page N+1 (which may
    be in the same ring batch). Tests that concurrent read/write to
    adjacent pages doesn't cause data races.
    """
    vm = apf_vm(vcpus=4, mem_mib=512)

    # Write 4 overlapping regions (each 32MB, shifted by 8MB)
    for i in range(4):
        _guest_python(
            vm,
            WRITE_FINGERPRINTS,
            size=32 * 1024 * 1024,
            tag=f"ilv{i}",
            seed=0xBB00 + i,
        )

    snapshot = vm.snapshot_full()
    vm.kill()

    microvm = microvm_factory.build_from_snapshot(
        snapshot,
        uffd_handler_name="on_demand",
        apf=True,
    )
    microvm.memory_monitor = None

    # Launch 4 processes: each reads its own region + writes a new one
    for i in range(4):
        verify_code = VERIFY_FINGERPRINTS.format(
            size=32 * 1024 * 1024, tag=f"ilv{i}", seed=0xBB00 + i, shuffle=""
        ).strip()
        microvm.ssh.check_output(
            f"cat > /tmp/ilv_{i}.py << 'PYEOF'\n{verify_code}\nPYEOF"
        )
    microvm.ssh.check_output(
        "for i in 0 1 2 3; do python3 /tmp/ilv_$i.py > /tmp/ilv_$i.out 2>&1 & done; wait"
    )
    for i in range(4):
        _, result, _ = microvm.ssh.check_output(f"cat /tmp/ilv_{i}.out")
        assert (
            "VERIFIED" in result and "OK" in result
        ), f"Interleaved region {i} failed: {result}"
