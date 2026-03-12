"""Test that serial output continues after snapshot restore during active TX.

The THRE interrupt bug manifests when the guest's TX circular buffer has
more than port->fifosize (16) bytes at snapshot time. serial8250_tx_chars()
can only send 16 bytes per THRE interrupt. With >16 bytes pending, THRI
stays set in the guest driver's cached IER. After restore, vm-superio's
IER is reset and emulate_serial_init() only sets RDA — no THRE interrupt
fires, and serial8250_start_tx() sees THRI already set so it doesn't
re-enable it via the TXEN fallback. TX stalls permanently.

To guarantee hitting this window, we use dd with bs=4096 to produce
write() calls much larger than 16 bytes, keeping the buffer full.
"""
from framework.microvm import Serial
import time


def test_serial_output_after_snapshot_during_active_tx(uvm_plain, microvm_factory):
    """Snapshot during active serial TX with full buffer, verify output resumes."""
    microvm = uvm_plain
    microvm.help.enable_console()
    microvm.spawn(serial_out_path=None)
    microvm.basic_config(vcpu_count=2, mem_size_mib=256)
    serial = Serial(microvm)
    serial.open()
    microvm.start()
    serial.rx("ubuntu-fc-uvm:~#")

    # Write large chunks (>> 16 bytes each) to keep the TX circular buffer
    # full. This ensures THRI stays set in the guest driver's cached IER
    # because serial8250_tx_chars() can't drain the buffer in one 16-byte pass.
    #
    # dd bs=4096 produces 4096 byte writes. Each write fills the circular
    # buffer. serial8250_tx_chars() sends 16 bytes, leaving 4080. THRI stays
    # set, waiting for the next THRE interrupt to send more.
    serial.tx("dd if=/dev/zero bs=4096 count=999999 2>/dev/null | tr '\\0' 'A' &")
    serial.rx("ubuntu-fc-uvm:~#")

    # Let the output flow for a bit to ensure the buffer is full.
    time.sleep(2)

    # Drain buffered output.
    drained = 0
    while True:
        ch = serial.rx_char()
        if ch == "":
            break
        drained += 1
    print(f"Drained {drained} chars before snapshot")

    # Snapshot while dd|tr is flooding the circular buffer.
    snapshot = microvm.snapshot_full()
    microvm.kill()

    # Restore.
    vm = microvm_factory.build()
    vm.help.enable_console()
    vm.spawn(serial_out_path=None)
    vm.restore_from_snapshot(snapshot, resume=True)
    serial = Serial(vm)
    serial.open()

    # Phase 1: Let any in-flight serial8250_tx_chars() complete (max 16 bytes).
    time.sleep(1)
    initial = ""
    while True:
        ch = serial.rx_char()
        if ch == "":
            break
        initial += ch
    print(f"Phase 1 (initial burst): {len(initial)} bytes")

    # Phase 2: Check for sustained output requiring new THRE interrupt cycles.
    # DO NOT send any input — that triggers RDA piggybacking.
    sustained = ""
    start = time.time()
    while (time.time() - start) < 10:
        ch = serial.rx_char()
        if ch:
            sustained += ch
            if len(sustained) > 50:
                break

    elapsed = time.time() - start
    print(f"Phase 2 (sustained): {len(sustained)} bytes in {elapsed:.1f}s")

    assert len(sustained) > 0, (
        f"Serial TX stalled after snapshot restore during active transmission. "
        f"Initial burst: {len(initial)} bytes (serial8250_tx_chars FIFO drain). "
        f"No sustained output — THRE interrupt cycle is broken. "
        f"emulate_serial_init() must set IER_THR_EMPTY_BIT and write to DATA "
        f"to trigger the initial THRE interrupt after restore."
    )
    print(f"SUCCESS: Sustained serial output after restore ({len(sustained)} bytes in {elapsed:.1f}s)")
