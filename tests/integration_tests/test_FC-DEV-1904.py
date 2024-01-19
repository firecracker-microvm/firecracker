def test_FC_DEV_1904(uvm_plain):
    """
    https://sim.amazon.com/issues/FC-DEV-1904

    Make the test pass

    ./tools/devtool test_debug integration_tests/test_FC-DEV-1904.py

    file:../../src/vmm/src/persist.rs::.dump_dirty(&mut file, &dirty_bitmap)
    Around here we would have to handle an error:
      file:../../src/vmm/src/vstate/memory.rs:285
    """

    vm_mem_size = 128
    uvm = uvm_plain
    uvm.spawn()
    uvm.basic_config(mem_size_mib=vm_mem_size, track_dirty_pages=True)
    uvm.add_net_iface()
    uvm.start()
    uvm.ssh.run("true")

    snap_full = uvm.snapshot_full(vmstate_path="vmstate_full", mem_path="mem_full")
    snap_diff = uvm.snapshot_diff(vmstate_path="vmstate_diff", mem_path="mem_diff")
    snap_diff2 = uvm.snapshot_diff(vmstate_path="vmstate_diff2", mem_path="mem_diff2")

    # file size is the same, but the `diff` snapshot is actually a sparse file
    assert snap_full.mem.stat().st_size == snap_diff.mem.stat().st_size

    # diff -> diff there should be no differences
    assert snap_diff2.mem.stat().st_blocks == 0

    # full -> diff there should be no differences
    assert snap_diff.mem.stat().st_blocks == 0
