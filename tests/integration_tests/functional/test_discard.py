import pytest
import os
import host_tools.drive as drive_tools


def test_discard_support(uvm_plain_rw):
    """
    Test the VIRTIO_BLK_T_DISCARD feature for valid and invalid requests.
    """

    vm = uvm_plain_rw
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()

    fs1 = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, "test_disk"), size=128)
    vm.add_drive(
        drive_id="test_disk",
        path_on_host=fs1.path,
        is_root_device=False,
        is_read_only=False,
    )

    vm.start()

    exit_code, stdout, _ = vm.ssh.run("cat /sys/block/vda/queue/discard_max_bytes")

    assert exit_code == 0, "Failed to read discard_max_bytes"
    assert int(stdout.strip()) > 0, f"discard_max_bytes is 0: {stdout}"

    vm.ssh.run("mount -o remount,discard /")
    exit_code, stdout, _ = vm.ssh.run("mount | grep /dev/vda")
    assert exit_code == 0, f"Failed to remount root filesystem with discard option: {stdout}"

    exit_code, stdout, _ = vm.ssh.run("fstrim -v /")
    assert exit_code == 0, f"fstrim -v failed: {stdout}"
    assert "bytes trimmed" in stdout, f"Unexpected fstrim output: {stdout}"
    vm.kill()