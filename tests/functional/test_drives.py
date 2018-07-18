"""
Tests that ensure the correctness of operations on /drives resources from the
guest side.
"""

from host_tools.network import SSHConnection


def test_rescan(test_microvm_with_ssh, network_config):
    """
    Tests that triggering a block device rescan makes the guest pick up any
    changes to the block device's size.
    """

    test_microvm = test_microvm_with_ssh

    test_microvm.basic_config(net_iface_count=0)
    """
    Sets up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    a root file system with the rw permission. The network interface is
    added after we get an unique MAC and IP.
    """
    test_microvm.basic_network_config(network_config)

    """ Adds a scratch block device. """
    test_microvm.put_default_scratch_device()

    test_microvm.start()

    ssh_connection = SSHConnection(test_microvm.slot.ssh_config)

    _check_scratch_size(ssh_connection, test_microvm.slot.sizeof_fsfile('scratch'))

    test_microvm.slot.resize_fsfile('scratch', 512)
    """ Resizes the filesystem file from 256 MiB (default) to 512 MiB."""

    response = test_microvm.api_session.put(
        test_microvm.actions_url,
        json={
            'action_type': 'BlockDeviceRescan',
            'payload': 'scratch',
        }
    )
    """ Rescan operations after the guest boots are allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    _check_scratch_size(ssh_connection, test_microvm.slot.sizeof_fsfile('scratch'))

    ssh_connection.close()


def test_non_partuuid_boot(test_microvm_with_ssh, network_config):
    """ Tests the output reported by blockdev when booting from /dev/vda."""
    test_microvm = test_microvm_with_ssh

    test_microvm.basic_config(vcpu_count=1, net_iface_count=0)
    """
    Sets up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    a root file system with the rw permission. The network interfaces is
    added after we get an unique MAC and IP.
    """
    test_microvm.basic_network_config(network_config)

    # Add another read-only block device.
    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/readonly',
        json={
            'drive_id': 'readonly',
            'path_on_host': test_microvm.slot.make_fsfile(name='readonly'),
            'is_root_device': False,
            'is_read_only': True
        }
    )
    """ Adds the file system with ro permissions. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    test_microvm.start()

    # Prepare the input for doing the assertion
    assert_dict = {}
    # Keep an array of strings specifying the location where some string
    # from the output is located.
    # 1-0 means line 1, column 0.
    keys_array = ["1-0", "1-8", "2-0"]
    # Keep a dictionary where the keys are the location and the values
    # represent the input to assert against.
    assert_dict[keys_array[0]] = "rw"
    assert_dict[keys_array[1]] = "/dev/vda"
    assert_dict[keys_array[2]] = "ro"
    check_drives(test_microvm, assert_dict, keys_array)


def test_partuuid_boot(test_microvm_with_partuuid, network_config):
    """ Tests the output reported by blockdev when booting with PARTUUID."""
    test_microvm = test_microvm_with_partuuid

    test_microvm.basic_config(
        vcpu_count=1,
        net_iface_count=0,
        add_root_device=False
    )
    """
    Sets up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    a root file system with the rw permission. The network interfaces is
    added after we get an unique MAC and IP.
    """
    test_microvm.basic_network_config(network_config)

    # Add the root block device specified through PARTUUID.
    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/rootfs',
        json={
            'drive_id': 'rootfs',
            'path_on_host': test_microvm.slot.rootfs_file,
            'is_root_device': True,
            'partuuid': '0eaa91a0-01',
            'is_read_only': False
        }
    )
    """ Adds the root file system with rw permissions. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    test_microvm.start()

    assert_dict = {}
    keys_array = ["1-0", "1-8", "2-0", "2-7"]
    assert_dict[keys_array[0]] = "rw"
    assert_dict[keys_array[1]] = "/dev/vda"
    assert_dict[keys_array[2]] = "rw"
    assert_dict[keys_array[3]] = "/dev/vda1"
    check_drives(test_microvm, assert_dict, keys_array)


def test_partuuid_update(test_microvm_with_ssh, network_config):
    """
    Tests that switching from booting from a PARTUUID to booting from
    /dev/vda is successful.
    """
    test_microvm = test_microvm_with_ssh
    test_microvm.basic_config(
        vcpu_count=1,
        net_iface_count=0,
        add_root_device=False
    )
    """
    Sets up the microVM with 1 vCPUs, 256 MiB of RAM, 0 network ifaces and
    a root file system with the rw permission. The network interfaces is
    added after we get an unique MAC and IP.
    """
    test_microvm.basic_network_config(network_config)

    # Add the root block device specified through PARTUUID.
    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/rootfs',
        json={
            'drive_id': 'rootfs',
            'path_on_host': test_microvm.slot.rootfs_file,
            'is_root_device': True,
            'partuuid': '0eaa91a0-01',
            'is_read_only': False
        }
    )
    assert(test_microvm.api_session.is_good_response(response.status_code))

    # Update the root block device to boot from /dev/vda.
    response = test_microvm.api_session.put(
        test_microvm.blk_cfg_url + '/rootfs',
        json={
            'drive_id': 'rootfs',
            'path_on_host': test_microvm.slot.rootfs_file,
            'is_root_device': True,
            'is_read_only': False
        }
    )
    assert(test_microvm.api_session.is_good_response(response.status_code))

    test_microvm.start()

    # Assert that the final booting method is from /dev/vda.
    assert_dict = {}
    keys_array = ["1-0", "1-8"]
    assert_dict[keys_array[0]] = "rw"
    assert_dict[keys_array[1]] = "/dev/vda"
    check_drives(test_microvm, assert_dict, keys_array)


def test_patch_drive(test_microvm_with_ssh, network_config):
    """
    Tests that replacing the backing filesystem file after guest boot works
    properly and that the changes are picked up by the guest.
    """
    test_microvm = test_microvm_with_ssh

    test_microvm.basic_config(net_iface_count=0)
    """
    Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 0 network ifaces and
    a root file system with the rw permission.
    """

    test_microvm.basic_network_config(network_config)
    test_microvm.put_default_scratch_device()

    test_microvm.start()

    response = test_microvm.api_session.patch(
        test_microvm.blk_cfg_url + '/scratch',
        json={
            'drive_id': 'scratch',
            'path_on_host': test_microvm.slot.make_fsfile(name='otherscratch', size=512)
        }
    )
    """ Updates to `path_on_host` with a valid path are allowed. """
    assert(test_microvm.api_session.is_good_response(response.status_code))

    ssh_connection = SSHConnection(test_microvm.slot.ssh_config)

    blksize_cmd = "lsblk -b /dev/vdb --output SIZE"
    size_bytes_str = "536870912" # 512MB
    _, stdout, stderr = ssh_connection.execute_command(blksize_cmd)
    """
    The `lsblk` command should output 2 lines to STDOUT: "SIZE" and the size of
    the device, in bytes.
    """
    assert (stderr.read().decode("utf-8") == '')
    stdout.readline() # skip "SIZE"
    assert(stdout.readline().strip() == size_bytes_str)

    ssh_connection.close()


def _check_scratch_size(ssh_connection, size):
    _, stdout, stderr = ssh_connection.execute_command(
        "blockdev --getsize64 /dev/vdb"
    )
    """ The scratch block device is /dev/vdb in the guest. """
    assert(stderr.read().decode("utf-8") == '')
    assert(stdout.readline().strip() == str(size))


def process_blockdev_output(blockdev_out, assert_dict, keys_array):
    blockdev_out_lines = blockdev_out.splitlines()

    for key in keys_array:
        line = int(key.split("-")[0])
        col = int(key.split("-")[1])
        blockdev_out_line = blockdev_out_lines[line]
        assert(blockdev_out_line.split("   ")[col] == assert_dict[key])


def check_drives(test_microvm, assert_dict, keys_array):
    ssh_connection = SSHConnection(test_microvm.slot.ssh_config)

    _, stdout, stderr = ssh_connection.execute_command("blockdev --report")
    assert (stderr.read().decode("utf-8") == '')
    process_blockdev_output(
        stdout.read().decode("utf-8"),
        assert_dict,
        keys_array)
