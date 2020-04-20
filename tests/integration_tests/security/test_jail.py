# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify the jailer's behavior."""
import os
import stat

# These are the permissions that all files/dirs inside the jailer have.
REG_PERMS = stat.S_IRUSR | stat.S_IWUSR | \
            stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | \
            stat.S_IROTH | stat.S_IXOTH
DIR_STATS = stat.S_IFDIR | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
FILE_STATS = stat.S_IFREG | REG_PERMS
SOCK_STATS = stat.S_IFSOCK | REG_PERMS
# These are the stats of the devices created by tha jailer.
CHAR_STATS = stat.S_IFCHR | stat.S_IRUSR | stat.S_IWUSR


def check_stats(filepath, stats, uid, gid):
    """Assert on uid, gid and expected stats for the given path."""
    st = os.stat(filepath)

    assert st.st_gid == gid
    assert st.st_uid == uid
    assert st.st_mode ^ stats == 0


def test_default_chroot(test_microvm_with_ssh):
    """Test that the code base assigns a chroot if none is specified."""
    test_microvm = test_microvm_with_ssh

    # Start customizing arguments.
    # Test that firecracker's default chroot folder is indeed `/srv/jailer`.
    test_microvm.jailer.chroot_base = None

    test_microvm.spawn()

    # Test the expected outcome.
    assert os.path.exists(test_microvm.jailer.api_socket_path())


def test_empty_jailer_id(test_microvm_with_ssh):
    """Test that the jailer ID cannot be empty."""
    test_microvm = test_microvm_with_ssh

    # Set the jailer ID to None.
    test_microvm.jailer.jailer_id = ""

    # pylint: disable=W0703
    try:
        test_microvm.spawn()
        # If the exception is not thrown, it means that Firecracker was
        # started successfully, hence there's a bug in the code due to which
        # we can set an empty ID.
        assert False
    except Exception as err:
        expected_err = "Jailer error: Invalid instance ID: invalid len (0);" \
                       "  the length must be between 1 and 64"
        assert expected_err in str(err)


def test_default_chroot_hierarchy(test_microvm_with_initrd):
    """Test the folder hierarchy created by default by the jailer."""
    test_microvm = test_microvm_with_initrd

    test_microvm.spawn()

    # We do checks for all the things inside the chroot that the jailer crates
    # by default.
    check_stats(test_microvm.jailer.chroot_path(), DIR_STATS,
                test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "dev"),
                DIR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "dev/net"),
                DIR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "run"),
                DIR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "dev/net/tun"),
                CHAR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(), "dev/kvm"),
                CHAR_STATS, test_microvm.jailer.uid, test_microvm.jailer.gid)
    check_stats(os.path.join(test_microvm.jailer.chroot_path(),
                             "firecracker"), FILE_STATS, 0, 0)


def test_arbitrary_usocket_location(test_microvm_with_initrd):
    """Test arbitrary location scenario for the api socket."""
    test_microvm = test_microvm_with_initrd
    test_microvm.jailer.extra_args = {'api-sock': 'api.socket'}

    test_microvm.spawn()

    check_stats(os.path.join(test_microvm.jailer.chroot_path(),
                             "api.socket"), SOCK_STATS,
                test_microvm.jailer.uid, test_microvm.jailer.gid)
