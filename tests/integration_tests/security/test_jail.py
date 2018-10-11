"""Tests that verify the jailer's behavior."""
import os


def test_default_chroot(test_microvm_with_ssh):
    """Test that the code base assigns a chroot if none is specified."""
    test_microvm = test_microvm_with_ssh

    # Start customizing arguments.
    # Test that firecracker's default chroot folder is indeed `/srv/jailer`.
    test_microvm.jailer.chroot_base = None

    test_microvm.spawn()

    # Test the expected outcome.
    assert os.path.exists(test_microvm.jailer.api_socket_path())
