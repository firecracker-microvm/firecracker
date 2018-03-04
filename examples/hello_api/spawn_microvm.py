import subprocess
import time
import urllib

import requests
import requests_unixsocket
requests_unixsocket.monkeypatch()


class Firecracker:
    """
    Toy class to showcase using the Firecracker API.
    A full API client can be generated from the Firecracker open-api model.
    """

    binary_name = 'firecracker'
    usocket_path_prefix = '/tmp/firecracker'

    machine_config_path = '/machine-config'
    network_ifaces_path = '/network-interfaces'
    drives_path = '/drives'
    vsocks_path = '/vsocks'
    boot_source_path = '/boot-source'
    actions_path = '/actions'

    def __init__(self, socket_name):
        self.socket_name = socket_name
        self.session_name = self.binary_name + socket_name

    def spawn(self):
        self.usocket_name = (
            self.usocket_path_prefix +
            self.socket_name +
            '.socket'
        )

        usocket_url = self.get_usocket_url()

        self.machine_config_url = usocket_url + self.machine_config_path
        self.network_ifaces_url = usocket_url + self.network_ifaces_path
        self.drives_url = usocket_url + self.drives_path
        self.vsocks_url = usocket_url + self.vsocks_path
        self.boot_source_url = usocket_url + self.boot_source_path
        self.actions_url = usocket_url + self.actions_path

        screen_cmd = (
            'screen -dmS ' + self.session_name +
            ' ./' + self.binary_name + ' --api-sock ' + self.usocket_name)
        subprocess.call(screen_cmd, shell=True)

    def get_usocket_url(self):
        url_encoded_prefix = urllib.parse.quote_plus(self.usocket_path_prefix)
        usocket_url = (
            'http+unix://' +
            url_encoded_prefix +
            self.socket_name +
            '.socket'
        )
        return usocket_url

# Spawn a new Firecracker Virtual Machine Manager process.
firecracker = Firecracker('0001')
firecracker.spawn()

# Give the api time to come online since we don't handle retries here.
time.sleep(0.0042)

# Configure the microVM CPU and memory.
requests.put(firecracker.machine_config_url, json={'vcpu_count': 2})
requests.put(firecracker.machine_config_url, json={'mem_size_mib': 256})

# Add a network interface to the microVM.
# Firecracker will map this host network interface into the microVM.
requests.put(
    firecracker.network_ifaces_url + '/1',
    json={
        'iface_id': '1',
        'host_dev_name': 'fc0001tap1',
        'state': 'Attached'
    }
)

# Add another network interface to the microVM.
# Firecracker will map this host network interface into the microVM.
requests.put(
    firecracker.network_ifaces_url + '/2',
    json={
        'iface_id': '2',
        'host_dev_name': 'fc0001tap2',
        'state': 'Attached'
    }
)

# Add a disk (block device) to the microVM.
# This one will be flagged as the root file system.
requests.put(
    firecracker.drives_url + '/1',
    json={
        'drive_id': '1',
        'path_on_host': '/tmp/firecracker0001/ami-rootfs.ext4',
        'state': 'Attached',
        'is_root_device': True
    }
)

# Add another disk (block device) to the microVM.
# This one is empty, usable for, e.g., guest scratch space.
requests.put(
    firecracker.drives_url + '/2',
    json={
        'drive_id': '2',
        'path_on_host': '/tmp/firecracker0001/scratch.ext4',
        'state': 'Attached',
        'is_root_device': False
    }
)

# Add a vsocket between the host and guest OSs (requiers both to be Linux).
# Requires appropriate privileges, and both host and guest kernel support.
requests.put(
    firecracker.vsocks_url + '/1',
    json={'vsock_id': '1', 'guest_cid': 10001, 'state': 'Attached'}
)

# Specify a boot source: a kernel image.
# Currently, only linux kernel images are supported.
requests.put(
    firecracker.boot_source_url,
    json={
        'boot_source_id': '1',
        'source_type': 'LocalImage',
        'local_image': {'kernel_image_path': '/tmp/vmlinux.bin'},
    }
)

# Start!
requests.put(
    firecracker.actions_url + '/1',
    json={'action_id': '1', 'action_type': 'InstanceStart'}
)
