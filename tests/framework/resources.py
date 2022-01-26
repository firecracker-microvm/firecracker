# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Defines classes for all the resources a microvm could need attaching."""

import urllib
import re

from framework.utils import compare_versions, is_io_uring_supported, run_cmd
from framework.defs import API_USOCKET_URL_PREFIX


class Actions():
    """Facility for sending operations instructions on the microvm."""

    ACTIONS_CFG_RESOURCE = 'actions'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._actions_cfg_url = api_url + self.ACTIONS_CFG_RESOURCE
        self._api_session = api_session

    def put(self, **args):
        """Send an instruction to the microvm."""
        datax = self.create_json(**args)
        return self._api_session.put(
            "{}".format(self._actions_cfg_url),
            json=datax
        )

    @staticmethod
    def create_json(action_type=None, payload=None):
        """Compose the json associated to this type of API request."""
        datax = {}

        if action_type is not None:
            datax['action_type'] = action_type

        if payload is not None:
            datax['payload'] = payload

        return datax


class Balloon():
    """Facility for specifying balloon device configurations."""

    BALLOON_CFG_RESOURCE = 'balloon'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._balloon_cfg_url = api_url + self.BALLOON_CFG_RESOURCE
        self._api_session = api_session

    def put(self, **args):
        """Specify the balloon device configuration."""
        datax = self.create_json(**args)
        return self._api_session.put(
            "{}".format(self._balloon_cfg_url),
            json=datax
        )

    def patch(self, **args):
        """Update a previously attached balloon device."""
        datax = self.create_json(**args)
        return self._api_session.patch(
            "{}".format(self._balloon_cfg_url),
            json=datax
        )

    def patch_stats(self, **args):
        """Update the balloon statistics interval."""
        datax = self.create_json(**args)
        return self._api_session.patch(
            "{}".format(self._balloon_cfg_url + "/statistics"),
            json=datax
        )

    def get(self):
        """Get the response of specifying the balloon configuration."""
        return self._api_session.get(
            self._balloon_cfg_url
        )

    def get_stats(self):
        """Get the response of specifying the balloon statistics."""
        return self._api_session.get(
            "{}".format(self._balloon_cfg_url + "/statistics")
        )

    @staticmethod
    def create_json(
            amount_mib=None,
            deflate_on_oom=None,
            stats_polling_interval_s=None
    ):
        """Compose the json associated to this type of API request."""
        datax = {}

        if amount_mib is not None:
            datax['amount_mib'] = amount_mib

        if deflate_on_oom is not None:
            datax['deflate_on_oom'] = deflate_on_oom

        if stats_polling_interval_s is not None:
            datax['stats_polling_interval_s'] = stats_polling_interval_s

        return datax


class BootSource():
    """Facility for specifying the source of the boot process."""

    BOOT_CFG_RESOURCE = 'boot-source'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._boot_cfg_url = api_url + self.BOOT_CFG_RESOURCE
        self._api_session = api_session

    def put(self, **args):
        """Specify the boot information."""
        datax = self.create_json(**args)

        return self._api_session.put(
            "{}".format(self._boot_cfg_url),
            json=datax
        )

    def patch(self, **args):
        """Update a previously attached boot source."""
        datax = self.create_json(**args)
        return self._api_session.patch(
            "{}".format(self._boot_cfg_url),
            json=datax
        )

    def get(self):
        """Get the response of specifying a boot source."""
        return self._api_session.get(
            self._boot_cfg_url
        )

    @staticmethod
    def create_json(
            boot_args=None,
            kernel_image_path=None,
            initrd_path=None):
        """Compose the json associated to this type of API request."""
        datax = {}

        if kernel_image_path is not None:
            datax['kernel_image_path'] = kernel_image_path

        if initrd_path is not None:
            datax['initrd_path'] = initrd_path

        if boot_args is not None:
            datax['boot_args'] = boot_args

        return datax


# Too few public methods (1/2) (too-few-public-methods)
# pylint: disable=R0903
class DescribeInstance():
    """Facility for getting the microVM state."""

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        self._descinst_cfg_url = \
            API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        self._api_session = api_session

    def get(self):
        """Get the status of configuring the current microvm."""
        return self._api_session.get(
            self._descinst_cfg_url
        )


class Drive():
    """Facility for attaching a block device."""

    DRIVE_CFG_RESOURCE = 'drives'

    def __init__(
        self,
        api_usocket_full_name,
        api_session,
        firecracker_version
    ):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._drive_cfg_url = api_url + self.DRIVE_CFG_RESOURCE
        self._api_session = api_session
        self._firecracker_version = firecracker_version

    def put(self, **args):
        """Attach a block device or update the details of a previous one."""
        # Default the io engine to Async on kernels > 5.10 so that we
        # make sure to exercise both Sync and Async behaviour in the CI.
        # Also check the FC version to make sure that it has support for
        # configurable io_engine.
        if is_io_uring_supported() and \
            compare_versions(self._firecracker_version, "0.25.0") > 0 \
            and \
                ('io_engine' not in args or args['io_engine'] is None):
            args['io_engine'] = 'Async'

        datax = self.create_json(**args)

        return self._api_session.put(
            "{}/{}".format(self._drive_cfg_url, args['drive_id']),
            json=datax
        )

    def put_with_default_io_engine(self, **args):
        """
        Attach a block device or update the details of a previous one, using...

        ...the Firecracker default for the io_engine.
        """
        datax = self.create_json(**args)

        return self._api_session.put(
            "{}/{}".format(self._drive_cfg_url, args['drive_id']),
            json=datax
        )

    def patch(self, **args):
        """Attach a block device or update the details of a previous one."""
        datax = self.create_json(**args)

        return self._api_session.patch(
            "{}/{}".format(self._drive_cfg_url, args['drive_id']),
            json=datax
        )

    def get(self, drive_id):
        """Get the status of attaching some block device."""
        return self._api_session.get(
            "{}/{}".format(self._drive_cfg_url, drive_id)
        )

    @staticmethod
    def create_json(
            drive_id=None,
            path_on_host=None,
            is_root_device=None,
            partuuid=None,
            is_read_only=None,
            rate_limiter=None,
            cache_type=None,
            io_engine=None):
        """Compose the json associated to this type of API request."""
        datax = {}

        if drive_id is not None:
            datax['drive_id'] = drive_id

        if path_on_host is not None:
            datax['path_on_host'] = path_on_host

        if is_root_device is not None:
            datax['is_root_device'] = is_root_device

        if partuuid is not None:
            datax['partuuid'] = partuuid

        if is_read_only is not None:
            datax['is_read_only'] = is_read_only

        if cache_type is not None:
            datax['cache_type'] = cache_type

        if rate_limiter is not None:
            datax['rate_limiter'] = rate_limiter

        if io_engine is not None:
            datax['io_engine'] = io_engine

        return datax


# Too few public methods (1/2) (too-few-public-methods)
# pylint: disable=R0903
class FullConfig():
    """Facility for getting the full microVM configuration."""

    EXPORT_CFG_RESOURCE = 'vm/config'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._export_cfg_url = api_url + self.EXPORT_CFG_RESOURCE
        self._api_session = api_session

    def get(self):
        """Get full configuration of the current microvm."""
        return self._api_session.get(
            self._export_cfg_url
        )


# Too few public methods (1/2) (too-few-public-methods)
# pylint: disable=R0903
class InstanceVersion():
    """Facility for getting the microVM version."""

    VERSION_CFG_RESOURCE = 'version'

    def __init__(self, api_usocket_full_name, fc_binary_path, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._version_cfg_url = api_url + self.VERSION_CFG_RESOURCE
        self._fc_binary_path = fc_binary_path
        self._api_session = api_session

    def get(self):
        """Get the version of the current microvm, from the cmdline."""
        _, stdout, _ = run_cmd(
            "{} --version".format(self._fc_binary_path))

        return re.match(
            r"^Firecracker v([0-9]+\.[0-9]+(\.[0-9]+)?)",
            stdout.partition('\n')[0]).group(1)

    def get_from_api(self):
        """Get the version of the current microvm, from the API."""
        return self._api_session.get(
            self._version_cfg_url
        )


class Logger():
    """Facility for setting up the logging system and sending API requests."""

    LOGGER_CFG_RESOURCE = 'logger'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._logger_cfg_url = api_url + self.LOGGER_CFG_RESOURCE
        self._api_session = api_session

    def put(self, **args):
        """Configure or update the settings of the logging system."""
        datax = self.create_json(**args)

        return self._api_session.put(
            "{}".format(self._logger_cfg_url),
            json=datax
        )

    def patch(self, **args):
        """Configure or update the settings of the logging system."""
        datax = self.create_json(**args)
        return self._api_session.patch(
            "{}".format(self._logger_cfg_url),
            json=datax
        )

    @staticmethod
    def create_json(
            log_path=None,
            level=None,
            show_level=None,
            show_log_origin=None):
        """Compose the json associated to this type of API request."""
        datax = {}

        if log_path is not None:
            datax['log_path'] = log_path

        if level is not None:
            datax['level'] = level

        if show_level is not None:
            datax['show_level'] = show_level

        if show_log_origin is not None:
            datax['show_log_origin'] = show_log_origin

        return datax


class SnapshotCreate():
    """Facility for sending create snapshot commands on the microvm."""

    SNAPSHOT_CREATE_URL = 'snapshot/create'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        self._snapshot_cfg_url = api_url + self.SNAPSHOT_CREATE_URL
        self._api_session = api_session

    def put(self, **args):
        """Create a snapshot of the microvm."""
        self._api_session.untime()
        datax = self.create_json(**args)
        return self._api_session.put(
            "{}".format(self._snapshot_cfg_url),
            json=datax
        )

    @staticmethod
    def create_json(mem_file_path, snapshot_path, diff=False, version=None):
        """Compose the json associated to this type of API request."""
        if diff:
            snapshot_type = 'Diff'
        else:
            snapshot_type = 'Full'
        datax = {
            'mem_file_path': mem_file_path,
            'snapshot_path': snapshot_path,
            'snapshot_type': snapshot_type,
        }
        if version is not None:
            datax['version'] = version

        return datax


class SnapshotLoad():
    """Facility for sending load snapshot commands on the microvm."""

    SNAPSHOT_LOAD_URL = 'snapshot/load'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        self._snapshot_cfg_url = api_url + self.SNAPSHOT_LOAD_URL
        self._api_session = api_session

    def put(self, **args):
        """Load a snapshot of the microvm."""
        datax = self.create_json(**args)
        return self._api_session.put(
            "{}".format(self._snapshot_cfg_url),
            json=datax
        )

    @staticmethod
    def create_json(mem_file_path, snapshot_path, diff=False, resume=False):
        """Compose the json associated to this type of API request."""
        datax = {
            'mem_file_path': mem_file_path,
            'snapshot_path': snapshot_path,
        }
        if diff:
            datax['enable_diff_snapshots'] = True
        if resume:
            datax['resume_vm'] = True
        return datax


class SnapshotHelper():
    """Facility for creation and loading of microvm snapshots."""

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        self._create = SnapshotCreate(api_usocket_full_name, api_session)
        self._load = SnapshotLoad(api_usocket_full_name, api_session)
        self._vm_state = Vm(api_usocket_full_name, api_session)

    def create(self, mem_file_path, snapshot_path, diff=False, version=None):
        """Create a snapshot of the microvm."""
        return self._create.put(
            mem_file_path=mem_file_path,
            snapshot_path=snapshot_path,
            diff=diff,
            version=version
        )

    def load(self, mem_file_path, snapshot_path, diff=False, resume=False):
        """Load a snapshot of the microvm."""
        response = self._load.put(
            mem_file_path=mem_file_path,
            snapshot_path=snapshot_path,
            diff=diff,
            resume=resume
        )

        if resume and "unknown field `resume_vm`" in response.text:
            # Retry using old API - separate resume command.
            response = self._load.put(
                mem_file_path=mem_file_path,
                snapshot_path=snapshot_path,
                diff=diff,
                resume=False
            )
            if response.status_code != 204:
                return response
            response = self._vm_state.patch(state='Resumed')

        return response


class Metrics:
    """Facility for setting up the metrics system and sending API requests."""

    METRICS_CFG_RESOURCE = 'metrics'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._metrics_cfg_url = api_url + self.METRICS_CFG_RESOURCE
        self._api_session = api_session

    def put(self, **args):
        """Configure or update the settings of the metrics system."""
        datax = self.create_json(**args)
        return self._api_session.put(
            "{}".format(self._metrics_cfg_url),
            json=datax
        )

    def patch(self, **args):
        """Configure or update the settings of the metrics system."""
        datax = self.create_json(**args)
        return self._api_session.patch(
            "{}".format(self._metrics_cfg_url),
            json=datax
        )

    @staticmethod
    def create_json(
            metrics_path=None,
    ):
        """Compose the json associated to this type of API request."""
        datax = {}
        if metrics_path is not None:
            datax['metrics_path'] = metrics_path
        return datax


class MachineConfigure():
    """Facility for configuring the machine capabilities."""

    MACHINE_CFG_RESOURCE = 'machine-config'

    def __init__(
            self,
            api_usocket_full_name,
            api_session,
            firecracker_version):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._machine_cfg_url = api_url + self.MACHINE_CFG_RESOURCE
        self._api_session = api_session
        self._firecracker_version = firecracker_version
        self._datax = {}

    @property
    def configuration(self):
        """Return machine config dictionary."""
        return self._datax

    def put(self, **args):
        """Specify the details of the machine configuration."""
        self._datax = self.create_json(**args)

        return self._api_session.put(
            "{}".format(self._machine_cfg_url),
            json=self._datax
        )

    def patch(self, **args):
        """Update the details of the machine configuration."""
        datax = self.create_json(**args)
        self._datax.update(datax)

        return self._api_session.patch(
            "{}".format(self._machine_cfg_url),
            json=datax
        )

    def get(self):
        """Get the status of configuring the current microvm."""
        return self._api_session.get(
            self._machine_cfg_url
        )

    def create_json(
            self,
            vcpu_count=None,
            mem_size_mib=None,
            smt=None,
            cpu_template=None,
            track_dirty_pages=None):
        """Compose the json associated to this type of API request."""
        datax = {}
        if vcpu_count is not None:
            datax['vcpu_count'] = vcpu_count

        if mem_size_mib is not None:
            datax['mem_size_mib'] = mem_size_mib

        if compare_versions(self._firecracker_version, "0.25.0") <= 0:
            datax['ht_enabled'] = False if smt is None else smt
        elif smt is not None:
            datax['smt'] = smt

        if cpu_template is not None:
            datax['cpu_template'] = cpu_template

        if track_dirty_pages is not None:
            datax['track_dirty_pages'] = track_dirty_pages

        return datax


class MMDS():
    """Facility for sending microvm metadata services related API calls."""

    MMDS_CFG_RESOURCE = 'mmds'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending MMDS API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._mmds_cfg_url = api_url + self.MMDS_CFG_RESOURCE
        self._api_session = api_session

    def put(self, **args):
        """Send a new MMDS request."""
        return self._api_session.put(
            "{}".format(self._mmds_cfg_url),
            json=args['json']
        )

    def put_config(self, **args):
        """Send a new MMDS config request."""
        return self._api_session.put(
            "{}".format(self._mmds_cfg_url + "/config"),
            json=args['json']
        )

    def patch(self, **args):
        """Update the details of some MMDS request."""
        return self._api_session.patch(
            "{}".format(self._mmds_cfg_url),
            json=args['json']
        )

    def get(self):
        """Get the status of the MMDS request."""
        return self._api_session.get(
            self._mmds_cfg_url
        )


class Network():
    """Facility for handling network configuration for a microvm."""

    NET_CFG_RESOURCE = 'network-interfaces'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._net_cfg_url = api_url + self.NET_CFG_RESOURCE
        self._api_session = api_session

    def put(self, **args):
        """Attach a new tap interface."""
        datax = self.create_json(**args)

        return self._api_session.put(
            "{}/{}".format(self._net_cfg_url, args['iface_id']),
            json=datax
        )

    def patch(self, **args):
        """Apply an update to some tap interface."""
        datax = self.create_json(**args)

        return self._api_session.patch(
            "{}/{}".format(self._net_cfg_url, args['iface_id']),
            json=datax
        )

    @staticmethod
    def create_json(
            iface_id=None,
            host_dev_name=None,
            guest_mac=None,
            rx_rate_limiter=None,
            tx_rate_limiter=None):
        """Create the json for the net specific API request."""
        datax = {
            'iface_id': iface_id
        }

        if host_dev_name is not None:
            datax['host_dev_name'] = host_dev_name

        if guest_mac is not None:
            datax['guest_mac'] = guest_mac

        if tx_rate_limiter is not None:
            datax['tx_rate_limiter'] = tx_rate_limiter

        if rx_rate_limiter is not None:
            datax['rx_rate_limiter'] = rx_rate_limiter

        return datax


class Vm():
    """Facility for handling the state for a microvm."""

    VM_CFG_RESOURCE = 'vm'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._vm_cfg_url = api_url + self.VM_CFG_RESOURCE
        self._api_session = api_session

    def patch(self, **args):
        """Apply an update to the microvm state."""
        datax = self.create_json(**args)

        return self._api_session.patch(
            self._vm_cfg_url,
            json=datax
        )

    @staticmethod
    def create_json(state):
        """Create the json for the vm specific API request."""
        datax = {
            'state': state
        }

        return datax


class Vsock():
    """Facility for handling vsock configuration for a microvm."""

    VSOCK_CFG_RESOURCE = 'vsock'

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'

        self._vsock_cfg_url = api_url + self.VSOCK_CFG_RESOURCE
        self._api_session = api_session

    def put(self, **args):
        """Attach a new vsock device."""
        datax = self.create_json(**args)

        return self._api_session.put(
            self._vsock_cfg_url,
            json=datax
        )

    def patch(self, **args):
        """Apply an update to some vsock device."""
        datax = self.create_json(**args)

        return self._api_session.patch(
            self._vsock_cfg_url,
            json=datax
        )

    @staticmethod
    def create_json(
            guest_cid,
            uds_path,
            vsock_id=None):
        """Create the json for the vsock specific API request."""
        datax = {
            'guest_cid': guest_cid,
            'uds_path': uds_path
        }
        if vsock_id:
            datax['vsock_id'] = vsock_id

        return datax
