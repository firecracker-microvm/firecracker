# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Defines classes for all the resources a microvm could need attaching."""

import urllib

from framework.defs import API_USOCKET_URL_PREFIX


class Actions:
    """Facility for sending operations instructions on the microvm."""

    ACTIONS_CFG_RESOURCE = 'actions'

    __actions_cfg_url = None
    __api_session = None

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        type(self).__actions_cfg_url = api_url + self.ACTIONS_CFG_RESOURCE
        type(self).__api_session = api_session

    @classmethod
    def put(cls, **args):
        """Send an instruction to the microvm."""
        datax = cls.create_json(**args)
        return Actions.__api_session.put(
            "{}".format(Actions.__actions_cfg_url),
            json=datax
        )

    @staticmethod
    def create_json(
            action_type=None,
            payload=None
    ):
        """Compose the json associated to this type of API request."""
        datax = {}
        if action_type is not None:
            datax['action_type'] = action_type
        if payload is not None:
            datax['payload'] = payload
        return datax


class BootSource:
    """Facility for specifying the source of the boot process."""

    BOOT_CFG_RESOURCE = 'boot-source'

    __boot_cfg_url = None
    __api_session = None

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        type(self).__boot_cfg_url = api_url + self.BOOT_CFG_RESOURCE
        type(self).__api_session = api_session

    @classmethod
    def put(cls, **args):
        """Specify the boot information."""
        datax = cls.create_json(**args)
        return BootSource.__api_session.put(
            "{}".format(BootSource.__boot_cfg_url),
            json=datax
        )

    @classmethod
    def patch(cls, **args):
        """Update a previously attached boot source."""
        datax = cls.create_json(**args)
        return BootSource.__api_session.patch(
            "{}".format(BootSource.__boot_cfg_url),
            json=datax
        )

    @classmethod
    def get(cls):
        """Get the response of specifying a boot source."""
        return BootSource.__api_session.get(
            BootSource.__boot_cfg_url
        )

    @staticmethod
    def create_json(
            boot_args=None,
            kernel_image_path=None
    ):
        """Compose the json associated to this type of API request."""
        datax = {}
        if kernel_image_path is not None:
            datax['kernel_image_path'] = kernel_image_path
        if boot_args is not None:
            datax['boot_args'] = boot_args
        return datax


class Drive:
    """Facility for attaching a block device."""

    DRIVE_CFG_RESOURCE = 'drives'

    __drive_cfg_url = None
    __api_session = None

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        type(self).__drive_cfg_url = api_url + self.DRIVE_CFG_RESOURCE
        type(self).__api_session = api_session

    @classmethod
    def put(cls, **args):
        """Attach a block device or update the details of a previous one."""
        datax = cls.create_json(**args)
        return Drive.__api_session.put(
            "{}/{}".format(Drive.__drive_cfg_url, args['drive_id']),
            json=datax
        )

    @classmethod
    def patch(cls, **args):
        """Attach a block device or update the details of a previous one."""
        datax = cls.create_json(**args)
        return Drive.__api_session.patch(
            "{}/{}".format(Drive.__drive_cfg_url, args['drive_id']),
            json=datax
        )

    @classmethod
    def get(cls, drive_id):
        """Get the status of attaching some block device."""
        return Drive.__api_session.get(
            "{}/{}".format(Drive.__drive_cfg_url, drive_id)
        )

    @staticmethod
    def create_json(
            drive_id=None,
            path_on_host=None,
            is_root_device=None,
            partuuid=None,
            is_read_only=None,
            rate_limiter=None
    ):
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
        if rate_limiter is not None:
            datax['rate_limiter'] = rate_limiter
        return datax


class Logger:
    """Facility for setting up the logging system and sending API requests."""

    LOGGER_CFG_RESOURCE = 'logger'

    __logger_cfg_url = None
    __api_session = None

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        type(self).__logger_cfg_url = api_url + self.LOGGER_CFG_RESOURCE
        type(self).__api_session = api_session

    @classmethod
    def put(cls, **args):
        """Configure or update the settings of the logging system."""
        datax = cls.create_json(**args)
        return Logger.__api_session.put(
            "{}".format(Logger.__logger_cfg_url),
            json=datax
        )

    @classmethod
    def patch(cls, **args):
        """Configure or update the settings of the logging system."""
        datax = cls.create_json(**args)
        return Logger.__api_session.patch(
            "{}".format(Logger.__logger_cfg_url),
            json=datax
        )

    @staticmethod
    def create_json(
            log_fifo=None,
            metrics_fifo=None,
            level=None,
            show_level=None,
            show_log_origin=None,
            options=None
    ):
        """Compose the json associated to this type of API request."""
        datax = {}
        if log_fifo is not None:
            datax['log_fifo'] = log_fifo
        if metrics_fifo is not None:
            datax['metrics_fifo'] = metrics_fifo
        if level is not None:
            datax['level'] = level
        if show_level is not None:
            datax['show_level'] = show_level
        if show_log_origin is not None:
            datax['show_log_origin'] = show_log_origin
        if options is not None:
            datax['options'] = options
        return datax


class MachineConfigure:
    """Facility for configuring the machine capabilities."""

    MACHINE_CFG_RESOURCE = 'machine-config'

    __machine_cfg_url = None
    __api_session = None

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        type(self).__machine_cfg_url = api_url + self.MACHINE_CFG_RESOURCE
        type(self).__api_session = api_session

    @classmethod
    def put(cls, **args):
        """Specify the details of the machine configuration."""
        datax = cls.create_json(**args)
        return MachineConfigure.__api_session.put(
            "{}".format(MachineConfigure.__machine_cfg_url),
            json=datax
        )

    @classmethod
    def patch(cls, **args):
        """Update the details of the machine configuration."""
        datax = cls.create_json(**args)
        return MachineConfigure.__api_session.patch(
            "{}".format(MachineConfigure.__machine_cfg_url),
            json=datax
        )

    @classmethod
    def get(cls):
        """Get the status of configuring the current microvm."""
        return MachineConfigure.__api_session.get(
            MachineConfigure.__machine_cfg_url
        )

    @staticmethod
    def create_json(
            vcpu_count=None,
            mem_size_mib=None,
            ht_enabled=None,
            cpu_template=None
    ):
        """Compose the json associated to this type of API request."""
        datax = {}
        if vcpu_count is not None:
            datax['vcpu_count'] = vcpu_count
        if mem_size_mib is not None:
            datax['mem_size_mib'] = mem_size_mib
        if ht_enabled is not None:
            datax['ht_enabled'] = ht_enabled
        if cpu_template is not None:
            datax['cpu_template'] = cpu_template
        return datax


class MMDS:
    """Facility for sending microvm metadata services related API calls."""

    MMDS_CFG_RESOURCE = 'mmds'

    __mmds_cfg_url = None
    __api_session = None

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending MMDS API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        type(self).__mmds_cfg_url = api_url + self.MMDS_CFG_RESOURCE
        type(self).__api_session = api_session

    @classmethod
    def put(cls, **args):
        """Send a new MMDS request."""
        return MMDS.__api_session.put(
            "{}".format(MMDS.__mmds_cfg_url),
            json=args['json']
        )

    @classmethod
    def patch(cls, **args):
        """Update the details of some MMDS request."""
        return MMDS.__api_session.patch(
            "{}".format(MMDS.__mmds_cfg_url),
            json=args['json']
        )

    @classmethod
    def get(cls):
        """Get the status of the mmds request."""
        return MMDS.__api_session.get(
            MMDS.__mmds_cfg_url
        )


class Network:
    """Facility for handling network configuration for a microvm."""

    NET_CFG_RESOURCE = 'network-interfaces'

    __net_cfg_url = None
    __api_session = None

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        type(self).__net_cfg_url = api_url + self.NET_CFG_RESOURCE
        type(self).__api_session = api_session

    @classmethod
    def put(cls, **args):
        """Attach a new tap interface."""
        datax = cls.create_json(**args)
        return Network.__api_session.put(
            "{}/{}".format(Network.__net_cfg_url, args['iface_id']),
            json=datax
        )

    @classmethod
    def patch(cls, **args):
        """Apply an update to some tap interface."""
        datax = cls.create_json(**args)
        return Network.__api_session.patch(
            "{}/{}".format(Network.__net_cfg_url, args['iface_id']),
            json=datax
        )

    @staticmethod
    def create_json(
            iface_id=None,
            host_dev_name=None,
            guest_mac=None,
            allow_mmds_requests=None,
            rx_rate_limiter=None,
            tx_rate_limiter=None
    ):
        """Create the json for the net specific API request."""
        datax = {
            'iface_id': iface_id
        }

        if host_dev_name is not None:
            datax['host_dev_name'] = host_dev_name
        if guest_mac is not None:
            datax['guest_mac'] = guest_mac
        if allow_mmds_requests is not None:
            datax['allow_mmds_requests'] = allow_mmds_requests
        if tx_rate_limiter is not None:
            datax['tx_rate_limiter'] = tx_rate_limiter
        if rx_rate_limiter is not None:
            datax['rx_rate_limiter'] = rx_rate_limiter
        return datax


class Vsock:
    """Facility for handling vsock configuration for a microvm."""

    VSOCK_CFG_RESOURCE = 'vsock'

    __vsock_cfg_url = None
    __api_session = None

    def __init__(self, api_usocket_full_name, api_session):
        """Specify the information needed for sending API requests."""
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        api_url = API_USOCKET_URL_PREFIX + url_encoded_path + '/'
        type(self).__vsock_cfg_url = api_url + self.VSOCK_CFG_RESOURCE
        type(self).__api_session = api_session

    @classmethod
    def put(cls, **args):
        """Attach a new vsock device."""
        datax = cls.create_json(**args)
        return Vsock.__api_session.put(
            Vsock.__vsock_cfg_url,
            json=datax
        )

    @classmethod
    def patch(cls, **args):
        """Apply an update to some vsock device."""
        datax = cls.create_json(**args)
        return Vsock.__api_session.patch(
            Vsock.__vsock_cfg_url,
            json=datax
        )

    @staticmethod
    def create_json(
            vsock_id,
            guest_cid,
            uds_path
    ):
        """Create the json for the vsock specific API request."""
        datax = {
            'vsock_id': vsock_id,
            'guest_cid': guest_cid,
            'uds_path': uds_path
        }

        return datax
