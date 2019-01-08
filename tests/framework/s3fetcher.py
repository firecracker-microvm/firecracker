# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define a class for interacting with microvm images in s3."""

import os
import re

from shutil import copyfile
from typing import List

import boto3
import botocore.client


class MicrovmImageS3Fetcher:
    """A borg class for fetching Firecracker microvm images from s3.

    # Microvm Image Bucket Layout

    A microvm image bucket needs to obey a specific layout, described below.

    ## Folder Layout

    ``` tree
    s3://<microvm-image-bucket>/<microvm-image-path>/
        <microvm_image_folder_n>/
            kernel/
                <optional_kernel_name>vmlinux.bin
            fsfiles/
                <rootfs_file_name>rootfs.ext4
                <other_fsfile_n>
                ...
            <other_resource_n>
            ...
        ...
    ```

    ## Tagging

    Microvm image folders are tagged with the capabilities of that image:

    ``` json
    TagSet = [{"key": "capability:<cap_name>", "value": ""}, ...]
    ```

    # Credentials

    `boto3` is configured to not perform the signing step at all by using
    the `signature_version=UNSIGNED` so no credentials are needed. Thus, the
    bucket where the microVM images are stored needs to be publicly accessible.
    """

    MICROVM_IMAGES_RELPATH = 'img/'
    MICROVM_IMAGE_KERNEL_RELPATH = 'kernel/'
    MICROVM_IMAGE_BLOCKDEV_RELPATH = 'fsfiles/'
    MICROVM_IMAGE_KERNEL_FILE_SUFFIX = r'vmlinux.bin'
    MICROVM_IMAGE_ROOTFS_FILE_SUFFIX = r'rootfs.ext4'
    MICROVM_IMAGE_SSH_KEY_SUFFIX = r'.id_rsa'

    ENV_LOCAL_IMAGES_PATH_VAR = 'OPT_LOCAL_IMAGES_PATH'

    CAPABILITY_KEY_PREFIX = 'capability:'

    _microvm_images = None
    _microvm_images_by_cap = None
    _microvm_images_bucket = None
    _s3 = None

    def __init__(
        self,
        microvm_images_bucket
    ):
        """Initialize S3 client, list of microvm images and S3 bucket name."""
        self._microvm_images_bucket = microvm_images_bucket
        self._s3 = boto3.client(
            's3',
            config=botocore.client.Config(signature_version=botocore.UNSIGNED)
        )
        self._map_bucket()
        assert self._microvm_images and self._microvm_images_by_cap

    def init_vm_resources(self, microvm_image_name, microvm):
        """Populate the microvm resource path with the necessary resources.

        Assumes the correct microvm image structure, and copies all
        microvm image resources into the microvm resource path.
        """
        for resource_key in self._microvm_images[microvm_image_name]:
            if resource_key in [
                self.MICROVM_IMAGE_KERNEL_RELPATH,
                self.MICROVM_IMAGE_BLOCKDEV_RELPATH
            ]:
                # Kernel and blockdev dirs already exist in the microvm's
                # allocated resources.
                continue

            microvm_dest_path = os.path.join(microvm.path, resource_key)
            if resource_key.endswith('/'):
                # Create a new microvm_directory if one is encountered.
                os.mkdir(microvm_dest_path)
                continue

            image_rel_path = os.path.join(
                self.MICROVM_IMAGES_RELPATH,
                microvm_image_name
            )

            # Relative path of a microvm resource within a microvm directory.
            resource_rel_path = os.path.join(
                image_rel_path,
                resource_key
            )

            if self.ENV_LOCAL_IMAGES_PATH_VAR in os.environ:
                # There's a user-managed local microvm image directory.
                resource_root_path = (
                    os.environ.get(self.ENV_LOCAL_IMAGES_PATH_VAR)
                )
            else:
                # Use a root path in the temporary test session directory.
                resource_root_path = microvm.path

            # Local path of a microvm resource. Used for downloading resources
            # only once.
            resource_local_path = os.path.join(
                resource_root_path,
                resource_rel_path
            )

            if not os.path.exists(resource_local_path):
                # Locally create / download an s3 resource the first time we
                # encounter it.
                os.makedirs(
                    os.path.dirname(resource_local_path),
                    exist_ok=True
                )
                self._s3.download_file(
                    self._microvm_images_bucket,
                    resource_rel_path,
                    resource_local_path)

            if not os.path.exists(microvm_dest_path):
                copyfile(resource_local_path, microvm_dest_path)

            if resource_key.endswith(self.MICROVM_IMAGE_KERNEL_FILE_SUFFIX):
                microvm.kernel_file = microvm_dest_path

            if resource_key.endswith(self.MICROVM_IMAGE_ROOTFS_FILE_SUFFIX):
                microvm.rootfs_file = microvm_dest_path

            if resource_key.endswith(self.MICROVM_IMAGE_SSH_KEY_SUFFIX):
                # Add the key path to the config dictionary and set
                # permissions.
                microvm.ssh_config['ssh_key_path'] = microvm_dest_path
                os.chmod(microvm_dest_path, 400)

    def hardlink_vm_resources(
            self,
            microvm_image_name,
            from_microvm,
            to_microvm
    ):
        """Hardlink resources from one microvm to another.

        Assumes the correct microvm image structure for the source vm specified
        by the `from_microvm` parameter and copies all necessary resources into
        the destination microvm specified through the `to_microvm` parameter.
        """
        for resource_key in self._microvm_images[microvm_image_name]:
            if resource_key in [
                self.MICROVM_IMAGE_KERNEL_RELPATH,
                self.MICROVM_IMAGE_BLOCKDEV_RELPATH
            ]:
                # Kernel and blockdev dirs already exist in the microvm's
                # allocated resources.
                continue

            microvm_dest_path = os.path.join(to_microvm.path, resource_key)
            microvm_source_path = os.path.join(from_microvm.path, resource_key)

            if resource_key.endswith('/'):
                # Create a new microvm_directory if one is encountered.
                os.mkdir(microvm_dest_path)
                continue

            if not os.path.exists(microvm_dest_path):
                os.link(microvm_source_path, microvm_dest_path)

            if resource_key.endswith(self.MICROVM_IMAGE_KERNEL_FILE_SUFFIX):
                to_microvm.kernel_file = microvm_dest_path

            if resource_key.endswith(self.MICROVM_IMAGE_ROOTFS_FILE_SUFFIX):
                to_microvm.rootfs_file = microvm_dest_path

            if resource_key.endswith(self.MICROVM_IMAGE_SSH_KEY_SUFFIX):
                # Add the key path to the config dictionary and set
                # permissions.
                to_microvm.ssh_config['ssh_key_path'] = microvm_dest_path
                os.chmod(microvm_dest_path, 400)

    def list_microvm_images(self, capability_filter: List[str] = None):
        """Return microvm images with the specified capabilities."""
        capability_filter = capability_filter or ['*']
        microvm_images_with_caps = []
        for cap in capability_filter:
            if cap == '*':
                microvm_images_with_caps.append({*self._microvm_images})
                continue
            microvm_images_with_caps.append(self._microvm_images_by_cap[cap])

        return list(set.intersection(*microvm_images_with_caps))

    def enum_capabilities(self):
        """Return a list of all the capabilities of all microvm images."""
        return [*self._microvm_images_by_cap]

    def _map_bucket(self):
        """Map all the keys and tags in the s3 microvm image bucket.

        This allows the other methods to work on local objects.

        Populates `self._microvm_images` with
        {microvm_image_folder_key_n: [microvm_image_key_n, ...], ...}

        Populates `self._microvm_images_by_cap` with a capability dict:
        `{capability_n: {microvm_image_folder_key_n, ...}, ...}
        """
        self._microvm_images = {}
        self._microvm_images_by_cap = {}
        folder_key_groups_regex = re.compile(
            self.MICROVM_IMAGES_RELPATH + r'(.+?)/(.*)'
        )

        for obj in self._s3.list_objects_v2(
            Bucket=self._microvm_images_bucket,
            Prefix=self.MICROVM_IMAGES_RELPATH
        )['Contents']:
            key_groups = re.match(folder_key_groups_regex, obj['Key'])
            if key_groups is None:
                # Ignore files (leaves) under MICROVM_IMAGES_RELPATH
                continue
            microvm_image_name = key_groups.group(1)
            resource = key_groups.group(2)

            if not resource:
                # This is a microvm image root folder.
                self._microvm_images[microvm_image_name] = []
                for cap in self._get_caps(obj['Key']):
                    if cap not in self._microvm_images_by_cap:
                        self._microvm_images_by_cap[cap] = set()
                    self._microvm_images_by_cap[cap].add(microvm_image_name)
            else:
                # This is key within a microvm image root folder.
                self._microvm_images[microvm_image_name].append(resource)

    def _get_caps(self, key):
        """Return the set of capabilities of an s3 object key."""
        tagging = self._s3.get_object_tagging(
            Bucket=self._microvm_images_bucket,
            Key=key
        )
        return {
            tag['Key'][len(self.CAPABILITY_KEY_PREFIX):]
            for tag in tagging['TagSet']
            if tag['Key'].startswith(self.CAPABILITY_KEY_PREFIX)
        }
