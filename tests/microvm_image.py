"""
This module defines `MicrovmImageFetcher`, a python borg class used to interact
with a s3 bucket containing structured microvm images.

# Notes

- Programming here is not defensive, since tests systems turn false negatives
  into a quality-improving positive feedback loop.
"""

import re
import os
from typing import List

import boto3

from microvm import MicrovmSlot


class MicrovmImageS3Fetcher:
    """
    A borg class for fetching Firecracker microvm images from microvm image
    s3 buckets.

    Microvm Image Bucket Layout
    ===========================

    A microvm image bucket needs to obey a specific layout, described below.

    Folder Layout
    -------------

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

    Tagging
    -------

    Microvm image folders are tagged with the capabilities of that image:

    ``` json
    TagSet = [{"key": "capability:<cap_name>", "value": ""}, ...]
    ```

    Credentials
    ===========

    When run on an EC2 instance, `boto3` will check for IMDS credentials if no
    other credentials are found. This mechanism is relied upon for running test
    sessions within an account that has access to the microvm-image-bucket. If
    that is not the case, local credentials must be present. See `boto3`
    documentation.
    """

    MICROVM_IMAGES_RELPATH = 'microvm-images/'
    MICROVM_IMAGE_KERNEL_RELPATH = 'kernel/'
    MICROVM_IMAGE_BLOCKDEV_RELPATH = 'fsfiles/'
    MICROVM_IMAGE_KERNEL_FILE_SUFFIX = r'vmlinux.bin'
    MICROVM_IMAGE_ROOTFS_FILE_SUFFIX = r'rootfs.ext4'
    CAPABILITY_KEY_PREFIX = 'capability:'

    __shared_state = {}
    """
    Singletons are one, and cumbersome to achieve in python. Borgs are many,
    but they all share the same state. This is now a borg class. All instances
    will share the same state, meaning that the s3 bucket will only be mapped
    once and the client can cache across all fixtures. You will be assimilated.
    """

    microvm_images = None

    def __init__(
        self,
        microvm_images_bucket,
        microvm_images_path=MICROVM_IMAGES_RELPATH
    ):
        self.__dict__ = self.__shared_state

        self.s3 = boto3.client('s3')
        # Will look for creds in IMDS if present.

        self.microvm_images_bucket = microvm_images_bucket
        self.microvm_images_path = microvm_images_path

        if self.microvm_images is None:
            self.map_bucket()

    def get_microvm_image(
        self,
        microvm_image_path,
        microvm_slot: MicrovmSlot
    ):
        """
        Fetches a microvm image into an existing microvm local slot. Assumes
        the correct microvm image/slot structure, and copies all microvm image
        resources into the microvm slot.
        """

        for resource_key in self.microvm_images[microvm_image_path]:
            if resource_key in [
                self.MICROVM_IMAGE_KERNEL_RELPATH,
                self.MICROVM_IMAGE_BLOCKDEV_RELPATH
            ]:
                # Kernel and blockdev dirs already exist in microvm_slot.
                continue

            source_rel_path = microvm_image_path + '/' + resource_key
            source_path = self.microvm_images_path + source_rel_path
            dest_path = microvm_slot.path + resource_key

            if resource_key.endswith('/'):
                # Create a new microvm_slot dir if one is encountered.
                os.mkdir(dest_path)
                continue

            self.s3.download_file(
                self.microvm_images_bucket,
                source_path,
                dest_path)

            if resource_key.endswith(self.MICROVM_IMAGE_KERNEL_FILE_SUFFIX):
                microvm_slot.kernel_file = dest_path

            if resource_key.endswith(self.MICROVM_IMAGE_ROOTFS_FILE_SUFFIX):
                microvm_slot.rootfs_file = dest_path

    def list_microvm_images(self, capability_filter: List[str]=['*']):
        """
        Returns a list of microvm images that have all the capabilities from
        the `capability_filter` list.
        """
        microvm_images_with_caps = []
        for cap in capability_filter:
            if cap == '*':
                microvm_images_with_caps.append({*self.microvm_images})
                continue
            microvm_images_with_caps.append(self.microvm_images_by_cap[cap])

        return list(set.intersection(*microvm_images_with_caps))

    def enum_capabilities(self):
        """ Returns a list of all the capabilities of all microvm images. """
        return [*self.microvm_images_by_cap]

    def map_bucket(self):
        """
        Maps all the keys and tags in the bucket so that the other methods can
        work on local objects.

        Populates `self.microvm_images` with
        {microvm_image_folder_key_n: [microvm_image_key_n, ...], ...}

        Populates `self.microvm_images_by_cap` with a capability dict:
        `{capability_n: {microvm_image_folder_key_n, ...}, ...}
        """

        self.microvm_images = {}
        self.microvm_images_by_cap = {}
        folder_key_groups_regex = re.compile(
            self.microvm_images_path + r'(.+?)/(.*)'
        )

        for obj in self.s3.list_objects_v2(
            Bucket=self.microvm_images_bucket,
            Prefix=self.microvm_images_path
        )['Contents']:
            key_groups = re.match(folder_key_groups_regex, obj['Key'])
            microvm_image_name = key_groups.group(1)
            resource = key_groups.group(2)

            if not resource:
                # This is a microvm image root folder.
                self.microvm_images[microvm_image_name] = []
                for cap in self.get_caps(obj['Key']):
                    if cap not in self.microvm_images_by_cap:
                        self.microvm_images_by_cap[cap] = set()
                    self.microvm_images_by_cap[cap].add(microvm_image_name)
            else:
                # This is key within a microvm image root folder.
                self.microvm_images[microvm_image_name].append(resource)

    def get_caps(self, key):
        """ Returns the set of capabilities of an s3 object key. """
        tagging = self.s3.get_object_tagging(
            Bucket=self.microvm_images_bucket,
            Key=key
        )
        return {
            tag['Key'][len(self.CAPABILITY_KEY_PREFIX):]
            for tag in tagging['TagSet']
            if tag['Key'].startswith(self.CAPABILITY_KEY_PREFIX)
        }
