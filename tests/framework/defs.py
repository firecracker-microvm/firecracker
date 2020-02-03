# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Some common defines used in different modules of the testing framework."""

from pathlib import Path

API_USOCKET_URL_PREFIX = 'http+unix://'
"""URL prefix used for the API calls through a UNIX domain socket."""
FC_BINARY_NAME = 'firecracker'
"""Firecracker's binary name."""
JAILER_BINARY_NAME = 'jailer'
"""Jailer's binary name."""
FC_WORKSPACE_DIR = Path(__file__).parent.parent.parent.resolve()
"""The Firecracker sources workspace dir."""
FC_WORKSPACE_TARGET_DIR = Path(FC_WORKSPACE_DIR).joinpath("build/cargo_target")
"""Cargo target dir for the Firecracker workspace. Set via .cargo/config."""
MAX_API_CALL_DURATION_MS = 300
"""Maximum accepted duration of an API call, in milliseconds."""
MICROVM_KERNEL_RELPATH = 'kernel/'
"""Relative path to the location of the kernel file."""
MICROVM_FSFILES_RELPATH = 'fsfiles/'
"""Relative path to the location of the filesystems."""
