# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Some common defines used in different modules of the testing framework."""

from pathlib import Path

# URL prefix used for the API calls through a UNIX domain socket
API_USOCKET_URL_PREFIX = 'http+unix://'
# Firecracker's binary name
FC_BINARY_NAME = 'firecracker'
# Jailer's binary name
JAILER_BINARY_NAME = 'jailer'
# The Firecracker sources workspace dir
FC_WORKSPACE_DIR = Path(__file__).parent.parent.parent.resolve()
# Cargo target dir for the Firecracker workspace. Set via .cargo/config
FC_WORKSPACE_TARGET_DIR = Path(FC_WORKSPACE_DIR).joinpath("build/cargo_target")
# Cargo build directory for seccompiler
SECCOMPILER_TARGET_DIR = FC_WORKSPACE_DIR / "build/seccompiler"
# Folder containing JSON seccomp filters
SECCOMP_JSON_DIR = FC_WORKSPACE_DIR / "resources/seccomp"
# Maximum accepted duration of an API call, in milliseconds
MAX_API_CALL_DURATION_MS = 300
# Relative path to the location of the kernel file
MICROVM_KERNEL_RELPATH = 'kernel/'
# Relative path to the location of the filesystems
MICROVM_FSFILES_RELPATH = 'fsfiles/'
"""The s3 bucket that holds global Firecracker specifications"""
SPEC_S3_BUCKET = 'spec.ccfc.min'
"""The default s3 bucket that holds Firecracker microvm test images"""
DEFAULT_TEST_IMAGES_S3_BUCKET = 'spec.ccfc.min'
"""Global directory for any of the pytest tests temporary files"""
ENV_TEST_IMAGES_S3_BUCKET = 'TEST_MICROVM_IMAGES_S3_BUCKET'
"""Default test session root directory path"""
DEFAULT_TEST_SESSION_ROOT_PATH = "/srv"
"""Absolute path to the test results folder"""
TEST_RESULTS_DIR = Path(FC_WORKSPACE_DIR) / "test_results"
