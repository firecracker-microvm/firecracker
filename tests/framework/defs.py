# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Some common defines used in different modules of the testing framework."""

import platform
from pathlib import Path

# Firecracker's binary name
FC_BINARY_NAME = "firecracker"

# The Firecracker sources workspace dir
FC_WORKSPACE_DIR = Path(__file__).parent.parent.parent.resolve()

# Folder containing JSON seccomp filters
SECCOMP_JSON_DIR = FC_WORKSPACE_DIR / "resources/seccomp"

# Maximum accepted duration of an API call, in milliseconds
MAX_API_CALL_DURATION_MS = 700

# Default test session root directory path
DEFAULT_TEST_SESSION_ROOT_PATH = "/srv"

# Default test session artifacts path
LOCAL_BUILD_PATH = FC_WORKSPACE_DIR / "build/"

# Absolute path to the test results folder
TEST_RESULTS_DIR = FC_WORKSPACE_DIR / "test_results"

# The minimum required host kernel version for which io_uring is supported in
# Firecracker.
MIN_KERNEL_VERSION_FOR_IO_URING = "5.10.51"

SUPPORTED_HOST_KERNELS = ["4.14", "5.10", "6.1"]

IMG_DIR = Path(DEFAULT_TEST_SESSION_ROOT_PATH) / "img"

# fall-back to the local directory
if not IMG_DIR.exists():
    IMG_DIR = LOCAL_BUILD_PATH / "img"

ARTIFACT_DIR = IMG_DIR / platform.machine()

MAX_SUPPORTED_VCPUS = 32
