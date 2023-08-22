# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Some common defines used in different modules of the testing framework."""

import platform
from pathlib import Path

# Firecracker's binary name
FC_BINARY_NAME = "firecracker"

# Jailer's binary name
JAILER_BINARY_NAME = "jailer"

# The Firecracker sources workspace dir
FC_WORKSPACE_DIR = Path(__file__).parent.parent.parent.resolve()

# Cargo target dir for the Firecracker workspace. Set via .cargo/config
FC_WORKSPACE_TARGET_DIR = FC_WORKSPACE_DIR / "build/cargo_target"

# Cargo build directory for seccompiler
SECCOMPILER_TARGET_DIR = FC_WORKSPACE_DIR / "build/seccompiler"

# Folder containing JSON seccomp filters
SECCOMP_JSON_DIR = FC_WORKSPACE_DIR / "resources/seccomp"

# Maximum accepted duration of an API call, in milliseconds
MAX_API_CALL_DURATION_MS = 700

# Default test session root directory path
DEFAULT_TEST_SESSION_ROOT_PATH = "/srv"

# Absolute path to the test results folder
TEST_RESULTS_DIR = FC_WORKSPACE_DIR / "test_results"

# Name of the file that stores firecracker's PID when launched by jailer with
#  `--new-pid-ns`.
FC_PID_FILE_NAME = "firecracker.pid"

# The minimum required host kernel version for which io_uring is supported in
# Firecracker.
MIN_KERNEL_VERSION_FOR_IO_URING = "5.10.51"

SUPPORTED_HOST_KERNELS = ["4.14", "5.10", "6.1"]

IMG_DIR = Path(DEFAULT_TEST_SESSION_ROOT_PATH) / "img"

# fall-back to the local directory
if not IMG_DIR.exists():
    IMG_DIR = Path(__file__).joinpath("../../../build/img").resolve()

ARTIFACT_DIR = IMG_DIR / platform.machine()
