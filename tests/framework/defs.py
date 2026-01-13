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

DEFAULT_BINARY_DIR = (
    LOCAL_BUILD_PATH
    / "cargo_target"
    / f"{platform.machine()}-unknown-linux-musl"
    / "release"
)

SUPPORTED_HOST_KERNELS = ["5.10", "6.1"]

# When pytest is run in the devctr the test.sh scipt copies artifacts (rootfs, guest kernels, etc)
# to the /srv/test_artifacts within the container
ARTIFACT_DIR = Path(DEFAULT_TEST_SESSION_ROOT_PATH) / "test_artifacts"

# Fall-back to the local directory if pytest was run without test.sh script
if not ARTIFACT_DIR.exists():
    current_artifacts_dir = (
        (Path(LOCAL_BUILD_PATH) / "current_artifacts")
        .read_text(encoding="utf-8")
        .strip()
    )
    ARTIFACT_DIR = FC_WORKSPACE_DIR / current_artifacts_dir
