# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Some common defines used in different modules of the testing framework."""

import platform
from enum import StrEnum
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

SUPPORTED_HOST_KERNELS = ["5.10", "6.1", "6.18"]

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


class LogLevel(StrEnum):
    """A log level accepted by Firecracker's `--level`.

    Firecracker parses the value case-insensitively (see
    `LevelFilter::from_str`), but the framework used to compare raw strings, so
    `"INFO"` and `"Info"` behaved differently here while being identical to
    Firecracker. Normalising through this enum keeps the two ends in agreement;
    callers may pass any casing.

    Firecracker also accepts `Warning` as an alias of `Warn`. Only the latter is
    a member, so the framework has one spelling per level.
    """

    OFF = "Off"
    ERROR = "Error"
    WARN = "Warn"
    INFO = "Info"
    DEBUG = "Debug"
    TRACE = "Trace"

    @classmethod
    def _missing_(cls, value):
        if not isinstance(value, str):
            return None
        folded = value.casefold()
        for member in cls:
            if member.value.casefold() == folded:
                return member
        return None
