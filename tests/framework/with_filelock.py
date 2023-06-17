# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Simple decorator so that only one process is running the decorated function
at any one time.

Caveat: two functions sharing the same name and using this decorator will use
the same lock, which may be unintended, but safe.

TBD disambiguate with the module name in that case.
"""


import functools
import tempfile
from pathlib import Path

from filelock import FileLock


def with_filelock(func):
    """Decorator so that only one process is running the decorated function at
    any one time.
    """

    tmp_dir = Path(tempfile.gettempdir())

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        lock_path = (tmp_dir / func.__name__).with_suffix(".lock")
        lock = FileLock(lock_path)
        with lock:
            return func(*args, **kwargs)

    return wrapper
