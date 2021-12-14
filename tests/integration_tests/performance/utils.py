# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility abstractions for performance tests."""


def handle_failure(file_dumper, fail_err):
    """Handle `statistics.core.CoreException` raised during...

    ...`statistics.core.Core`s `run_exercise`.

    :param file_dumper - ResultsFileDumper
    :param fail_err - statistics.CoreException
    """
    file_dumper.dump(fail_err.result)
    if fail_err:
        raise fail_err
