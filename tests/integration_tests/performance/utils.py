# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility abstractions for performance tests."""
import json


def handle_failure(file_dumper, fail_err):
    """Handle `statistics.core.CoreException` raised during...

    ...`statistics.core.Core`s `run_exercise`.

    :param file_dumper - ResultsFileDumper
    :param fail_err - statistics.CoreException
    """
    dump_test_result(file_dumper, fail_err.result)
    if fail_err:
        raise fail_err


def dump_test_result(file_dumper, result):
    """Dump tests results to file using the `file_dumper`.

    :param file_dumper - ResultsFileDumper
    :param result - dict
    """
    if isinstance(result, dict) and file_dumper:
        file_dumper.writeln(json.dumps(result))
