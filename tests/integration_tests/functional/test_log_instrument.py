# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Checks that the output of instrumentation examples is correct"""
import pytest

from framework import utils
from host_tools.cargo_build import get_binary

EXPECTED_OUTPUTS = {
    "one": """[2023-10-12T16:29:00Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:29:00Z DEBUG one] cmp: true
[2023-10-12T16:29:00Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:29:00Z INFO  one] 4
[2023-10-12T16:29:00Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:29:00Z DEBUG one] cmp: false
[2023-10-12T16:29:00Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:29:00Z INFO  one] 6
[2023-10-12T16:29:00Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:29:00Z DEBUG one] cmp: false
[2023-10-12T16:29:00Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:29:00Z INFO  one] 7""".splitlines(),
    "two": """[2023-10-12T16:29:30Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:29:30Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:29:30Z INFO  two] None
[2023-10-12T16:29:30Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:29:30Z DEBUG two] [\"a\", \"b\"]
[2023-10-12T16:29:30Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:29:30Z INFO  two] Some([\"a\", \"b\"])""".splitlines(),
    "three": """[2023-10-12T16:30:04Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:30:04Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:30:04Z INFO  three] None
[2023-10-12T16:30:04Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:30:04Z DEBUG three] [\"a\", \"b\"]
[2023-10-12T16:30:04Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:30:04Z INFO  three] Some([\"a\", \"b\"])""".splitlines(),
    "four": """[2023-10-12T16:30:37Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:30:37Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:30:37Z INFO  four] None
[2023-10-12T16:30:37Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:30:37Z DEBUG four] [\"a\", \"b\"]
[2023-10-12T16:30:37Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:30:37Z INFO  four] Some([\"a\", \"b\"])""".splitlines(),
    "five": """[2023-10-12T16:31:12Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:31:12Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:31:12Z INFO  five] None
[2023-10-12T16:31:12Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:31:12Z DEBUG five] [\"a\", \"b\"]
[2023-10-12T16:31:12Z DEBUG five] 23
[2023-10-12T16:31:12Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:31:12Z INFO  five] Some([\"a\", \"b\"])""".splitlines(),
    "six": """[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:31:54Z DEBUG six] cmp: true
[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:31:54Z INFO  six] 4
[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:31:54Z DEBUG six] cmp: false
[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)::one>>two
[2023-10-12T16:31:54Z DEBUG six] res: 0
[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)::one<<two
[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:31:54Z INFO  six] 0
[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)>>one
[2023-10-12T16:31:54Z DEBUG six] cmp: false
[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)::one>>two
[2023-10-12T16:31:54Z DEBUG six] res: 1
[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)::one<<two
[2023-10-12T16:31:54Z TRACE log_instrument] ThreadId(1)<<one
[2023-10-12T16:31:54Z INFO  six] 1""".splitlines(),
}


@pytest.mark.parametrize(
    "example, expected_output", EXPECTED_OUTPUTS.items(), ids=EXPECTED_OUTPUTS
)
def test_instrumentation_example_output(example, expected_output):
    """Test the output of instrumentation examples does not change"""
    example_binary = get_binary("log-instrument", example=example)

    # Logging output goes to stderr
    _, stdout, stderr = utils.check_output(str(example_binary))

    assert not stdout

    lines = stderr.splitlines()
    assert len(lines) == len(expected_output)
    for line_number, line in enumerate(stderr.splitlines()):
        # Need to strip off timestamps
        assert line[20:] == expected_output[line_number][20:]
