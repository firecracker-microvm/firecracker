# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for security tests"""

import json
from pathlib import Path

import pytest

from host_tools.cargo_build import run_seccompiler_bin


@pytest.fixture()
def seccompiler(tmp_path):
    "A seccompiler helper fixture"

    class Seccompiler:
        "A seccompiler helper class"

        def compile(self, data: dict, basic=False) -> Path:
            "Use seccompiler-bin to compile a filter from a dict"
            inp = tmp_path / "input.json"
            inp.write_text(json.dumps(data))
            bpf = tmp_path / "output.bpfmap"
            run_seccompiler_bin(bpf_path=bpf, json_path=inp, basic=basic)
            return bpf

    return Seccompiler()
