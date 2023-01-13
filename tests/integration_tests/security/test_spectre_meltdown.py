# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# N.B.: Although this repository is released under the Apache-2.0, part of its test requires a
# script from the third party "Spectre & Meltdown Checker" project. This script is under the
# GPL-3.0-only license.
"""Tests spectre / meltdown mitigation."""

import pytest
import requests

from framework import utils


CHECKER_URL = "https://meltdown.ovh"
CHECKER_FILENAME = "spectre-meltdown-checker.sh"


@pytest.fixture(scope="session", name="spectre_meltdown_checker")
def download_spectre_meltdown_checker(tmp_path_factory):
    """Download spectre / meltdown checker script."""
    resp = requests.get(CHECKER_URL, timeout=5)
    resp.raise_for_status()

    path = tmp_path_factory.mktemp("tmp", True) / CHECKER_FILENAME
    path.write_bytes(resp.content)

    return path


def test_spectre_meltdown_checker_on_host(spectre_meltdown_checker):
    """
    Test with the spectre / meltdown checker on host.

    @type: security
    """
    utils.run_cmd(f"sh {spectre_meltdown_checker} --explain")


def test_spectre_meltdown_checker_on_guest(
    spectre_meltdown_checker,
    test_microvm_with_spectre_meltdown,
    network_config,
):
    """
    Test with the spectre / meltdown checker on guest.

    @type: security
    """
    microvm = test_microvm_with_spectre_meltdown
    microvm.spawn()
    microvm.basic_config()
    microvm.ssh_network_config(network_config, "1")
    microvm.start()

    run_spectre_meltdown_checker_on_guest(
        microvm,
        spectre_meltdown_checker,
    )


def test_spectre_meltdown_checker_on_guest_with_template(
    spectre_meltdown_checker,
    test_microvm_with_spectre_meltdown,
    network_config,
    cpu_template,
):
    """
    Test with the spectre / meltdown checker on guest with CPU template.

    @type: security
    """
    microvm = test_microvm_with_spectre_meltdown
    microvm.spawn()
    microvm.basic_config()
    resp = microvm.machine_cfg.put(
        vcpu_count=2,
        mem_size_mib=256,
        cpu_template=cpu_template,
    )
    assert microvm.api_session.is_status_no_content(resp.status_code)
    microvm.ssh_network_config(network_config, "1")
    microvm.start()

    run_spectre_meltdown_checker_on_guest(
        microvm,
        spectre_meltdown_checker,
    )


def run_spectre_meltdown_checker_on_guest(
    microvm,
    spectre_meltdown_checker,
):
    """Run the spectre / meltdown checker on guest"""
    remote_path = f"/bin/{CHECKER_FILENAME}"
    microvm.ssh.scp_file(spectre_meltdown_checker, remote_path)
    ecode, stdout, stderr = microvm.ssh.execute_command(f"sh {remote_path} --explain")
    assert ecode == 0, f"stdout:\n{stdout.read()}\nstderr:\n{stderr.read()}\n"
