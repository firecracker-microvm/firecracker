# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Opcode fuzzer test for aarch64."""

import platform
import time

import pytest

from framework import utils
from framework.utils_cpu_templates import nonci_on_arm

PLATFORM = platform.machine()

TIMEOUT = 4 * 60 * 60


def run_armshaker(vm):
    """
    Run armshaker inside uVM
    """

    # Git clone armshaker
    # We are using fork of `armsharker` because original version
    # does not compile with new versions of `glibc`
    # (`SIGSTKSZ` is not a constant anymore)
    cmd = "git clone https://github.com/ShadowCurse/armshaker"
    utils.run_cmd(cmd)

    # Compile armshaker
    utils.run_cmd("make", cwd="armshaker")

    # Copy armshaker to uVM
    vm.ssh.scp_put("armshaker/fuzzer", "/tmp/fuzzer")

    # Start armshaker inside tmux in order to let it run headless
    code, stdout, stderr = vm.ssh.execute_command(
        "tmux new-session -d 'cd /tmp && ./fuzzer'"
    )
    print("tmux armshaker code: ", code)
    print("tmux armshaker stdout: ", stdout)
    print("tmux armshaker stderr: ", stderr)

    curr_inst = ""
    # Armshaker tests all instructions from 0 to ffffffff
    while curr_inst != "ffffffff":
        time.sleep(10 * 60)
        code, stdout, stderr = vm.ssh.execute_command("cat /tmp/data/status")
        if stdout != "":
            curr_inst = stdout.split("\n")[0].split(":")[1]
            print("instuctions tested: ", curr_inst)
        else:
            print("couldn't read /tmp/data/status")
            print("code: ", code)
            print("stdout: ", stdout)
            print("stderr: ", stderr)

    # Execution succeeded. Print last status
    _, stdout, _ = vm.ssh.execute_command("cat /tmp/data/status")
    print("final status: ", stdout)


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
@pytest.mark.timeout(TIMEOUT)
@pytest.mark.nonci
def test_armshaker_default(test_microvm_with_api):
    """
    Run armshaker inside default uVM
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    vm.start()
    run_armshaker(vm)


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
@pytest.mark.timeout(TIMEOUT)
@nonci_on_arm
def test_armshaker_with_static_template(test_microvm_with_api, cpu_template):
    """
    Run armshaker inside uVM with static templates
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config(cpu_template=cpu_template)
    vm.add_net_iface()
    vm.start()
    run_armshaker(vm)


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
@pytest.mark.timeout(TIMEOUT)
@nonci_on_arm
def test_armshaker_with_custom_template(test_microvm_with_api, custom_cpu_template):
    """
    Run armshaker inside uVM with custom templates
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config()
    vm.cpu_config(custom_cpu_template["template"])
    vm.add_net_iface()
    vm.start()
    run_armshaker(vm)
