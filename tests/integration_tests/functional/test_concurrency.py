# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Ensure multiple microVMs work correctly when spawned simultaneously."""

from concurrent.futures import ThreadPoolExecutor

from framework.utils import configure_mmds, populate_data_store

NO_OF_MICROVMS = 20


def test_run_concurrency_with_mmds(microvm_factory, guest_kernel, rootfs):
    """
    Spawn multiple firecracker processes to run concurrently with MMDS
    """

    data_store = {
        "latest": {
            "meta-data": {
                "ami-id": "ami-12345678",
                "reservation-id": "r-fea54097",
                "local-hostname": "ip-10-251-50-12.ec2.internal",
                "public-hostname": "ec2-203-0-113-25.compute-1.amazonaws.com",
                "dummy_res": ["res1", "res2"],
            },
            "Limits": {"CPU": 512, "Memory": 512},
            "Usage": {"CPU": 12.12},
        }
    }

    microvms = []
    # Launch guests with initially populated data stores
    for index in range(NO_OF_MICROVMS):
        microvm = microvm_factory.build(guest_kernel, rootfs)
        microvm.spawn()
        microvm.add_net_iface()

        # Configure MMDS before population
        configure_mmds(microvm, iface_ids=["eth0"], version="V2")

        # Populate data store with some data prior to starting the guest
        populate_data_store(microvm, data_store)
        microvm.basic_config(vcpu_count=1, mem_size_mib=128)
        microvm.start()

        # We check that the vm is running by testing that the ssh does
        # not time out.
        microvm.ssh.run("true")
        microvms.append(microvm)

    # With all guests launched and running send a batch of
    # MMDS patch requests to all running microvms.
    for index in range(NO_OF_MICROVMS):
        test_microvm = microvms[index]
        dummy_json = {
            "latest": {
                "meta-data": {
                    "ami-id": "another_dummy",
                    "secret_key10": "eaasda48141411aeaeae10",
                    "secret_key11": "eaasda48141411aeaeae11",
                    "secret_key12": "eaasda48141411aeaeae12",
                    "secret_key13": "eaasda48141411aeaeae13",
                    "secret_key14": "eaasda48141411aeaeae14",
                    "secret_key15": "eaasda48141411aeaeae15",
                    "secret_key16": "eaasda48141411aeaeae16",
                    "secret_key17": "eaasda48141411aeaeae17",
                    "secret_key18": "eaasda48141411aeaeae18",
                    "secret_key19": "eaasda48141411aeaeae19",
                    "secret_key20": "eaasda48141411aeaeae20",
                }
            }
        }
        test_microvm.api.mmds.patch(json=dummy_json)


def test_run_concurrency(microvm_factory, guest_kernel, rootfs):
    """
    Check we can spawn multiple microvms.
    """

    def launch1():
        microvm = microvm_factory.build(guest_kernel, rootfs)
        microvm.spawn()
        microvm.basic_config(vcpu_count=1, mem_size_mib=128)
        microvm.add_net_iface()
        microvm.start()

        # We check that the vm is running by testing that the ssh does
        # not time out.
        microvm.ssh.run("true")

    with ThreadPoolExecutor(max_workers=NO_OF_MICROVMS) as tpe:
        for _ in range(NO_OF_MICROVMS):
            tpe.submit(launch1)
