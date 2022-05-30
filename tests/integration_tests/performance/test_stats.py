# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Smoke test for stats module."""

import json
import logging
import os
import pytest
import random

from framework.matrix import TestContext, TestMatrix
from framework.stats.baseline import Provider as BaselineProvider
from framework.stats.consumer import LambdaConsumer
from framework.stats import core
from framework.stats.core import Core
from framework.stats.metadata import DictProvider as DictMetadataProvider
from framework.stats.producer import LambdaProducer
from framework.utils import DictQuery, get_kernel_version
from framework.utils_cpuid import get_cpu_model_name
from integration_tests.performance.configs import defs
from integration_tests.performance.utils import handle_failure

TEST_ID = "stats"
kernel_version = get_kernel_version(level=1)
CONFIG_NAME_REL = "test_{}_config_{}.json".format(TEST_ID,
                                                  kernel_version)
CONFIG_NAME_ABS = os.path.join(defs.CFG_LOCATION, CONFIG_NAME_REL)
CONFIG = json.load(open(CONFIG_NAME_ABS, encoding='utf-8'))

# Measurements tags.
CPU_UTILIZATION_VMM = "cpu_utilization_vmm"
CPU_UTILIZATION_VMM_SAMPLES_TAG = "cpu_utilization_vmm_samples"
CPU_UTILIZATION_VCPUS_TOTAL = "cpu_utilization_vcpus_total"

# Data producers
def st_prod_func(llimit, ulimit):
    return {
        "randint": random.randint(llimit, ulimit),
        "state": random.getstate()
    }

st_prod = LambdaProducer(
        func=st_prod_func,
        func_kwargs={"llimit": 0, "ulimit": 100}
)

# The baseline provider is a requirement for the `DictProvider`.
class RandintBaselineProvider(BaselineProvider):
    def __init__(self, exercise_id, env_id):
        super().__init__(DictQuery({}))
        if "baselines" in CONFIG:
            super().__init__(DictQuery(CONFIG["baselines"][exercise_id]))
        self._tag = "{}/" + env_id + "/{}"
    def get(self, ms_name: str, st_name: str) -> dict:
        key = self._tag.format(ms_name, st_name)
        baseline = self._baselines.get(key)
        if baseline:
            target = baseline.get("target")
            return {
                "target": target,
            }
        return None

baseline_provider_sum = RandintBaselineProvider(
    "10RandomIntsSumExercise",
    "randint")
metadata_provider_sum = DictMetadataProvider(
    CONFIG["measurements"]["10RandomIntsSumExercise"],
    baseline_provider_sum)

# `LambdaConsumer` for exercice
def st_cons_sum_func(cons, res):
    cons.consume_data("ints", res["randint"])
    cons.consume_custom("PNGR_state", hash(res["state"]))

# The following function is consuming data points,
# pertaining to measurements defined above.
st_cons_sum = LambdaConsumer(
        st_cons_sum_func,
        metadata_provider=metadata_provider_sum)

# Defining statistics `Core`
# Both exercises require the core to drive both producers and consumers for
# 10 iterations to achieve the wanted result.
st_core = Core(name="randint_observation", iterations=10)
st_core.add_pipe(st_prod, st_cons_sum, tag="10RandomIntsSumExercise")

# Start the exercise by checking the criteria.
def test_stats(bin_cloner_path, results_file_dumper):
    """
    Smoke test for stats module.

    @type: performance
    """
    logger = logging.getLogger(TEST_ID)
    logger.info("Testing on processor %s", get_cpu_model_name())

    # Create a test context and add builder, logger, network.
    test_context = TestContext()
    test_context.custom = {
        'logger': logger,
        'name': TEST_ID,
        'results_file_dumper': results_file_dumper,
        'io_engine': 'Sync'
    }

    test_matrix = TestMatrix(context=test_context, artifact_sets=[])
    test_matrix.run_test(_test_stats)

def _test_stats(context):
    logger = context.custom["logger"]
    file_dumper = context.custom["results_file_dumper"]
    io_engine = context.custom["io_engine"]

    # Gather results and verify pass criteria.
    try:
        result = st_core.run_exercise()
    except core.CoreException as err:
        handle_failure(file_dumper, err)

    file_dumper.dump(result)
