# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Module for common statistic tests metadata providers."""

from abc import ABC, abstractmethod
from typing import Dict

from .criteria import CriteriaFactory
from .function import FunctionFactory
from .types import MeasurementDef, StatisticDef
from .baseline import Provider as BaselineProvider


# pylint: disable=R0903
class Provider(ABC):
    """Backend for test metadata retrieval.

    Metadata consists from measurements and statistics definitions.
    """

    def __init__(self, baseline_provider: BaselineProvider):
        """Initialize the metadata provider."""
        self._baseline_provider = baseline_provider

    @property
    @abstractmethod
    def measurements(self) -> Dict[str, MeasurementDef]:
        """Return measurement dictionary."""

    @property
    def baseline_provider(self) -> BaselineProvider:
        """Return the baseline provider."""
        return self._baseline_provider


# pylint: disable=R0903
class DictProvider(Provider):
    """Backend for test metadata retrieval."""

    UNIT_KEY = "unit"
    STATISTICS_KEY = "statistics"

    def __init__(self,
                 measurements: dict,
                 baseline_provider: BaselineProvider):
        """
        Initialize metadata provider.

        The provider expects to receive measurements following the below
        schema:
        ```
        "measurements": {
            "$id": "MEASUREMENTS_SCHEMA"
            "type": "object",
            "definitions": "definitions": {
                "Criteria": {
                    "type": "string",
                    "description": "Comparison criteria class name. They are
                    implemented in the `statistics.criteria` module."
                }
                "Function": {
                    "type": "string",
                    "description": "Statistic functions class name. They are
                    implemented in the `statistics.function` module."
                }
                "StatisticDef": {
                    {
                        "type": "object",
                        "description": "Exhaustive statistic definition."
                        "properties": {
                            "name":     { "type": "string" },
                            "function": {
                                "type": "string"
                                "$ref": "#/definitions/Function"
                            },
                            "criteria": {
                                "type": "string"
                                "$ref" "#/definitions/Criteria"
                            }
                        },
                        "required": ["function"]
                    }
                }
            },
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Measurement name."
                },
                "value": {
                    "type": "object",
                    "properties": {
                        "unit": "string",
                        "statistics": {
                            "type": "object",
                            "properties": {
                                "key": {
                                    "type": "string",
                                    "description": "Statistic name."
                                },
                                "value": {
                                    "type": "object",
                                    "$ref": "#/definitions/StatisticDef"
                                }
                            }
                        }
                    },
                    "required": ["unit"]
                }
            }
        }
        ```
        """
        super().__init__(baseline_provider)

        self._measurements = {}
        for ms_name in measurements:
            assert DictProvider.UNIT_KEY in measurements[ms_name], \
                f"'{DictProvider.UNIT_KEY}' field is required for '" \
                f"{ms_name}' measurement definition."
            assert DictProvider.STATISTICS_KEY in measurements[ms_name], \
                f"'{DictProvider.STATISTICS_KEY}' field is required for '" \
                f"{ms_name}' measurement definition."

            unit = measurements[ms_name][DictProvider.UNIT_KEY]
            st_defs = measurements[ms_name][DictProvider.STATISTICS_KEY]

            st_list = []
            for st_def in st_defs:
                # Mandatory.
                func_cls_name = st_def.get("function")
                assert func_cls_name, f"Error in '{ms_name}' " \
                                      "measurement definition: " \
                                      "'function' field is required for " \
                                      "measurement statistics definitions."

                func_cls = FunctionFactory.get(func_cls_name)
                assert func_cls_name, f"Error in '{ms_name}' " \
                                      "measurement definition: " \
                                      f"'{func_cls_name}' is not a valid " \
                                      f"statistic function."

                name = st_def.get("name")
                func = func_cls()
                if name:
                    func = func_cls(name)

                criteria = None
                criteria_cls_name = st_def.get("criteria")
                baseline = baseline_provider.get(ms_name, func.name)
                if criteria_cls_name and baseline:
                    criteria_cls = CriteriaFactory.get(criteria_cls_name)
                    assert criteria_cls, f"{criteria_cls_name} is not a " \
                                         f"valid criteria."
                    criteria = criteria_cls(baseline)

                st_list.append(StatisticDef(func, criteria))

            self._measurements[ms_name] = MeasurementDef(ms_name, unit,
                                                         st_list)

    @property
    def measurements(self):
        """Return measurement dictionary."""
        return self._measurements
