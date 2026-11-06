# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pytest plugin for running a dimension at extra values for chosen cases only."""

import pytest


def pin_variant(dim, values, when):
    """Convenience marker for running the `dim` fixture at `values`, all but the first only for cases matching `when`.

    `dim` must be a fixture with a default value, such as `track_dirty_pages`,
    not one with its own `params`, such as `pci_enabled`. `when` maps
    parameter names, fixtures included, to a value or to a list, tuple or set
    of values. Runs at the other values carry a marker named after `dim`,
    which must be registered in `pytest.ini`.

    Usage:
        @pytest.mark.parametrize("vcpus", [1, 2])
        @pin_variant("track_dirty_pages", [False, True], when={"vcpus": 2})
        def test_foo(uvm, vcpus, track_dirty_pages): ...
    """
    return pytest.mark.variant(dim, values, when=when)


def pytest_generate_tests(metafunc):
    """Parametrize each `pin_variant` dimension, marking its runs at the extra values."""
    for mark in metafunc.definition.iter_markers("variant"):
        dim, values = mark.args
        metafunc.parametrize(
            dim,
            [values[0]]
            + [
                pytest.param(value, marks=getattr(pytest.mark, dim))
                for value in values[1:]
            ],
            indirect=True,
        )


def _matches(params, when):
    return all(
        (
            params[name] in expected
            if isinstance(expected, (list, tuple, set, frozenset))
            else params[name] == expected
        )
        for name, expected in when.items()
    )


def _outside_when(item):
    for mark in item.iter_markers("variant"):
        dim, values = mark.args
        params = item.callspec.params
        if params[dim] != values[0] and not _matches(params, mark.kwargs["when"]):
            return True
    return False


def pytest_collection_modifyitems(config, items):
    """Deselect the `pin_variant` runs of cases that do not match `when`."""
    kept, deselected = [], []
    for item in items:
        (deselected if _outside_when(item) else kept).append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = kept
