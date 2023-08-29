# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Defines utilities for performing A/B-tests.

A/B-Tests are style of tests where we do not care what state a test is in, but only that this state does not change
across a pull request. This is useful if
1. Validating the state requires some baseline to be persisted in the repository, and maintaining this baseline
   adds significant operational burden (for example, performance tests), or
2. The state can change due to outside factors (e.g. Hardware changes), and such external changes would block all
   pull requests until they are resolved.

Consider for example a `cargo audit` tests, which is used to reject usage of dependency versinos that have known
security vulnerabilities, or which have been yanked. The "state" here is "list of vulnerable dependencies". Clearly,
this can change due to external action (a new vulnerability is discovered and published to RustSec). At this point,
every PR would fail until this dependency is removed, blocking all development. Simply removing the test from PR CI
is not an option, since we want to avoid the scenario where a PR adds a dependency with a known vulnerability (e.g.
the PR itself changes the "list of vulnerable dependencies"). A/B-Testing allows us to not block PRs on the former case,
while still preventing the latter: We run cargo audit twice, once on main HEAD, and once on the PR HEAD. If the output
of both invocations is the same, the test passes (with us being alerted to this situtation via a special pipeline that
does not block PRs). If not, it fails, preventing PRs from introducing new vulnerable dependencies.
"""
import contextlib
import os
from tempfile import TemporaryDirectory
from typing import Callable, Optional, TypeVar

from framework import utils

# Locally, this will always compare against main, even if we try to merge into, say, a feature branch.
# We might want to do a more sophisticated way to determine a "parent" branch here.
DEFAULT_A_REVISION = os.environ.get("BUILDKITE_PULL_REQUEST_BASE_BRANCH", "main")


T = TypeVar("T")
U = TypeVar("U")


def default_comparator(ah: T, be: T) -> bool:
    """Returns `true` iff that the two arguments are equal.

    The default assertion for A/B-tests using `ab_test`.

    Ridiculous variable names sponsored by pylint."""
    return ah == be


def git_ab_test(
    test_runner: Callable[[bool], T],
    comparator: Callable[[T, T], U] = default_comparator,
    *,
    a_revision: str = DEFAULT_A_REVISION,
    b_revision: Optional[str] = None,
) -> (T, T, U):
    """
    Performs an A/B-test using the given test runner between the specified revision, and the currently checked out revision.
    The specified revisions will be checked out in temporary directories, with `test_runner` getting executed in the
    repository root. If the test depends on firecracker binaries built from the requested revision, care has to be taken
    that they are built from the sources in the temporary directory (which can be ensured via the `workspace` parameter
    to `cargo_build.get_binary`).

    Note that there are no guarantees on the order in which the two tests are run.

    :param test_runner: A callable which when executed runs the test in the context of the current working directory. Its
                        parameter is `true` if and only if it is currently running the "A" test.
    :param comparator: A callable taking two outputs from `test_runner` and comparing them. Should return some value
                       indicating whether the test should pass or no, which will be returned by the `ab_test` functions,
                       and on which the caller can then do an assertion.
    :param a_revision: The revision to checkout for the "A" part of the test. Defaults to the pull request target branch
                       if run in CI, and "main" otherwise.
    :param b_revision: The git revision to check out for "B" part of the test. Defaults to whatever is currently checked
                       out (in which case no temporary directory will be created).
    :return: The output of both "A" test, the "B" test and the comparator, which can then be used for assertions
             (alternatively, your comparator can perform any required assertions and not return anything).
    """

    # We can't just checkout random branches in the current working directory. Locally, this might not work because of
    # uncommitted changes. In the CI this will not work because multiple tests will run in parallel, and thus switching
    # branches will cause random failures in other tests.
    with temporary_checkout(a_revision) as a_tmp:
        with chdir(a_tmp):
            result_a = test_runner(True)

        if b_revision:
            with temporary_checkout(b_revision) as b_tmp:
                with chdir(b_tmp):
                    result_b = test_runner(False)
                # Have to call comparator here to make sure both temporary directories exist (as the comparator
                # might rely on some files that were created during test running, see the benchmark test)
                comparison = comparator(result_a, result_b)
        else:
            # By default, pytest execution happens inside the `tests` subdirectory. Change to the repository root, as
            # documented.
            with chdir(".."):
                result_b = test_runner(False)
            comparison = comparator(result_a, result_b)

        return result_a, result_b, comparison


@contextlib.contextmanager
def temporary_checkout(revision: str):
    """
    Context manager that checks out firecracker in a temporary directory and `chdir`s into it

    Will change back to whatever was the current directory when the context manager was entered, even if exceptions
    happen along the way.
    """
    with TemporaryDirectory() as tmp_dir:
        utils.run_cmd(
            f"git clone https://github.com/firecracker-microvm/firecracker {tmp_dir}"
        )

        with chdir(tmp_dir):
            utils.run_cmd(f"git checkout {revision}")

        yield tmp_dir


# Once we upgrade to python 3.11, this will be in contextlib:
# https://docs.python.org/3/library/contextlib.html#contextlib.chdir
@contextlib.contextmanager
def chdir(to):
    """Context manager that temporarily `chdir`s to the specified path"""
    cur = os.getcwd()

    try:
        os.chdir(to)
        yield
    finally:
        os.chdir(cur)
