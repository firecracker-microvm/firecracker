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
import shutil
import statistics
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, List, Optional, TypeVar

import scipy

from framework import utils
from framework.defs import FC_WORKSPACE_DIR
from framework.microvm import Microvm
from framework.utils import CommandReturn
from framework.with_filelock import with_filelock
from host_tools.cargo_build import get_firecracker_binaries

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
    test_runner: Callable[[Path, bool], T],
    comparator: Callable[[T, T], U] = default_comparator,
    *,
    a_revision: str = DEFAULT_A_REVISION,
    b_revision: Optional[str] = None,
) -> (T, T, U):
    """
    Performs an A/B-test using the given test runner between the specified revision, and the currently checked out revision.
    The specified revisions will be checked out in temporary directories, with `test_runner` getting executed in the
    repository root. If the test depends on firecracker binaries built from the requested revision, care has to be taken
    that they are built from the sources in the temporary directory.

    Note that there are no guarantees on the order in which the two tests are run.

    :param test_runner: A callable which when executed runs the test in the context of the current working directory. Its
                        first parameter is a temporary directory in which firecracker is checked out at some revision.
                        The second parameter is `true` if and only if the checked out revision is the "A" revision.
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
        result_a = test_runner(a_tmp, True)

        if b_revision:
            with temporary_checkout(b_revision) as b_tmp:
                result_b = test_runner(b_tmp, False)
                # Have to call comparator here to make sure both temporary directories exist (as the comparator
                # might rely on some files that were created during test running, see the benchmark test)
                comparison = comparator(result_a, result_b)
        else:
            # By default, pytest execution happens inside the `tests` subdirectory. Pass the repository root, as
            # documented.
            result_b = test_runner(Path.cwd().parent, False)
            comparison = comparator(result_a, result_b)

        return result_a, result_b, comparison


def is_pr() -> bool:
    """Returns `True` iff we are executing in the context of a build kite run on a pull request"""
    return os.environ.get("BUILDKITE_PULL_REQUEST", "false") != "false"


def git_ab_test_host_command_if_pr(
    command: str,
    *,
    comparator: Callable[[CommandReturn, CommandReturn], bool] = default_comparator,
    **kwargs,
):
    """Runs the given bash command as an A/B-Test if we're in a pull request context (asserting that its stdout and
    stderr did not change across the PR). Otherwise runs the command, asserting it returns a zero exit code
    """
    if is_pr():
        git_ab_test_host_command(command, comparator=comparator)
    else:
        utils.run_cmd(command, **kwargs, cwd=Path.cwd().parent)


def git_ab_test_host_command(
    command: str,
    *,
    comparator: Callable[[CommandReturn, CommandReturn], bool] = default_comparator,
    a_revision: str = DEFAULT_A_REVISION,
    b_revision: Optional[str] = None,
):
    """Performs an A/B-Test of the specified command, asserting that both the A and B invokations return the same stdout/stderr"""
    (_, old_out, old_err), (_, new_out, new_err), the_same = git_ab_test(
        lambda path, _is_a: utils.run_cmd(command, ignore_return_code=True, cwd=path),
        comparator,
        a_revision=a_revision,
        b_revision=b_revision,
    )

    assert (
        the_same
    ), f"The output of running command `{command}` changed:\nOld:\nstdout:\n{old_out}\nstderr:\n{old_err}\n\nNew:\nstdout:\n{new_out}\nstderr:\n{new_err}"


def set_did_not_grow_comparator(
    set_generator: Callable[[CommandReturn], set]
) -> Callable[[CommandReturn, CommandReturn], bool]:
    """Factory function for comparators to use with git_ab_test_command that converts the command output to sets
    (using the given callable) and then checks that the "B" set is a subset of the "A" set
    """
    return lambda output_a, output_b: set_generator(output_b).issubset(
        set_generator(output_a)
    )


def git_ab_test_with_binaries(
    test_runner: Callable[[Path, Path], T],
    comparator: Callable[[T, T], U] = default_comparator,
    *,
    a_revision: str = DEFAULT_A_REVISION,
    b_revision: Optional[str] = None,
) -> (T, T, U):
    """Similar to `git_ab_test`, with the only difference being that this function compiles firecracker at the specified
    revisions and only passes the firecracker binaries to the test_runner. Maintains a cache of previously compiled
    revisions, to prevent excessive recompilation across different tests of the same revision
    """

    @with_filelock
    def grab_binaries(checkout: Path):
        with chdir(checkout):
            revision = utils.run_cmd("git rev-parse HEAD").stdout.strip()

        revision_store = FC_WORKSPACE_DIR / "build" / revision
        if not revision_store.exists():
            firecracker, jailer = get_firecracker_binaries(workspace_dir=checkout)

            revision_store.mkdir(parents=True, exist_ok=True)
            shutil.copy(firecracker, revision_store / "firecracker")
            shutil.copy(jailer, revision_store / "jailer")

        return (
            revision_store / "firecracker",
            revision_store / "jailer",
        )

    return git_ab_test(
        lambda checkout, _is_a: test_runner(*grab_binaries(checkout)),
        comparator,
        a_revision=a_revision,
        b_revision=b_revision,
    )


def git_ab_test_guest_command(
    microvm_factory: Callable[[Path, Path], Microvm],
    command: str,
    *,
    comparator: Callable[[CommandReturn, CommandReturn], bool] = default_comparator,
    a_revision: str = DEFAULT_A_REVISION,
    b_revision: Optional[str] = None,
):
    """The same as git_ab_test_command, but via SSH. The closure argument should setup a microvm using the passed
    paths to firecracker and jailer binaries."""

    def test_runner(firecracker, jailer):
        microvm = microvm_factory(firecracker, jailer)
        return microvm.ssh.run(command)

    (_, old_out, old_err), (_, new_out, new_err), the_same = git_ab_test_with_binaries(
        test_runner, comparator, a_revision=a_revision, b_revision=b_revision
    )

    assert (
        the_same
    ), f"The output of running command `{command}` changed:\nOld:\nstdout:\n{old_out}\nstderr\n{old_err}\n\nNew:\nstdout:\n{new_out}\nstderr:\n{new_err}"


def git_ab_test_guest_command_if_pr(
    microvm_factory: Callable[[Path, Path], Microvm],
    command: str,
    *,
    comparator=default_comparator,
):
    """The same as git_ab_test_command_if_pr, but via SSH"""
    if is_pr():
        git_ab_test_guest_command(microvm_factory, command, comparator=comparator)
    else:
        microvm = microvm_factory(*get_firecracker_binaries())
        ecode, stdout, stderr = microvm.ssh.run(command)
        assert ecode == 0, f"stdout:\n{stdout}\nstderr:\n{stderr}\n"


def check_regression(
    a_samples: List[float], b_samples: List[float], *, n_resamples: int = 9999
):
    """Checks for a regression by performing a permutation test. A permutation test is a non-parametric test that takes
    three parameters: Two populations (sets of samples) and a function computing a "statistic" based on two populations.
    First, the test computes the statistic for the initial populations. It then randomly
    permutes the two populations (e.g. merges them and then randomly splits them again). For each such permuted
    population, the statistic is computed. Then, all the statistics are sorted, and the percentile of the statistic for the
    initial populations is computed. We then look at the fraction of statistics that are larger/smaller than that of the
    initial populations. The minimum of these two fractions will then become the p-value.

    The idea is that if the two populations are indeed drawn from the same distribution (e.g. if performance did not
    change), then permuting will not affect the statistic (indeed, it should be approximately normal-distributed, and
    the statistic for the initial populations will be somewhere "in the middle").

    Useful for performance tests.
    """
    return scipy.stats.permutation_test(
        (a_samples, b_samples),
        # Compute the difference of means, such that a positive different indicates potential for regression.
        lambda x, y: statistics.mean(y) - statistics.mean(x),
        vectorized=False,
        n_resamples=n_resamples,
    )


@contextlib.contextmanager
def temporary_checkout(revision: str):
    """
    Context manager that checks out firecracker in a temporary directory and `chdir`s into it

    Will change back to whatever was the current directory when the context manager was entered, even if exceptions
    happen along the way.
    """
    with TemporaryDirectory() as tmp_dir:
        # `git clone` can take a path instead of an URL, which causes it to create a copy of the
        # repository at the given path. However, that path needs to point to the root of a repository,
        # it cannot be some arbitrary subdirectory. Therefore:
        _, git_root, _ = utils.run_cmd("git rev-parse --show-toplevel")
        # split off the '\n' at the end of the stdout
        utils.run_cmd(f"git clone {git_root.strip()} {tmp_dir}")

        with chdir(tmp_dir):
            utils.run_cmd(f"git checkout {revision}")

        yield Path(tmp_dir)

        # If we compiled firecracker inside the checkout, python's recursive shutil.rmdir will
        # run incredibly long. Thus, remove manually.
        utils.run_cmd(f"rm -rf {tmp_dir}")


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
