# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Pytest plugin that schedules tests to run concurrently.

This plugin adds a new command line option (`--concurrency`), allowing the
user to choose the maximum number of worker processes that can run tests
concurrently.

Tests are typically run one at a time, with some tests being executed in
parallel with others.
There is an assumption made, that if a test starts a microvm, its performance
may be affected by other tests running in parallel with it, so for this reason
the test framework limits tests that launch microvms to be executed in parallel
with others.

In order to check if a test launches a VM, the framework looks up what fixtures
the test uses. If one of those fixtures matches the list enumerated in
`PytestScheduler.TestItem.CONC_FIXTURES_PREF`, then the tests concurrency limit
will be set to 1, which means that while that test is running, at most one test
can run in parallel with it.

Although these limitations are detected automatically, one can also define
concurrency limits manually by adding the `@pytest.mark.concurrency(ARG)`
decorator, where ARG can be a number or 'max'.
If ARG is a number, that number will be set as the concurrency level for the
test. If ARG is 'max' then the test will run using the maximum concurrency
limit set.
If ARG > maximum concurrency limit, then the concurrency level will not exceed
the maximum level.

Scheduling is achieved by overriding the pytest run loop (i.e.
`pytest_runtestloop()`), and splitting the test session item list across
multiple `fork()`ed worker processes. Since no user code is run before
`pytest_runtestloop()`, each worker becomes a pytest session itself.
Reporting is disabled for worker process, each worker sending its results
back to the main / server process, via an IPC pipe, for aggregation.
"""

import multiprocessing as mp
import os
import re
import sys
import threading
from pathlib import Path
from random import random
from select import select
from time import sleep
import pytest

from _pytest.main import ExitCode
import host_tools.proc as proc

from . import mpsing  # pylint: disable=relative-beyond-top-level
from . import defs  # pylint: disable=relative-beyond-top-level


class Suite:
    """Declare a test suite given a name and list of paths."""

    def __init__(self, name, path_list):
        """Initialize using name and list of paths."""
        self.name = name
        self.path_list = [Path(path) for path in path_list]
        self.ignored = []

    def ignore_path(self, path):
        """Ignore tests in this path."""
        self.ignored.append(path)

    def get_runnable_items(self, session_items):
        """Return a list of runnable items given the session items."""
        items = list(session_items)

        # A test can match any of the patterns defined by the batch,
        # in order to get assigned to it.
        to_remove = []
        for item in items:
            # Check if the file path matches any of the path lists
            matches_batch = re.search(
                "|".join(["({})".format(x) for x in self.path_list]),
                "/".join(item.listnames()),
            )

            # Don't continue if no path is matched
            if not matches_batch:
                to_remove.append(item)
                continue

            # Check if that file path also matches an ignored path
            is_ignored = None
            if len(self.ignored) > 0:
                is_ignored = re.search(
                    "|".join(["({})".format(x) for x in self.ignored]),
                    "/".join(item.listnames()),
                )
            if matches_batch and is_ignored is not None:
                to_remove.append(item)

        return set(items) - set(to_remove)


class PytestScheduler(mpsing.MultiprocessSingleton):
    """A pretty custom test execution scheduler."""

    class TestItem:  # pylint: disable=too-few-public-methods
        """Test item to run during this session."""

        # Fixture prefixes that will limit concurrency to 1
        CONC_FIXTURES_PREF = [
            defs.MICROVM_PREFIX_NAME,
            "bin_cloner_path",
            "network_config"]

        def __init__(self, item, max_concurrency):
            """
            Initialize with a given session item.

            Checks the test decorator concurrency marker and stores it.
            If no concurrency decorator is present, it sets it to 1.
            """
            self.item = item
            self.concurrency = 1

            # Concurrency marker overrides anything
            conc_marker = item.get_closest_marker("concurrency")
            if conc_marker:
                # Check if the concurrency marker was set as arg
                # e.g. concurrency(1)
                if len(conc_marker.args) >= 1:
                    (self.concurrency,) = conc_marker.args

                # 'max' means that we run at the given maximum
                if self.concurrency == "max":
                    self.concurrency = max_concurrency
            else:
                runs_microvm = False
                for fixture in item.fixturenames:
                    # Magic string that tells us that the test launches a VM
                    # If we find it in the fixture list, we assume that this
                    # test will run alone
                    for prefix in self.CONC_FIXTURES_PREF:
                        if fixture.startswith(prefix):
                            runs_microvm = True
                            break

                    if runs_microvm:
                        break

                self.concurrency = 1 if runs_microvm else max_concurrency

            self.concurrency = min(max_concurrency, self.concurrency)

        def can_run(self, workers):
            """
            Check if self can run in a pool of workers.

            Returns True if it can, False if it cannot.
            """
            # Check if the given item can run in parallel with
            # the current pool
            if self.concurrency <= len(workers):
                return False

            # Check if current workers can run in parallel with the new one
            for worker in workers.values():
                if worker.concurrency <= len(workers):
                    return False

            return True

    def __init__(self):
        """Initialize the scheduler.

        Not to be called directly, since this is a singleton. Use
        `PytestScheduler.instance()` to get the scheduler object.
        """
        super().__init__()
        self._mp_singletons = [self]
        self.session = None
        self.test_running = False

    def register_mp_singleton(self, mp_singleton):
        """Register a multi-process singleton object.

        Since the scheduler will be handling the main testing loop, it needs
        to be aware of any multi-process singletons that must be serviced
        during the test run (i.e. polled and allowed to handle method
        execution in the server context).
        """
        self._mp_singletons.append(mp_singleton)

    @staticmethod
    def do_pytest_addoption(parser):
        """Pytest hook. Add concurrency command line option."""
        avail_cpus = len(os.sched_getaffinity(0))
        # Defaulting to a third of the available (logical) CPUs sounds like a
        # good enough plan.
        default = max(1, int(avail_cpus / 3))
        parser.addoption(
            "--concurrency",
            "--concurrency",
            dest="concurrency",
            action="store",
            type=int,
            default=default,
            help="Concurrency level (max number of worker \
processes to spawn).",
        )

        parser.addoption(
            "--testsuite",
            "--testsuite",
            dest="testsuite",
            action="store",
            type=str,
            default="ci",
            help="Specify what test suite to run.",
        )

    def pytest_sessionstart(self, session):
        """Pytest hook. Called at pytest session start.

        This will execute in the server context (before the tests are
        executed).
        """
        self.session = session

    def pytest_runtest_logreport(self, report):
        """Pytest hook. Called whenever a new test report is ready.

        This will execute in the worker / child context.
        """
        self._add_report(report)

    def pytest_runtestloop(self, session):
        """Pytest hook. The main test scheduling and running loop.

        Called in the server process context.
        """
        # Don't run tests on test discovery
        if session.config.option.collectonly:
            return True

        # First, go through the args and check if a file was specified
        # If yes, then the user is telling us to run that file, not the
        # built-in test suites
        file_args = []
        for arg in session.config.args:
            if Path(arg).is_file():
                file_args.append(arg)

        test_suite = None
        if len(file_args) == 0:
            # Get available test suites
            available_suites = get_test_suites()

            # Get the given suite name by command line
            given_tsuite = session.config.option.testsuite

            # Check if the requested suite has been declared
            for suite in available_suites:
                if suite.name == given_tsuite:
                    test_suite = suite

            if not test_suite:
                raise ValueError(
                    f"Given test suite {given_tsuite} not available in: %s"
                    % ", ".join(suite.name for suite in available_suites)
                )
        else:
            test_suite = Suite("on-the-fly", file_args)

        self._run_items(test_suite.get_runnable_items(session.items))

        return "stahp"

    @pytest.mark.tryfirst
    # pylint: disable=unused-argument
    # pylint: disable=no-self-use
    def pytest_sessionfinish(self, session, exitstatus):
        """Pytest hook. Wrap up the whole testing session.

        Since the scheduler is more or less mangling the test session in order
        to distribute test items to worker processes, the main pytest process
        can become unaware of test failures and errors. Using this session
        wrap-up hook to set the correct exit code.
        """
        trep = session.config.pluginmanager.getplugin("terminalreporter")
        if "error" in trep.stats:
            session.exitstatus = ExitCode.INTERNAL_ERROR
        if "failed" in trep.stats:
            session.exitstatus = ExitCode.TESTS_FAILED

    def wait_for_worker_to_die(self, workers):
        """
        Wait for a worker to die.

        Polls worker list and handles any IPC calls.
        If one of the workers dies, it removes it from the workers dict.
        """
        while self.test_running:
            rlist, _, _ = select(self._mp_singletons, [], [], 0.1)
            for mps in rlist:
                mps.handle_ipc_call()

            for worker in list(workers.keys()):
                if not worker.is_alive():
                    del workers[worker]

    def _run_items(self, items):
        """Run test items and spread them by concurrency."""
        max_concurrency = self.session.config.option.concurrency
        test_items = [
            PytestScheduler.TestItem(i, max_concurrency) for i in items
        ]

        # Sort test items by highest concurrency value first
        items_prio = sorted(
            test_items, key=lambda c: c.concurrency, reverse=True
        )

        workers = {}
        self.test_running = True
        # Start a thread that reaps workers
        watcher = threading.Thread(
            target=self.wait_for_worker_to_die, args=(workers,))
        watcher.start()

        while items_prio:
            # Pop items and start processes as long as something can run
            if items_prio[0].can_run(workers):
                crt_item = items_prio.pop(0)

                # Avoid storming the host with too many workers
                # started at once.
                _delay = (
                    random() + len(workers) / 5.0 if len(workers) > 1 else 0
                )

                # Create the worker process and start it up.
                worker = mp.Process(
                    target=self._worker_main, args=(crt_item.item, _delay)
                )
                workers[worker] = crt_item
                worker.start()
            sleep(0.1)

        # Wait for all workers to die
        while workers:
            sleep(1)

        # Signal the thread that things are over and we're heading back home
        self.test_running = False
        watcher.join()

    def _worker_main(self, item, startup_delay=0):
        """Execute a bunch of test items sequentially.

        This is the worker process entry point and main loop.
        """
        sys.stdin.close()
        # Sleeping here to avoid storming the host when many workers are
        # started at the same time.
        #
        # TODO: investigate storming issue;
        #       Not sure what the exact problem is, but worker storms cause an
        #       elevated response time on the API socket. Since the reponse
        #       time is measured by our decorators, it also includes the
        #       Python libraries overhead, which might be non-negligible.
        sleep(startup_delay if startup_delay else 0)

        # Restrict the session to this worker's item list only.
        # I.e. make pytest believe that the test session is limited to this
        # worker's job.
        self.session.items = [item]

        # Disable the terminal reporting plugin, so it doesn't mess up
        # stdout, when run in a multi-process context.
        # The terminal reporter plugin will remain enabled in the server
        # process, gathering data via worker calls to `_add_report()`.
        trep = self.session.config.pluginmanager.get_plugin("terminalreporter")
        self.session.config.pluginmanager.unregister(trep)

        item.ihook.pytest_runtest_protocol(item=item, nextitem=None)

    @mpsing.ipcmethod
    def _add_report(self, report):
        """Send a test report to the server process.

        A report is generated for every test item, and for every test phase
        (setup, call, and teardown).
        """
        # Translation matrix from (when)x(outcome) to pytest's
        # terminalreporter plugin stats (dictionary) key.
        key_xlat = {
            "setup.passed": "",
            "setup.failed": "error",
            "setup.skipped": "skipped",
            "call.passed": "passed",
            "call.failed": "failed",
            "call.skipped": "skipped",
            "teardown.passed": "",
            "teardown.failed": "error",
            "teardown.skipped": "",
        }
        stats_key = key_xlat["{}.{}".format(report.when, report.outcome)]

        trep = self.session.config.pluginmanager.get_plugin("terminalreporter")
        if trep:
            if stats_key not in trep.stats:
                trep.stats[stats_key] = []
            trep.stats[stats_key].append(report)

        if stats_key:
            self._report_progress(report.nodeid, stats_key)

    def _report_progress(self, nodeid, outcome):
        """Show the user some nice progress indication."""
        outcome_cols = {
            "passed": "green",
            "failed": "red",
            "error": "red",
            "skipped": "yellow",
        }
        if outcome not in outcome_cols:
            return

        color = outcome_cols[outcome]
        self._raw_stdout(
            "  ",
            self._colorize(color, "{:10}".format(outcome.upper())),
            self._colorize(color, nodeid)
            if outcome in ["error", "failed"]
            else nodeid,
            "\n",
        )

    @staticmethod
    def _colorize(color, msg):
        """Add an ANSI / terminal color escape code to `msg`.

        If stdout is not a terminal, `msg` will just be encoded into a byte
        stream, without adding any ANSI decorations.
        Note: the returned value will always be a stream of bytes, not a
              string, since the result needs to be sent straight to the
              terminal.
        """
        if not isinstance(msg, bytes):
            msg = str(msg).encode("utf-8")
        if not sys.stdout.isatty():
            return msg
        term_codes = {
            "red": b"\x1b[31m",
            "yellow": b"\x1b[33m",
            "green": b"\x1b[32m",
            "reset": b"\x1b(B\x1b[m",
        }
        return term_codes[color] + msg + term_codes["reset"]

    @staticmethod
    def _raw_stdout(*words):
        """Send raw-byte output to stdout.

        All arguments are concatenated and, if necessary, encoded into raw
        byte streams, before being written to stdout.
        """
        byte_words = [
            w if isinstance(w, bytes) else str(w).encode("utf-8")
            for w in words
        ]
        buf = b"".join(byte_words)
        os.write(sys.stdout.fileno(), buf)


def get_test_suites():
    """Return a list of available test suites."""

    def suite_ci():
        schedule = Suite("ci", ["integration_tests/.+"])

        # Style related tests are run only on AMD.
        if "AMD" not in proc.proc_type():
            schedule.ignore_path("integration_tests/style/")

        # Snapshot perf tests don't run on AMD
        if "AMD" in proc.proc_type():
            schedule.ignore_path(
                "integration_tests/performance/test_snapshot_perf.py"
            )

        return schedule

    def suite_perf():
        return Suite("perf", ["performance_tests/.+"])

    return [suite_ci(), suite_perf()]
