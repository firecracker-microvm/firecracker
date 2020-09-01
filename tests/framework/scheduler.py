# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Pytest plugin that schedules tests to run concurrently.

This plugin adds a new command line option (`--concurrency`), allowing the
user to choose the maximum number of worker processes that can run tests
concurrently.

Tests are split into batches, each batch being assigned a maximum concurrency
level. For instance, all performance tests will run sequentially
(i.e. concurrency=1), since they rely on the availability of the full host
resources, in order to make accurate measurements. Additionally, other tests
may be restricted to running sequentially, if they are per se
concurrency-unsafe. See `PytestScheduler.pytest_runtestloop()`.

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
from random import random
from select import select
from time import sleep
import pytest
# Needed to force deselect nonci tests.
from _pytest.mark import Expression, MarkMatcher
from _pytest.main import ExitCode

from . import mpsing  # pylint: disable=relative-beyond-top-level


class PytestScheduler(mpsing.MultiprocessSingleton):
    """A pretty custom test execution scheduler."""

    def __init__(self):
        """Initialize the scheduler.

        Not to be called directly, since this is a singleton. Use
        `PytestScheduler.instance()` to get the scheduler object.
        """
        super().__init__()
        self._mp_singletons = [self]
        self.session = None

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
            help="Concurrency level (max number of worker processes to spawn)."
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

    @staticmethod
    def filter_batch(config, batch, marker_name):
        """Deselect marked tests which are not explicitly selected."""
        deselected = []
        expr = Expression.compile(config.option.markexpr)
        for item in batch['items'][:]:
            for key in item.keywords:
                if key is marker_name and \
                        not expr.evaluate(MarkMatcher.from_item(item)):
                    deselected.append(item)
                    batch['items'].remove(item)
                    break

        config.hook.pytest_deselected(items=deselected)

    def pytest_runtestloop(self, session):
        """Pytest hook. The main test scheduling and running loop.

        Called in the server process context.
        """
        # Don't run tests on test discovery
        if session.config.option.collectonly:
            return True

        # max_concurrency = self.session.config.option.concurrency
        schedule = [
            {
                # Performance batch: tests that measure performance, and need
                # to be run in a non-cuncurrent environment.
                'name': 'performance',
                'concurrency': 1,
                'patterns': [
                    "/performance/.+",
                ],
                'items': []
            },
            {
                # Unsafe batch: tests that, for any reason, are not
                # concurrency-safe, and therefore need to be run sequentially.
                'name': 'unsafe',
                'concurrency': 1,
                'patterns': [
                    "/functional/test_initrd.py",
                    "/functional/test_max_vcpus.py",
                    "/functional/test_rate_limiter.py",
                    "/functional/test_signals.py",
                    "/build/test_coverage.py"
                ],
                'items': []
            },
            {
                # Safe batch: tests that can be run safely in a concurrent
                # environment.
                'name': 'safe',
                # FIXME: we still have some framework concurrency issues
                # which prevent us from successfully using `max_concurrency`.
                # 'concurrency': max_concurrency,
                'concurrency': 1,
                'patterns': [
                    "/functional/.+",
                    "/build/.+",
                    "/security/.+"
                ],
                'items': []
            },
            {
                # Unknown batch: a catch-all batch, scheduling any tests that
                # haven't been categorized to run sequentially (since we don't
                # know if they are concurrency-safe).
                'name': 'unknown',
                'concurrency': 1,
                'patterns': [".+"],
                'items': []
            }
        ]

        # Go through the list of tests and assign each of them to its
        # corresponding batch in the schedule.
        for item in session.items:
            # A test can match any of the patterns defined by the batch,
            # in order to get assigned to it.
            for batch in schedule:
                # Found a matching batch. No need to look any further.
                if re.search(
                    "|".join(["({})".format(x) for x in batch['patterns']]),
                    "/".join(item.listnames()),
                ) is not None:
                    batch['items'].append(item)
                    break

        # Filter out empty batches.
        schedule = [batch for batch in schedule if batch['items']]

        # Evaluate marker expression only for the marked batch items.
        # If pytest runs with a marker expression which does not include
        # `nonci` marked tests (e.g `-m "not nonci" or non-existent marker
        # expression), the tests marked with `nonci` marker will be skipped.
        for batch in schedule:
            PytestScheduler.filter_batch(session.config,
                                         batch,
                                         marker_name="nonci")
            break

        for batch in schedule:
            self._raw_stdout(
                "\n[ ",
                self._colorize('yellow', batch['name']),
                " | ",
                "{} tests".format(len(batch['items'])),
                " | ",
                "{} worker(s)".format(batch['concurrency']),
                " ]\n"
            )
            self._run_batch(batch)

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

    def _run_batch(self, batch):
        """Run the tests in this batch, spread across multiple workers.

        Called in the server process context.
        """
        max_workers = batch['concurrency']
        items_per_worker = max(1, int(len(batch['items']) / max_workers))
        workers = []
        while batch['items']:
            # Pop `items_per_worker` out from this batch and send them to
            # a new worker.
            worker_items = batch['items'][-items_per_worker:]
            del batch['items'][-items_per_worker:]

            # Avoid storming the host with too many workers started at once.
            _delay = random() + len(workers) / 5.0 if max_workers > 1 else 0

            # Create the worker process and start it up.
            worker = mp.Process(
                target=self._worker_main,
                args=(worker_items, _delay)
            )
            workers.append(worker)
            worker.start()

        # Main loop, reaping workers and processing IPC requests.
        while workers:
            rlist, _, _ = select(self._mp_singletons, [], [], 0.1)
            for mps in rlist:
                mps.handle_ipc_call()
            _ = [w.join() for w in workers if not w.is_alive()]
            workers = [w for w in workers if w.is_alive()]

    def _worker_main(self, items, startup_delay=0):
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
        self.session.items = items

        # Disable the terminal reporting plugin, so it doesn't mess up
        # stdout, when run in a multi-process context.
        # The terminal reporter plugin will remain enabled in the server
        # process, gathering data via worker calls to `_add_report()`.
        trep = self.session.config.pluginmanager.get_plugin("terminalreporter")
        self.session.config.pluginmanager.unregister(trep)

        for item, nextitem in zip(
                self.session.items,
                self.session.items[1:] + [None]
                ):
            item.ihook.pytest_runtest_protocol(item=item, nextitem=nextitem)

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
            "teardown.skipped": ""
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
            "skipped": "yellow"
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
            "\n"
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
            'red': b"\x1b[31m",
            'yellow': b"\x1b[33m",
            'green': b"\x1b[32m",
            'reset': b"\x1b(B\x1b[m"
        }
        return term_codes[color] + msg + term_codes['reset']

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
