# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

'''
This file implements functionality for generating reports.

A report typically consists of what tests have been executed, the type of test,
what functionality it validates, what is the criteria that we use to validate
and an optional link to a GitHub issue.

To pick up all the items listed above, this module defines the `Report` class
which is responsible for gathering data on what tests have been executed,
extracting test information and generating the report.

While some items such as test name can be extracted directly from code, others
such as test type or issue link are extracted from the function docstring.
A test docstring is defined like below:
    def test_net_device():
        """
        Test description
        @type: regression
        @issue: https://github.com/firecracker-microvm/firecracker/issues/1
        """

    return "Actual value: 8", "Maximum value: 10"

On the first line we define the test description. Each subsequent item is
defined by specifying a token enclosed by '@' and ':'. None of these tokens
is mandatory to be defined in the docstring. If the token is missing, the
report may contain the default value or no value at all.

Since we also want to store what test criteria we're targetting for a test to
pass, the framework picks up the values returned by each test to report this
data.

The format used for returning the test criteria is a tuple, with the first
element being the actual value or result and the second one being the checked
limits.

For example, for the test above the reported criteria would be
    'Maximum value: 10'
While the test result would be:
    'Actual value: 8'

The test framework does not do any comparison here, so it's the users
responsibility to properly report these values.
'''
import datetime
import inspect
import json
import re
import subprocess
from collections import namedtuple
from pathlib import Path
from . import mpsing   # pylint: disable=relative-beyond-top-level

# Try to see if we're in a git repo. If yes, set the commit ID
COMMIT_ID = ""
try:
    COMMIT_ID = subprocess.check_output(
        "git rev-parse HEAD",
        shell=True
    ).decode().strip()
except subprocess.CalledProcessError:
    COMMIT_ID = "Out of tree build"


class Report(mpsing.MultiprocessSingleton):
    """
    Class that holds data about what tests have been executed.

    Generates a test report at the end of the test session.
    """

    FNAME_JSON = "test_report.json"

    # Define a container for representing a report item.
    # It contains the default value, what items it accepts (None if anything is
    # accepted) and whether the item is filled from the docstring or not.
    # If not filled from the docstring, the test framework will add the content
    # through the test results.
    ReportItem = namedtuple("ReportItem",
                            ["value", "from_docstring", "one_of", "required"])

    # Contains a test item name, the value, optionally defines what values
    # it accepts and whether the value is required.
    # This is where we define what items we look-up in the docstring.
    doc_items = {
        # Internal test name representation
        "name": ReportItem("", False, None, False),

        # What the test does
        "description": ReportItem("", True, None, True),

        # If the test passed, failed or was skipped
        "outcome": ReportItem("", False, None, False),

        # How long the test took
        "duration": ReportItem(0, False, None, False),

        # What kind of test we're running. We only accept a predefined list
        # of tests.
        "type": ReportItem("", True, ["build", "functional", "performance",
                                      "security", "style"], True),

        # What we take into account to pass a test
        "criteria": ReportItem("", False, None, False),

        # Actual result compared to the criteria
        "result": ReportItem("", False, None, False),

        # Link to GitHub issue related to this test
        "issue": ReportItem("", True, None, False),
    }

    # A precomputed list of items that we pick up from the docstring.
    # It's composed of the items containing True as 'from_docscring' in the
    # doc_items list.
    # To avoid subsequent regex calls, we only build the regex pattern once.
    visible_items = \
        re.compile("(@[%s]+:)" %
                   "|".join([name for name, item in doc_items.items()
                             if item.from_docstring]))

    # Test description is not necessarily specified by a preceding
    # "@description:" string, so we assume that any string at the beginning
    # of the docstring is the test description.
    default_item = "description"

    class TestItem():
        """Holds data about one test item."""

        def __init__(self, test_function):
            """Parse test function and test report data."""
            self._test_data = self.parse_data(test_function)

            # Mark the item as not done yet
            self.done = False

        def finish(self, test_report):
            """Mark a test as finished and gather test data."""
            self._test_data["duration"] = test_report.duration
            self._test_data["outcome"] = test_report.outcome

            self.done = True

        def set_return(self, data):
            """Parse return values and set actual and expected values."""
            # If test has returned something and it's a tuple, parse it.
            if isinstance(data, tuple):
                self._test_data["result"] = str(data[0])
                self._test_data["criteria"] = str(data[1])

        @staticmethod
        def parse_data(test):
            """
            Parse data about the given test item.

            We use Report.doc_items to fill out a default dict, then we
            parse the docstring to gather data.
            """
            # Gets docstring and cleans up the content through `getdoc`
            data = inspect.getdoc(test.function)

            # Set the default item
            crt_item = Report.default_item

            # Create a dict with default values
            found_data = {
                key: Report.doc_items[key].value
                for key in Report.doc_items}
            found_data["name"] = test.nodeid

            # Handle None docstrings
            if not data:
                raise ValueError(
                    f"{found_data['name']}: Test requires docstring."
                )

            # Split docstring by items enclosed by '@' and ':'.
            # The point here is to split strings like:
            #   @TOKEN_NAME: VALUE
            # which results in ['TOKEN_NAME', 'VALUE']
            docstring_items = {}
            for item in re.split(Report.visible_items, data.strip()):
                # Check if the current item is one of the tokens
                if item[1:-1] in Report.doc_items:
                    crt_item = item[1:-1]
                    continue

                item_value = item.strip()
                crt_doc_item = Report.doc_items[crt_item]

                # If an item that's not picked up from the docstring is
                # specified, then continue.
                if not crt_doc_item.from_docstring:
                    continue

                # Check if we need to validate the item as 'one_of'
                if crt_doc_item.one_of and \
                        item_value not in crt_doc_item.one_of:
                    raise ValueError(
                        f"{crt_item} must be one of "
                        f"{crt_doc_item.one_of}, not {item_value}")

                # Check if the item was found twice
                if crt_item in docstring_items.keys():
                    raise ValueError(f"Item {crt_item} specified twice.")

                docstring_items[crt_item] = item_value

            # Look for required docstring items.
            for name, item in Report.doc_items.items():
                if not item.from_docstring or not item.required:
                    continue

                if name not in docstring_items:
                    raise ValueError(
                        f"{found_data['name']}: Test {name} is required."
                    )

                if docstring_items[name] == "":
                    raise ValueError(
                        f"{found_data['name']}: Test {name} is empty."
                    )

            return {**found_data, **docstring_items}

        def to_json(self):
            """Get data ready to be saved as a json."""
            return self._test_data

    def __init__(self, report_location="test_report/"):
        """Initialize a test report object with a given path."""
        super().__init__()
        self._mp_singletons = [self]

        self._collected_items = {}
        self._data_loc = Path(report_location)
        self._start_time = datetime.datetime.utcnow()

    def add_collected_items(self, items):
        """Add to report what items pytest has collected."""
        for item in items:
            self._collected_items[item.nodeid] = Report.TestItem(item)

    @mpsing.ipcmethod
    def set_return(self, nodeid, rval):
        """
        Set return value for a given test.

        This function is called over IPC and needs picklable
        objects as params.
        """
        self._collected_items[nodeid].set_return(rval)

    @mpsing.ipcmethod
    def finish_test_item(self, report):
        """Mark a test as finished and update the report."""
        self._collected_items[report.nodeid].finish(report)
        self.write_report(self._collected_items)

    def write_report(self, report_items):
        """Write test report to disk."""
        # Sort tests alphabetically and serialize to json
        self._data_loc.mkdir(exist_ok=True, parents=True)

        # Dump the JSON file
        with open(self._data_loc / Report.FNAME_JSON, "w") as json_file:
            total_duration = 0
            test_items = []
            for item in report_items.values():
                # Don't log items marked as not done. An item may be not done
                # because of a series of reasons, such an item being removed
                # from the test suite at runtime (e.g. lint tests only executed
                # on AMD)
                if not item.done:
                    continue

                item_json = item.to_json()

                test_items.append(item_json)
                # Add total test duration - does not include overhead from
                # fixtures and other conftest initializations.
                total_duration += item_json["duration"]

            json_data = {
                "commit_id": COMMIT_ID,
                "start_time_utc": str(self._start_time),
                "end_time_utc": str(datetime.datetime.utcnow()),
                "duration": total_duration,
                "test_items": test_items
            }
            json.dump(json_data, json_file, indent=4)
