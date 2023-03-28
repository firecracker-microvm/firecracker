# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Compare gathered baselines interactively."""

import enum
import json
import sys

import questionary
from utils.comparator import BaseComparator
from utils.defs import DEFAULT_BASELINE_DIRECTORY
from utils.fetcher import BaselineDirectoryFetcher


class Command(enum.Enum):
    """List of commands"""

    LOAD = "Load baseline JSON files"
    COMPARE = "Compare baseline values"
    QUIT = "Quit"


class InteractiveComparator(BaseComparator):
    """Class for comparing baselines interactively"""

    def __init__(self):
        super().__init__()
        self._fetchers = {}

    @property
    def fethcers(self):
        """Return fetchers"""
        return self._fetchers

    def cmd_loop(self):
        """Main loop to receive command"""
        while True:
            cmd = questionary.select(
                "Select command:",
                choices=[c.value for c in Command],
            ).ask()

            if cmd == Command.LOAD.value:
                self.cmd_load()
            elif cmd == Command.COMPARE.value:
                self.cmd_compare()
            elif cmd == Command.QUIT.value:
                print("Bye.")
                break

    def cmd_load(self):
        """Load command"""
        dpath = questionary.path(
            "Enter directory path to load JSON:",
            default=DEFAULT_BASELINE_DIRECTORY,
        ).ask()
        if not dpath:
            return

        dfetcher = BaselineDirectoryFetcher(dpath)
        self._fetchers.update(dfetcher.fetchers)

    def cmd_compare(self):
        """Compare command"""
        # select
        path1, instance1, model1 = self._select("source")
        if path1 is None:
            return

        test = self._fetchers[path1].test
        path2, instance2, model2 = self._select("target", test)
        if path2 is None:
            return

        # calculate diff
        diff = self.calc_diff(
            self._fetchers[path1].get_baseline(instance1, model1),
            self._fetchers[path2].get_baseline(instance2, model2),
        )

        # calculate stats
        stats = self.calc_stats(diff)

        # print to stdout
        print(
            f"Test: {test}\n"
            f"Source:\n"
            f"  Instance type: {instance1}\n"
            f"  CPU model: {model1}\n"
            f"  JSON path: {path1}\n"
            f"Target:\n"
            f"  Instance type: {instance2}\n"
            f"  CPU model: {model2}\n"
            f"  JSON path: {path2}\n"
            f"Stats:\n"
            f"{json.dumps(stats, indent=4)}"
        )

        # dump results
        data = {
            "test": test,
            "source": {
                "path": path1,
                "instance": instance1,
                "model": model1,
            },
            "target": {"path": path1, "instance": instance2, "model": model2},
            "diff": diff,
            "stats": stats,
        }
        self._dump(data)

    def _select(self, sample, test=None):
        """Select a baseline"""
        # select file
        if test:
            choices = [f.fpath for f in self._fetchers.values() if f.test == test]
        else:
            choices = self._fetchers.keys()

        if len(choices) == 0:
            print(
                "No available data. Please import JSON files.",
                file=sys.stderr,
            )
            return None, None, None

        path = questionary.select(
            f"Select path for {sample} sample:",
            choices=sorted(choices),
        ).ask()
        if not path:
            return None, None, None

        # select instance type
        instance = questionary.select(
            f"Select instance type for {sample} sample:",
            choices=self._fetchers[path].get_instances(),
        ).ask()
        if not instance:
            return None, None, None

        # select CPU model
        models = self._fetchers[path].get_models(instance)
        if len(models) == 1:
            model = models[0]
        else:
            model = questionary.select(
                f"Select CPU for {sample} sample:",
                choices=models,
            ).ask()
            if not model:
                return None, None, None

        return path, instance, model

    def _dump(self, data):
        """Dump results"""
        ofile = questionary.text(
            "Enter file path to dump (Keep empty not to dump):"
        ).ask()
        if not ofile:
            return

        dumped = json.dumps(data, indent=4)
        with open(ofile, "w", encoding="utf-8") as file:
            file.write(dumped)


def main():
    """Main function"""
    comp = InteractiveComparator()
    comp.cmd_loop()


if __name__ == "__main__":
    main()
