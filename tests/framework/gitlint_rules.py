# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The user defined rules for gitlint."""

from gitlint.rules import CommitRule, RuleViolation

# Too few public methods (1/2) (too-few-public-methods)
# pylint: disable=R0903


class SignedOffBy(CommitRule):
    """Make sure that each commit contains a "Signed-off-by" line."""

    # The name of the rule.
    name = "body-requires-signed-off-by"

    # The unique id of the rule.
    id = "UC2"

    def validate(self, commit):
        """Validate user defined gitlint rules."""
        for line in commit.message.body:
            if line.startswith("Signed-off-by"):
                return []

        msg = "Body does not contain a 'Signed-off-by' line"
        return [RuleViolation(self.id, msg, line_nr=1)]
