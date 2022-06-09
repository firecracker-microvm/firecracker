# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The user defined rules for gitlint."""

from gitlint.rules import CommitRule, RuleViolation

# Too few public methods (1/2) (too-few-public-methods)
# pylint: disable=R0903


class EndsSigned(CommitRule):
    """Checks commit message body formatting.

    Makes sure each commit message body ends with
    1 or more signatures ("Signed-off-by"), followed by
    0 or more co-authors ("Co-authored-by").
    """

    # The name of the rule.
    name = "body-requires-signature"

    # The unique id of the rule.
    id = "UC2"

    def validate(self, commit):
        """Validate user defined gitlint rules."""
        # Utilities
        def rtn(stmt, i):
            return [RuleViolation(self.id, stmt, None, i)]

        co_auth = "Co-authored-by:"
        sig = "Signed-off-by:"

        message_iter = enumerate(commit.message.body)

        # Checks commit message contains a `sig` string
        found = False
        for i, line in message_iter:
            # We check that no co-authors are declared before signatures.
            if line.startswith(co_auth):
                return rtn(f"'{co_auth}' found before '{sig}'", i)
            if line.startswith(sig):
                found = True
                break

        # If no signature was found in the message
        # (before `message_iter` ended)
        if not found:
            return rtn(f"'{sig}' not found in commit message body", None)

        # Checks lines following signature are
        # either signatures or co-authors
        for i, line in message_iter:
            if line.startswith(sig) or not line.strip():
                continue

            # Once we encounter the first co-author,
            # we no longer accept signatures
            if line.startswith(co_auth):
                break

            return rtn(
                (f"Non '{co_auth}' or '{sig}' string found "
                 f"following 1st '{sig}'"),
                i,
            )

        # Checks lines following co-author are only additional co-authors.
        for i, line in message_iter:
            if not line.startswith(co_auth):
                return rtn(
                    f"Non '{co_auth}' string found after 1st '{co_auth}'",
                    i,
                )

        # Return no errors
        return []
