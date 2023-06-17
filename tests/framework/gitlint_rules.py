# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The user defined rules for gitlint."""

from gitlint.rules import CommitRule, RuleViolation


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
        r"""Validate user defined gitlint rules.

        >>> from gitlint.tests.base import BaseTestCase
        >>> from gitlint.rules import RuleViolation
        ...
        >>> ends_signed = EndsSigned()
        ...
        >>> msg1 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Signed-off-by: name <email@domain>"
        ... )
        >>> commit1 = BaseTestCase.gitcommit(msg1)
        >>> ends_signed.validate(commit1)
        []
        >>> msg2 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Signed-off-by: name <email>\n\n"
        ... f"Co-authored-by: name <email>"
        ... )
        >>> commit2 = BaseTestCase.gitcommit(msg2)
        >>> ends_signed.validate(commit2)
        []
        >>> msg3 = (
        ... f"Title\n\nMessage.\n\n"
        ... )
        >>> commit3 = BaseTestCase.gitcommit(msg3)
        >>> vio3 = ends_signed.validate(commit3)
        >>> vio_msg3 = (
        ... f"'Signed-off-by:' not found "
        ... f"in commit message body"
        ... )
        >>> vio3 == [RuleViolation("UC2", vio_msg3)]
        True
        >>> msg4 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Signed-off-by: name <email@domain>\n\na sentence"
        ... )
        >>> commit4 = BaseTestCase.gitcommit(msg4)
        >>> vio4 = ends_signed.validate(commit4)
        >>> vio_msg4 = (
        ... f"Non 'Co-authored-by:' or 'Signed-off-by:'"
        ... f" string found following 1st 'Signed-off-by:'"
        ... )
        >>> vio4 == [RuleViolation("UC2", vio_msg4, None, 5)]
        True
        >>> msg5 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Co-authored-by: name <email@domain>\n\n"
        ... f"a sentence."
        ... )
        >>> commit5 = BaseTestCase.gitcommit(msg5)
        >>> vio5 = ends_signed.validate(commit5)
        >>> vio_msg5 = (
        ... f"'Co-authored-by:' found before 'Signed-off-by:'"
        ... )
        >>> vio5 == [RuleViolation("UC2", vio_msg5, None, 3)]
        True
        >>> msg6 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Signed-off-by: name <email@domain>\n\n"
        ... f"Co-authored-by: name <email@domain>\n\n"
        ... f"a sentence"
        ... )
        >>> commit6 = BaseTestCase.gitcommit(msg6)
        >>> vio6 = ends_signed.validate(commit6)
        >>> vio_msg6 = (
        ... f"Non 'Co-authored-by:' string found "
        ... f"after 1st 'Co-authored-by:'"
        ... )
        >>> vio6 == [RuleViolation("UC2", vio_msg6, None, 6)]
        True
        """

        # Utilities
        def rtn(stmt, i):
            return [RuleViolation(self.id, stmt, None, i)]

        co_auth = "Co-authored-by:"
        sig = "Signed-off-by:"

        message_iter = enumerate(commit.message.original.split("\n"))

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
                f"Non '{co_auth}' or '{sig}' string found " f"following 1st '{sig}'",
                i,
            )

        # Checks lines following co-author are only additional co-authors.
        for i, line in message_iter:
            if line and not line.startswith(co_auth):
                return rtn(
                    f"Non '{co_auth}' string found after 1st '{co_auth}'",
                    i,
                )

        # Return no errors
        return []
