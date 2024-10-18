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
        r"""Validates Signed-off-by and Co-authored-by tags as Linux's scripts/checkpatch.pl

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
        ... f"Co-authored-by: name <email>\n\n"
        ... f"Signed-off-by: name <email>"
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
        ... f"'Signed-off-by:' not found in commit message body"
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
        ... f"Non 'Co-authored-by:' or 'Signed-off-by:' string found following 1st 'Signed-off-by:'"
        ... )
        >>> vio4 == [RuleViolation("UC2", vio_msg4, None, 5)]
        True
        >>> msg5 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Co-authored-by: name <email@domain>"
        ... )
        >>> commit5 = BaseTestCase.gitcommit(msg5)
        >>> vio5 = ends_signed.validate(commit5)
        >>> vio_msg5 = (
        ... f"Missing 'Signed-off-by:' following 'Co-authored-by:'"
        ... )
        >>> vio5 == [RuleViolation("UC2", vio_msg5, None, 2)]
        True
        >>> msg6 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Co-authored-by: name <email@domain>\n\n"
        ... f"Signed-off-by: different name <email@domain>"
        ... )
        >>> commit6 = BaseTestCase.gitcommit(msg6)
        >>> vio6 = ends_signed.validate(commit6)
        >>> vio_msg6 = (
        ... f"'Co-authored-by:' and 'Signed-off-by:' name/email do not match"
        ... )
        >>> vio6 == [RuleViolation("UC2", vio_msg6, None, 6)]
        True
        """

        violations = []

        # Utilities
        def vln(stmt, i):
            return RuleViolation(self.id, stmt, None, i)

        co_auth = "Co-authored-by:"
        sig = "Signed-off-by:"

        message_iter = enumerate(commit.message.original.split("\n"))

        # Skip ahead to the first signoff or co-author tag

        # Checks commit message contains a `Signed-off-by` string
        for i, line in message_iter:
            if line.startswith(sig) or line.startswith(co_auth):
                break
        else:
            # No signature was found in the message (before `message_iter` ended)
            # This check here can have false-negatives (e.g. if the body ends with only
            # a 'Co-authored-by' tag), but then below will realize that the co-authored-by
            # tag isnt followed by a Signed-off-by tag and fail (and also the DCO check will
            # complain).
            violations.append(vln(f"'{sig}' not found in commit message body", None))

        # Check that from here on out we only have signatures and co-authors, and that
        # every co-author is immediately followed by a signature with the same name/email.
        for i, line in message_iter:
            if line.startswith(co_auth):
                try:
                    _, next_line = next(message_iter)
                except StopIteration:
                    violations.append(
                        vln(f"Missing '{sig}' tag following '{co_auth}'", i)
                    )
                else:
                    if not next_line.startswith(sig):
                        violations.append(
                            vln(f"Missing '{sig}' tag following '{co_auth}'", i + 1)
                        )
                        continue

                    if next_line.split(":")[1].strip() != line.split(":")[1].strip():
                        violations.append(
                            vln(f"{co_auth} and {sig} name/email do not match", i + 1)
                        )
                continue

            if line.startswith(sig) or not line.strip():
                continue

            violations.append(
                vln(
                    f"Non '{co_auth}' or '{sig}' string found following 1st '{sig}'",
                    i,
                )
            )

        # Return errors
        return violations
