# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The user defined rules for gitlint."""

import re

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

        >>> from gitlint.git import GitContext
        >>> from gitlint.rules import RuleViolation
        ...
        >>> ends_signed = EndsSigned()
        >>> miss_sob_follows_coab = "Missing 'Signed-off-by' following 'Co-authored-by'"
        >>> miss_sob = "'Signed-off-by' not found in commit message body"
        >>> non_sign = "Non 'Co-authored-by' or 'Signed-off-by' string found following 1st 'Signed-off-by'"
        >>> email_no_match = "'Co-authored-by' and 'Signed-off-by' name/email do not match"
        ...
        >>> msg1 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Signed-off-by: name <email@domain>"
        ... )
        >>> commit1 = GitContext.from_commit_msg(msg1).commits[0]
        >>> ends_signed.validate(commit1)
        []
        >>> msg2 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Co-authored-by: name <email>\n\n"
        ... f"Signed-off-by: name <email>"
        ... )
        >>> commit2 = GitContext.from_commit_msg(msg2).commits[0]
        >>> ends_signed.validate(commit2)
        []
        >>> msg3 = f"Title\n\nMessage.\n\n"
        >>> commit3 = GitContext.from_commit_msg(msg3).commits[0]
        >>> vio3 = ends_signed.validate(commit3)
        >>> vio3 == [RuleViolation("UC2", miss_sob)]
        True
        >>> msg4 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Signed-off-by: name <email@domain>\n\na sentence"
        ... )
        >>> commit4 = GitContext.from_commit_msg(msg4).commits[0]
        >>> vio4 = ends_signed.validate(commit4)
        >>> vio4 == [RuleViolation("UC2", non_sign, None, 6)]
        True
        >>> msg5 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Co-authored-by: name <email@domain>"
        ... )
        >>> commit5 = GitContext.from_commit_msg(msg5).commits[0]
        >>> vio5 = ends_signed.validate(commit5)
        >>> vio5 == [
        ...   RuleViolation("UC2", miss_sob, None, None),
        ...   RuleViolation("UC2", miss_sob_follows_coab, None, 5)
        ... ]
        True
        >>> msg6 = (
        ... f"Title\n\nMessage.\n\n"
        ... f"Co-authored-by: name <email@domain>\n\n"
        ... f"Signed-off-by: different name <email@domain>"
        ... )
        >>> commit6 = GitContext.from_commit_msg(msg6).commits[0]
        >>> vio6 = ends_signed.validate(commit6)
        >>> vio6 == [RuleViolation("UC2", email_no_match, None, 6)]
        True
        """

        violations = []

        # Utilities
        def vln(stmt, i):
            violations.append(RuleViolation(self.id, stmt, None, i))

        coab = "Co-authored-by"
        sob = "Signed-off-by"

        # find trailers
        trailers = []
        for i, line in enumerate(commit.message.original.splitlines()):
            # ignore empty lines
            if not line:
                continue
            match = re.match(r"([\w-]+):\s+(.*)", line)
            if match:
                key, val = match.groups()
                trailers.append((i, key, val))
            else:
                trailers.append((i, "line", line))
        # artificial line so we can check any "previous line" rules
        trailers.append((trailers[-1][0] + 1, None, None))

        # Checks commit message contains a `Signed-off-by` string
        if not [x for x in trailers if x[1] == sob]:
            vln(f"'{sob}' not found in commit message body", None)

        prev_trailer, prev_value = None, None
        sig_trailers = False
        for i, trailer, value in trailers:
            if trailer in {sob, coab}:
                sig_trailers = True
            elif trailer not in {sob, coab, None} and sig_trailers:
                vln(
                    f"Non '{coab}' or '{sob}' string found following 1st '{sob}'",
                    i,
                )
            # Every co-author is immediately followed by a signature
            if prev_trailer == coab:
                if trailer != sob:
                    vln(f"Missing '{sob}' following '{coab}'", i)
                else:
                    # with the same name/email.
                    if value != prev_value:
                        vln(f"'{coab}' and '{sob}' name/email do not match", i)

            prev_trailer, prev_value = trailer, value

        # Return errors
        return violations
