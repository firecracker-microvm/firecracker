# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for Markdown files."""
import os
import framework.utils as utils


def _validate_markdown(filename):
    errors = []
    linenum = 0;
    with open(filename, 'r+', encoding='utf-8') as file:
        for line in file:
            #check line length
            if len(line) > 80:
                errors.append("length of the line too long: line number " + str(linenum))
            #check trailing whitespace or tab
            if line.endswith(' ') or line.endswith('\t'):
                errors.append("trailing white space: line number "+ str(linenum))
            #check hard tab
            if '\t' in line:
                errors.append("hard tab: line number "+ str(linenum))
            linenum += 1
    return '\n'.join(errors)

def test_markdown_style():
    """Fail if a file violates markdown style."""
    errors = {}
    # Get all *.py files from the project
    markdown_files = utils.get_files_from(
        find_path="..",
        pattern="*.md",
        exclude_names=["build"])

    for filepath in markdown_files:
        print(filepath)
        res = _validate_markdown(filepath)
        if len(res) > 0:
            errors.update({filepath:res})
            #print(filepath + " has invalid markdown\n" + res)
    for file in errors:
        print(file + "\n " + errors[file])
    print(str(len(errors)) + " files have markdown errors")
    assert len(errors) == 0 