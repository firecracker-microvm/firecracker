"""Tests ensuring codebase style compliance for Markdown files."""
import os
import framework.utils as utils


def _validate_markdown(filename):
    if filename.endswith(('.md')):
        with open(filename) as file:
            for line in file:
                #check line length
                if len(line) >= 80:
                    print("length of the line too long ", line) 
                    return False
                #check trailing whitespace or tab
                if line.endswith(' ') or line.endswith('\t'):
                    print("trailing white space ", line)
                    return False
                #check hard tab
                if '\t' in line:
                    print("hard tab ", line)
                    return False
    return True

def test_markdown_style():
    """Fail if a file violates markdown style."""
    for subdir, _, files in os.walk(os.getcwd()):
        for file in files:
            filepath = os.path.join(subdir, file)
            assert _validate_markdown(filepath) is True, "%s has invalid markdown" % filepath
