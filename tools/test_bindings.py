# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Script used to check if bindgen-generated code creates structs that differ from previously created
onces.

The script uses `pahole` (man 1 pahole) to gather debug information from two firecracker binaries
(script's arguments). It parses pahole output and gathers struct information in a dictionary of the
form:

```
{
    "struct_name": {"size": size_in_bytes, "alignment": alignment_in_bytes},
    ...
}
```

It also, filters structure names using the "bindings" filter for keeping only bindgen related
structs.

*NOTE*: this assumes that all bindgen-related structs live under a crate or module name with
"bindings" in it. At the moment, this is true.

It then iterates through the structs of the firecracker binary built from the older version and
checks if there are mismatches with the struct info from the second binary (newer version)

### Usage

1. Create the two binaries

```
# First create the binary with existing bindings
$ git checkout main
$ ./tools/devtool build
$ cp ./build/cargo_target/x86_64-unknown-linux-musl/debug/firecracker firecracker_old

# Second create the binary with new bindings
$ git checkout new_bindings
$ ./tools/devtool build
$ cp ./build/cargo_target/x86_64-unknown-linux-musl/debug/firecracker firecracker_new

# Run the script
$ python3 ./tools/test_bindings.py firecracker_old firecracker_new
```
"""

import argparse
import logging
import re
import subprocess
import sys

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


def parse_pahole(pahole_output):
    """Gather bindings related structs from pahole output

    Parse pahole output and gather struct information filtering for the 'bindings' keyword.
    The information gathered is the struct size and its alignment.

    @param fname: File including pahole output
    @return: A dictionary where keys are struct names and values struct size and alignment
    """
    ret = {}

    # regular expression matches the name of the struct, its size and alignment
    structs = re.findall(
        rb"struct (.*?)\{.*?/\* size: (\d+).*?\*/.*?\n\} "
        rb"__attribute__\(\(__aligned__\((\d+)\)\)\)\;",
        pahole_output,
        flags=re.DOTALL,
    )

    for struct in structs:
        struct_name = str(struct[0])
        size = int(struct[1])
        alignment = int(struct[2])

        if "bindings" in struct_name:
            ret[struct_name] = {"size": size, "alignment": alignment}

    return ret


def pahole(binary: str) -> str:
    """Runs pahole on a binary and returns its output as a str

    If pahole fails this will raise a `CalledProcessError`

    @param binary: binary to run pahole on
    @return: On success, it will return the stdout of the pahole process
    """
    result = subprocess.run(
        ["pahole", binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
    )
    return result.stdout


def check_pahole_mismatches(old: str, new: str) -> bool:
    """Checks for pahole mismatches in pahole information between two binaries

    @param old: old Firecracker binary
    @param new: new Firecracker binary
    @return: false if no mismatches found, true otherwise
    """
    pahole_structs_1 = parse_pahole(pahole(old))
    pahole_structs_2 = parse_pahole(pahole(new))

    # We go through all the structs existing in the old firecracker binary and check for mismatches
    # in the new one.
    for name, prop_1 in pahole_structs_1.items():
        # Note that the reverse, i.e. a name existing in the new binary but not in the old binary,
        # is not a problem. That would mean we are making use of some new struct from
        # bindgen-generated code. That does not break ABI compatibility.
        if name not in pahole_structs_2:
            log.warning("struct '%s' does not exist in new binary", name)
            continue

        prop_2 = pahole_structs_2[name]
        # Size mismatches are hard errors
        if prop_1["size"] != prop_2["size"]:
            log.error("size of '%s' does not match in two binaries", name)
            log.error("old: %s", prop_1["size"])
            log.error("new: %s", prop_2["size"])
            return True

        # Alignment mismatches just cause warnings
        if prop_1["alignment"] != prop_2["alignment"]:
            log.warning("alignment of '%s' does not match in two binaries", name)
            log.warning("old: %s", prop_1["alignment"])
            log.warning("new: %s", prop_2["alignment"])
        else:
            log.info("struct '%s' matches", name)

    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check bindings ABI compatibility for Firecracker"
    )
    parser.add_argument(
        "firecracker_old",
        type=str,
        metavar="old-firecracker-binary",
        help="Firecracker binary with old bindings",
    )
    parser.add_argument(
        "firecracker_new",
        type=str,
        metavar="new-firecracker-binary",
        help="Firecracker binary with new bindings",
    )
    args = parser.parse_args()

    if check_pahole_mismatches(args.firecracker_old, args.firecracker_new):
        log.error("Structure layout mismatch")
        sys.exit(1)
    else:
        log.info("Structure layout matches")

    sys.exit(0)
