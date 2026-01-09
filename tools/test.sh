#!/bin/bash

# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

TOOLS_DIR=$(dirname $0)
source "$TOOLS_DIR/functions"

# Set our TMPDIR inside /srv, so all files created in the session end up in one
# place
say "Create TMPDIR in /srv"
export TMPDIR=/srv/tmp
mkdir -pv $TMPDIR

# Some of the security tests need this (test_jail.py)
# Convert the Docker created cgroup so we can create cgroup children
# From https://github.com/containerd/containerd/issues/6659
say "cgroups v2: enable nesting"
CGROUP=/sys/fs/cgroup
if [ -f $CGROUP/cgroup.controllers -a -e $CGROUP/cgroup.type ]; then
    # move the processes from the root group to the /init group,
    # otherwise writing subtree_control fails with EBUSY.
    # An error during moving non-existent process (i.e., "cat") is ignored.
    mkdir -p $CGROUP/init
    xargs -rn1 < $CGROUP/cgroup.procs > $CGROUP/init/cgroup.procs || :
    # enable controllers
    sed -e 's/ / +/g' -e 's/^/+/' < $CGROUP/cgroup.controllers \
        > $CGROUP/cgroup.subtree_control
fi

if [ -f build/current_artifacts ]; then
  say "Copy artifacts to /srv/test_artifacts, so hardlinks work"
  cp -ruvfL $(cat build/current_artifacts) /srv/test_artifacts
else
  # The directory must exist for pytest to function
  mkdir -p /srv/test_artifacts
  say_warn "No current artifacts are set. Some tests might break"
fi

cd tests
export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-} --pdbcls=IPython.terminal.debugger:TerminalPdb"

{
    # disable errexit momentarily so we can capture the exit status
    set +e
    pytest "$@"
    ret=$?
    set -e
}

# if the tests failed and we are running in CI, print some disk usage stats
# to help troubleshooting
if [ $ret != 0 ] && [ "$BUILDKITE" == "true" ]; then
    df -ih
    df -h
    du -h / 2>/dev/null |sort -h |tail -32
fi

exit $ret
