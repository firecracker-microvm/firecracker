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

say "Copy CI artifacts to /srv, so hardlinks work"
cp -ruvf build/img /srv

cd tests
pytest "$@"
exit $?
