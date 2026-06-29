#!/bin/bash
# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Proxy script that handles chunked pipeline upload.
# Usage: .buildkite/pipeline_pr.py --max-jobs 500 | .buildkite/pipeline_upload.sh
#
# If the input is a JSON array (chunked), uploads each element separately.
# If it's a single object, uploads it directly (backwards compatible).

set -euo pipefail

pipeline_json=$(cat)

if echo "$pipeline_json" | jq -e 'type == "array"' > /dev/null 2>&1; then
    count=$(echo "$pipeline_json" | jq 'length')
    for ((i = 0; i < count; i++)); do
        echo "$pipeline_json" | jq ".[$i]" | buildkite-agent pipeline upload
    done
else
    echo "$pipeline_json" | buildkite-agent pipeline upload
fi
