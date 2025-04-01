#!/bin/bash
# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# # SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

AMZN_DRIVER_VERSION="2.13.3"
KERNEL_VERSION=$1
DKMS_CONF_LOCATION=$2
START_DIR=$(pwd)

cd /tmp/

git clone --depth=1 https://github.com/amzn/amzn-drivers.git
mv amzn-drivers /usr/src/amzn-drivers-${AMZN_DRIVER_VERSION}

cp $DKMS_CONF_LOCATION /usr/src/amzn-drivers-${AMZN_DRIVER_VERSION}

dkms add -m amzn-drivers -v ${AMZN_DRIVER_VERSION}
dkms build -k ${KERNEL_VERSION} -m amzn-drivers -v ${AMZN_DRIVER_VERSION}
dkms install -k ${KERNEL_VERSION} -m amzn-drivers -v ${AMZN_DRIVER_VERSION}

cd $START_DIR
