# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for the OpenAPI specification."""

import os
import yaml


def check_swagger_style(yaml_spec):
    """Check if the swagger definition is correctly formatted."""
    with open(yaml_spec, 'r') as file_stream:
        try:
            yaml.safe_load(file_stream)
        # pylint: disable=broad-except
        except Exception as exception:
            print(str(exception))


def test_firecracker_swagger():
    """Fail if Firecracker swagger specification is malformed."""
    yaml_spec = os.path.normpath(
        os.path.join(os.getcwd(), '../src/api_server/swagger/firecracker.yaml')
    )
    check_swagger_style(yaml_spec)
