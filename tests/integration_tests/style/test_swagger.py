# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for the OpenAPI specification."""

import os
import yaml
import framework.utils as utils


def check_yaml_style(yaml_spec):
    """Check if the swagger definition is correctly formatted."""
    with open(yaml_spec, 'r') as file_stream:
        try:
            yaml.safe_load(file_stream)
        # pylint: disable=broad-except
        except Exception as exception:
            print(str(exception))


def validate_swagger(swagger_spec):
    """Fail if OpenApi spec is not followed."""
    validate_cmd = 'swagger-cli validate {}'.format(swagger_spec)
    retcode, stdout, _ = utils.run_cmd(validate_cmd)

    # Verify validity.
    assert "is valid" in stdout
    assert retcode == 0


def test_firecracker_swagger():
    """
    Test that Firecracker swagger specification is valid.

    @type: style
    """
    swagger_spec = os.path.normpath(
        os.path.join(os.getcwd(), '../src/api_server/swagger/firecracker.yaml')
    )
    check_yaml_style(swagger_spec)
    validate_swagger(swagger_spec)
