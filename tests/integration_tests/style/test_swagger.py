# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests ensuring codebase style compliance for the OpenAPI specification."""

from pathlib import Path

import yaml
from openapi_spec_validator import validate_spec
from openapi_spec_validator.readers import read_from_filename


def check_yaml_style(yaml_spec):
    """Check if the swagger definition is correctly formatted."""
    with open(yaml_spec, "r", encoding="utf-8") as file_stream:
        try:
            yaml.safe_load(file_stream)
        # pylint: disable=broad-except
        except Exception as exception:
            print(str(exception))


def validate_swagger(swagger_spec):
    """Fail if OpenAPI spec is not followed."""
    spec_dict, _ = read_from_filename(swagger_spec)
    validate_spec(spec_dict)


def test_firecracker_swagger():
    """
    Test that Firecracker swagger specification is valid.

    @type: style
    """
    swagger_spec = Path("../src/api_server/swagger/firecracker.yaml")
    check_yaml_style(swagger_spec)
    validate_swagger(swagger_spec)
