# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A simple IMDSv2 client

- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html

Important! For this client to work in a container scenario, make sure your
instances are set with an adequate hop limit (2 for example). See
`ec2:MetadataHttpPutResponseHopLimit`
"""


import time

import requests

IMDSV2_HDR_TOKEN_TTL = "X-aws-ec2-metadata-token-ttl-seconds"
IMDSV2_HDR_TOKEN = "X-aws-ec2-metadata-token"


class IMDSv2Client:
    """
    A simple IMDSv2 client.

    >>> IMDSv2Client().get("/meta-data/instance-type")     # doctest: +SKIP
    ...
    """

    def __init__(self, endpoint="http://169.254.169.254", version="latest"):
        self.endpoint = endpoint
        self.version = version
        self.ttl = 21600
        self.token_expiry_time = 0
        self.token = None

    def get_token(self):
        """Get a token from IMDSv2"""
        if self.token_expiry_time < time.time():
            headers = {IMDSV2_HDR_TOKEN_TTL: str(self.ttl)}
            # To get a token, docs say to always use latest
            url = f"{self.endpoint}/latest/api/token"
            res = requests.put(url, headers=headers, timeout=2)
            self.token = res.content
            self.token_expiry_time = time.time() + self.ttl
        return self.token

    def get(self, path):
        """
        Get a metadata path from IMDSv2

        >>> IMDSv2Client().get("/meta-data/instance-type") # doctest: +SKIP
        'm5d.metal'
        """
        headers = {IMDSV2_HDR_TOKEN: self.get_token()}
        url = f"{self.endpoint}/{self.version}{path}"
        res = requests.get(url, headers=headers, timeout=2)
        if res.status_code != 200:
            raise Exception(f"IMDSv2 returned {res.status_code} for {url}")
        return res.text


IMDS_V2 = IMDSv2Client()
imdsv2_get = IMDS_V2.get
