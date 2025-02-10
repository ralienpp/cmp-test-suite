# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility for handling HTTP responses."""

import sys

# only needed if the script is called to check how a request is handled.
# python ./resources/httputils.py
sys.path.append(".")
import logging
import os
import socket
import ssl
from typing import Optional, Union

import requests
from pyasn1.error import PyAsn1Error
from robot.api.deco import keyword, not_keyword

from resources import cmputils


def http_response_contains_pki_message(data: requests.Response) -> bool:  # noqa: D417 for RF docs
    """Check if a server returned a `rfc9480.PKIMessage` on failure.

    The server might respond with an error status code, and in such cases,
    this function attempts to parse the response as a `rfc9480.PKIMessage`.
    If the server response is empty or parsing of the `pyasn1` `PKIMessage`
    structure fails, the function returns `False`.

    Arguments:
    ---------
    - data: The Response object to parse.

    Returns:
    -------
    - True if the response contains a valid PKIMessage.
    - False if the response is empty or parsing fails.

    """
    if not data.content:
        return False

    try:
        cmputils.parse_pkimessage(data.content)
        return True
    except PyAsn1Error:
        return False


# Currently, has the Robot Framework, not this flexibility.


@keyword(name="Add URL Suffix")
def add_url_suffix(  # noqa: D417 Missing argument descriptions in the docstring
    url: str, suffix: Optional[str]
) -> str:
    """Add a suffix to a URL if it is not empty.

    Arguments:
        - url: The URL to append the suffix to.
        - suffix: The suffix to append to the URL.

    Returns:
    -------
        - The URL with the suffix appended.

    """
    if not suffix:
        return url

    return os.path.join(url, suffix)


