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


@keyword("Start SSL Server")
def start_ssl_server(  # noqa: D417 Missing argument descriptions in the docstring
    server_cert: str,
    server_key: str,
    client_ca: str,
    host: str = "0.0.0.0",
    port: Union[str, int] = 8443,
    timeout: Union[str, int] = 20,
    password: Optional[str] = None,
) -> Optional[bytes]:
    """Start a TLS server that listens for incoming connections and processes data.

    Arguments:
    ---------
       - `server_cert`: Path to the server's certificate file.
       - `server_key`: Path to the server's private key file.
       - `client_ca`: Path to the CA certificate file used to validate the client's certificate.
       - `host`: Host address to bind the server to. Defaults to "127.0.0.0".
       - `port`: Port number to bind the server to. Defaults to 8443.
       - `timeout`: Timeout duration in seconds. Defaults to `20` seconds.
       - `password`: Password for the server's private key file. Defaults to None.

    Returns:
    -------
        - The received data as a byte string.

    Raises:
    ------
        - `SSLError`: If an SSL error occurs.
        - `timeout`: If the connection times out.

    Examples:
    --------
    | ${data}= | Start SSL Server | server_cert=server.crt | server_key=server.key | client_ca=client_ca.crt |
    | ${data}= | Start SSL Server | server_cert=server.crt | server_key=server.key | client_ca=client_ca.crt \
    | host=0.0.0.0 | port=8443 | timeout=60 |

    """
    timeout = int(timeout)
    port = int(port)

    # Create an SSL context with client authentication
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=server_cert, keyfile=server_key, password=password)
    context.load_verify_locations(cafile=client_ca)

    received_data = bytearray()
    # Create a TCP/IP socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
            sock.listen(1)
            print(f"Listening on {host}:{port}")

            # Accept a client connection
            with context.wrap_socket(sock, server_side=True) as secure_sock:
                conn, addr = secure_sock.accept()
                logging.debug("Accepted connection from  %s", str(addr))
                conn.settimeout(timeout)

                try:
                    # Continuously receive data until the client closes the connection or timeout occurs
                    while True:
                        data = conn.recv(buflen=1024)
                        if not data:
                            logging.info("Client closed the connection.")
                            break
                        received_data.extend(data)
                        logging.debug("Received %s bytes", str(len(data)))
                except socket.timeout:
                    logging.warning("Connection timed out.")
                except ssl.SSLError as e:
                    logging.warning("SSL error: %s", str(e))
                finally:
                    conn.close()
                    logging.info("Connection closed.")

                return bytes(received_data)
    except KeyboardInterrupt:
        logging.info("Server stopped by user.")
        return None


