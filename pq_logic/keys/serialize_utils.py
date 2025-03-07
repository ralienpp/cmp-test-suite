# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for serializing keys."""

import base64
import textwrap


def prepare_enc_key_pem(password: str, one_asym_key: bytes, key_name: bytes) -> bytes:
    """Prepare PEM formatted encrypted key.

    :param password: Password for encryption.
    :param one_asym_key: Key to encrypt.
    :param key_name: Name of the key.
    :return: PEM formatted encrypted key.
    """
    from pq_logic.keys.key_pyasn1_utils import derive_and_encrypt_key

    enc_data, iv = derive_and_encrypt_key(password=password, data=one_asym_key, decrypt=False)

    pem_lines = []
    pem_lines.append(b"-----BEGIN " + key_name + b" PRIVATE KEY-----")
    pem_lines.append(b"Proc-Type: 4,ENCRYPTED")
    pem_lines.append(b"DEK-Info: AES-256-CBC," + iv.hex().upper().encode("ascii"))
    pem_lines.append(b"")

    b64 = base64.b64encode(enc_data).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(b64, width=64))

    pem_lines.extend(line.encode("ascii") for line in wrapped.split("\n"))
    pem_lines.append(b"-----END " + key_name + b" PRIVATE KEY-----")
    pem_lines.append(b"")

    return b"\n".join(pem_lines)
