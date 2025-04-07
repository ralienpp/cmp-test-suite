# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Generate cryptographic keys using the `cryptography` library."""

import logging
from typing import Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc4211, rfc5958, rfc6664, rfc9481
from resources.exceptions import BadAlg, BadAsn1Data
from resources.oid_mapping import get_curve_instance, may_return_oid_to_name
from resources.typingutils import PrivateKey
from robot.api.deco import not_keyword


@not_keyword
def generate_ec_key(algorithm: str, curve: Optional[str] = None) -> PrivateKey:
    """Generate a private key for a specified elliptic curve algorithm and curve.

    This function generates a private key for Ed25519, Ed448, X25519, and X448.

    :param algorithm: The name of the elliptic curve algorithm. Supported values are:
                      - "ed25519" for Ed25519PrivateKey
                      - "ed448" for Ed448PrivateKey
                      - "x25519" for X25519PrivateKey
                      - "x448" for X448PrivateKey
    :param curve: the name of the elliptic curve.
    :return: A generated private key object corresponding to the specified algorithm.
    :raises ValueError: If the provided algorithm is not supported.
    """
    if algorithm in ["ecdh", "ecdsa", "ecc", "ec"]:
        if curve is None:
            curve = "secp256r1"
        curve_instance = get_curve_instance(curve_name=curve)
        return ec.generate_private_key(curve=curve_instance)

    if algorithm == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()

    if algorithm == "ed448":
        return ed448.Ed448PrivateKey.generate()

    if algorithm == "x25519":
        return x25519.X25519PrivateKey.generate()

    if algorithm == "x448":
        return x448.X448PrivateKey.generate()

    raise ValueError(f"Unsupported ecc algorithm: {algorithm}")


def _generate_dh_private_key(
    p: Optional[int] = None, g: int = 2, secret_scalar: Optional[int] = None, length: int = 2048
) -> dh.DHPrivateKey:
    """Generate a Diffie-Hellman (DH) private key using the provided parameters.

    :param p: The prime modulus for the DH parameters. If not provided, a new prime modulus
              will be generated based on the specified `length`.
    :param g: The generator for the DH parameters. Defaults to 2.
    :param secret_scalar: The secret scalar value to use for key generation. If not provided,
                          a new secret scalar will be generated.
    :param length: The length of the key in bits if `p` is not provided. Default to 2048.
    :return: The generated DH private key.
    :raises ValueError: If the `secret_scalar` parameter is provided, but not `p`.
    """
    if p is None:
        parameters = dh.generate_parameters(generator=g, key_size=length)
    else:
        parameters = dh.DHParameterNumbers(p, g).parameters()

    if secret_scalar is not None:
        if p is None:
            raise ValueError("Parameter `p` must be provided when using a `secret_scalar`.")
        public_number = pow(g, secret_scalar, p)
        private_key = dh.DHPrivateNumbers(
            x=secret_scalar, public_numbers=dh.DHPublicNumbers(public_number, parameters.parameter_numbers())
        ).private_key()
    else:
        private_key = parameters.generate_private_key()

    return private_key


@not_keyword
def generate_trad_key(algorithm="rsa", **params) -> PrivateKey:  # noqa: D417 for RF docs
    """Generate a `cryptography` key based on the specified algorithm.

    This function supports generating keys for various cryptographic algorithms including RSA, DSA, ECDSA, ECDH,
    Ed25519, and DH. Depending on the selected algorithm, additional parameters can be provided.

    Arguments:
    ---------
        - `algorithm`: The cryptographic algorithm to use for key generation.
        - `**params`: Additional parameters specific to the algorithm.

    Supported algorithms:
    ---------------------
        - "rsa": RSA (default).
        - "dsa": DSA.
        - "ecdsa" or "ecdh": Elliptic Curve.
        - "ed25519": Ed25519.
        - "dh": Diffie-Hellman.
        - "bad_rsa_key": RSA with a bit size of 512.

    Additional Parameters:
    ----------------------
        - For "rsa" and "dsa":
            - length (int, str): The length of the key to generate, in bits. Default is 2048.
        - For "ecdsa" or "ecdh":
            - curve (str): Curve name, see `cryptography.hazmat.primitives.asymmetric.ec`. Default is `secp256r1`.
        - For "dh":
            - g (int): The generator for DH key generation. Default is 2.
            - secret_scalar (str, int): the private key value for DH key generation. If not provided, one is generated.
            - length (int, str): The length of the modulus to generate if `p` is not provided. Default is 2048.


    Returns:
    -------
        - The generated private key.

    Raises:
    ------
        - `ValueError` if the specified algorithm is not supported or if invalid parameters are provided.

    Examples:
    --------
    | ${private_key}= | Generate Key | algorithm=rsa | length=2048 |
    | ${private_key}= | Generate Key | algorithm=dh | length=2048 |
    | ${private_key}= | Generate Key | algorithm=ecdsa | curve=secp384r1 |

    """
    algorithm = algorithm.lower()

    if algorithm == "bad-rsa-key":
        from cryptography.hazmat.bindings._rust import (  # pylint: disable=import-outside-toplevel
            openssl as rust_openssl,
        )

        private_key = rust_openssl.rsa.generate_private_key(65537, 512)  # type: ignore

    elif algorithm == "rsa":
        length = int(params.get("length") or 2048)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=length)

    elif algorithm == "dsa":
        length = int(params.get("length", 2048))
        private_key = dsa.generate_private_key(key_size=length)

    elif algorithm in {"ed25519", "ed448", "x25519", "x448", "ecdh", "ecdsa", "ecc", "ec"}:
        curve = params.get("curve", "secp256r1")
        private_key = generate_ec_key(algorithm, curve)

    elif algorithm == "dh":
        private_key = _generate_dh_private_key(
            p=params.get("p"),
            g=params.get("g", 2),
            secret_scalar=params.get("secret_scalar"),
            length=int(params.get("length", 2048)),
        )

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return private_key


@not_keyword
def parse_trad_key_from_one_asym_key(
    one_asym_key: Union[rfc5958.OneAsymmetricKey, bytes, rfc4211.PrivateKeyInfo],  # type: ignore
    must_be_version_2: bool = True,
):
    """Parse a traditional key from a single asymmetric key.

    :param one_asym_key: The OneAsymmetricKey object or its DER-encoded bytes.
    :param must_be_version_2: If True, the key must be a version 2 key.
    :return: The parsed private key.
    :raises BadAsn1Data: If the provided data is not a OneAsymmetricKey object.
    :raises ValueError: If the key is not a version 2 key.
    """
    if isinstance(one_asym_key, bytes):
        one_asym_key, rest = decoder.decode(one_asym_key, rfc5958.OneAsymmetricKey())  # type: ignore
        one_asym_key: rfc5958.OneAsymmetricKey
        if rest:
            raise BadAsn1Data("OneAsymmetricKey")

    version = int(one_asym_key["version"])
    private_key_bytes = one_asym_key["privateKey"].asOctets()
    if version != 1 and must_be_version_2:
        raise ValueError("The provided key is not a version 2 key.")

    public_key_bytes = one_asym_key["publicKey"].asOctets() if one_asym_key["publicKey"].isValue else None

    oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]

    # the `cryptography` library does not support v2.
    tmp = rfc4211.PrivateKeyInfo()
    tmp["privateKeyAlgorithm"]["algorithm"] = oid
    tmp["privateKeyAlgorithm"]["parameters"] = one_asym_key["privateKeyAlgorithm"]["parameters"]
    tmp["privateKey"] = one_asym_key["privateKey"]
    tmp["version"] = 0

    private_info = encoder.encode(tmp)
    if public_key_bytes is None:
        return serialization.load_der_private_key(private_info, password=None)

    private_len = len(private_key_bytes)
    pub_len = len(public_key_bytes)

    logging.info("The Private Key size is: %d bytes", private_len)
    logging.info("The Public Key size is: %d bytes", pub_len)

    private_key = serialization.load_der_private_key(private_info, password=None)

    if oid == rfc9481.id_Ed25519:
        # is saved as decoded OctetString, is done by the `cryprography` library.
        # maybe verify if this is correct.
        private_key = serialization.load_der_private_key(private_info, password=None)
        # key_bytes = decoder.decode(private_key_bytes, univ.OctetString())[0].asOctets()
        # private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

    elif oid in [rfc9481.rsaEncryption]:
        # As per section 2 in RFC 5958: "Earlier versions of this
        # specification [RFC5208] did not specify a particular encoding rule
        # set, but generators SHOULD use DER [X.690] and receivers MUST support
        # BER [X.690], which also includes DER [X.690]".
        private_key = serialization.load_der_private_key(private_info, password=None)
        public_key = serialization.load_der_public_key(public_key_bytes)

    elif oid == rfc6664.id_ecPublicKey:
        private_key = serialization.load_der_private_key(private_info, password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("The private key is not an Elliptic Curve private key.")
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(data=public_key_bytes, curve=private_key.curve)

    elif oid == rfc9481.id_X25519:
        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)

    elif oid == rfc9481.id_X448:
        public_key = x448.X448PublicKey.from_public_bytes(public_key_bytes)

    elif oid == rfc9481.id_Ed448:
        public_key = ed448.Ed448PublicKey.from_public_bytes(public_key_bytes)

    else:
        _name = may_return_oid_to_name(oid)
        raise BadAlg(f"Can not load the traditional key for the algorithm: {_name}")

    if private_key.public_key() != public_key:
        raise ValueError("The public key does not match the private key.")

    return private_key
