# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains utility functions for validating PQ keys and certificates."""

import logging

from pyasn1_alt_modules import rfc9480
from resources import asn1utils, certextractutils
from resources.certutils import load_public_key_from_cert
from resources.exceptions import UnknownOID
from resources.oidutils import HYBRID_NAME_2_OID, HYBRID_OID_2_NAME, PQ_NAME_2_OID, PQ_OID_2_NAME
from robot.api.deco import keyword

from pq_logic.keys.abstract_composite import AbstractCompositeSigPublicKey
from pq_logic.keys.abstract_pq import PQPublicKey, PQSignaturePublicKey
from pq_logic.pq_utils import is_kem_public_key

# https://www.ietf.org/archive/id/draft-ietf-lamps-kyber-certificates-06.txt
# section 3:
# When any of the ML-KEM AlgorithmIdentifier appears in the
# SubjectPublicKeyInfo field of an X.509 certificate, the key usage
# certificate extension MUST only contain `keyEncipherment`.


@keyword(name="Validate Migration Alg ID")
def validate_migration_alg_id(  # noqa: D417 Missing argument descriptions in the docstring
    alg_id: rfc9480.AlgorithmIdentifier,
) -> None:
    """Validate a post-quantum or hybrid algorithm identifier.

    Arguments:
    ---------
        - `alg_id`: The `AlgorithmIdentifier` to validate.

    Raises:
    ------
        - `ValueError`: If the `parameters` field is not absent.

    Examples:
    --------
    | Validate Migration Alg ID | ${alg_id} |

    """
    if alg_id["algorithm"] not in PQ_OID_2_NAME:
        if alg_id["parameters"].isValue:
            name = PQ_OID_2_NAME.get(alg_id["algorithm"])
            name = name or PQ_OID_2_NAME.get(str(alg_id["algorithm"]))
            raise ValueError(
                f"The Post-Quantum algorithm identifier {name} does not `allow` the parameters"
                f" field to be set: {alg_id['parameters']}"
            )

    elif alg_id["algorithm"] in HYBRID_OID_2_NAME:
        if alg_id["parameters"].isValue:
            name = HYBRID_OID_2_NAME.get(alg_id["algorithm"])
            name = name or HYBRID_OID_2_NAME.get(str(alg_id["algorithm"]))
            raise ValueError(
                f"The Hybrid algorithm identifier {name} does not `allow` the parameters"
                f" field to be set: {alg_id['parameters']}"
            )
    else:
        raise UnknownOID(oid=alg_id["algorithm"])


@keyword(name="Validate Migration Certificate KeyUsage")
def validate_migration_certificate_key_usage(  # noqa: D417 Missing argument descriptions in the docstring
    cert: rfc9480.CMPCertificate,
) -> None:
    """Validate the key usage of a certificate with a PQ public key.

    Arguments:
    ---------
        - `cert`: The certificate to validate.

    Raises:
    ------
        - `ValueError`: If the key is a KEM or Hybrid-KEM -key and the key usage is not `keyEncipherment`.
        - `ValueError`: If the key is a PQ signature key and the key usage is not `digitalSignature`.

    Examples:
    --------
    | Validate Migration Certificate Key Usage | ${cert} |


    """
    public_key: PQPublicKey = load_public_key_from_cert(cert)  # type: ignore
    key_usage = certextractutils.get_field_from_certificate(cert, extension="key_usage")

    if key_usage is None:
        logging.info("Key usage extension was not present in the parsed certificate.")
        return

    key_usage = asn1utils.get_set_bitstring_names(key_usage).split(", ")  # type: ignore

    sig_usages = {"digitalSignature", "nonRepudiation", "keyCertSign", "cRLSign"}

    if isinstance(public_key, (PQSignaturePublicKey, AbstractCompositeSigPublicKey)):
        ml_dsa_disallowed = {"keyEncipherment", "dataEncipherment", "keyAgreement", "encipherOnly", "decipherOnly"}

        if not set(key_usage).issubset(sig_usages):
            raise ValueError(f"The post-quantum {public_key.name} keyUsage must be one of: {sig_usages}")
        if set(key_usage) & ml_dsa_disallowed:
            raise ValueError(f"ML-DSA keyUsage must not include: {ml_dsa_disallowed}")

    if is_kem_public_key(public_key):
        ml_kem_allowed = {"keyEncipherment"}
        if set(key_usage) != ml_kem_allowed:
            raise ValueError(f"ML-KEM keyUsage must only contain: {ml_kem_allowed}.But got {key_usage}")

    else:
        raise ValueError(f"Unsupported public key type: {type(public_key)}")


def validate_migration_oid_in_certificate(  # noqa: D417 Missing argument descriptions in the docstring
    cert: rfc9480.CMPCertificate, name: str
) -> None:
    """Validate the OID of the public key in the certificate.

    Arguments:
    ---------
        - `cert`: The certificate to validate.
        - `name`: The name of the public key algorithm.

    Raises:
    ------
        - `ValueError`: If the OID does not match the name.
        - `UnknownOID`: If the OID is unknown.
        - `ValueError`: If the name is not supported.

    """
    pub_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]

    name_oid = PQ_NAME_2_OID.get(name) or HYBRID_NAME_2_OID.get(name)
    if name_oid is None:
        raise ValueError(
            f"The name {name} is not supported."
            f" Supported names are: {list(PQ_NAME_2_OID.keys()) + list(HYBRID_NAME_2_OID.keys())}"
        )

    if PQ_NAME_2_OID.get(name) is not None:
        if str(pub_oid) != str(PQ_NAME_2_OID[name]):
            raise ValueError(f"The OID {pub_oid} does not match the name {name}.")

    elif HYBRID_NAME_2_OID.get(name) is not None:
        if str(pub_oid) != str(HYBRID_NAME_2_OID[name]):
            raise ValueError(f"The OID {pub_oid} does not match the name {name}.")
    else:
        raise UnknownOID(pub_oid)
