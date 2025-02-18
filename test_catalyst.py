# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


"""Try out all possible combinations of alternative signature data and verify the signature of a catalyst cert."""

import glob

from pq_logic.fips.fips204 import ML_DSA
from pq_logic.hybrid_sig.catalyst_logic import (
    extract_alt_signature_data,
    validate_catalyst_extensions,
)
from pq_logic.hybrid_sig.chameleon_logic import build_delta_cert_from_paired_cert
from pq_logic.keys.abstract_pq import PQPrivateKey, PQPublicKey
from pq_logic.keys.sig_keys import MLDSAPublicKey
from pyasn1_alt_modules import rfc9480
from resources.certutils import parse_certificate
from resources.exceptions import InvalidAltSignature
from resources.oid_mapping import KEY_CLASS_MAPPING, may_return_oid_to_name
from unit_tests.utils_for_test import get_subject_and_issuer, print_chain_subject_and_issuer


def get_chameleon_certs() -> list[str]:
    """Return a list of all chameleon certificates in the specified directory."""
    pem_files = []
    for file in glob.iglob("./data/pqc-certificates/providers/**", recursive=True):
        if file.endswith(".der") and "chameleon" in file:
            pem_files.append(file)

    if pem_files == []:
        raise FileNotFoundError("No chameleon certificates found in the specified directory.")
    return pem_files


def get_catalyst_certs() -> list[str]:
    """Return a list of all catalyst certificates in the specified directory."""
    pem_files = []
    for file in glob.iglob("./data/pqc-certificates/providers/**", recursive=True):
        if file.endswith(".der") and "catalyst" in file:
            pem_files.append(file)

    if pem_files == []:
        raise FileNotFoundError("No catalyst certificates found in the specified directory.")
    return pem_files


def get_key_name(key) -> str:
    """Return the name of the key."""
    if isinstance(key, (PQPublicKey, PQPrivateKey)):
        return key.key_name
    else:
        return str(KEY_CLASS_MAPPING.get(type(key).__name__, key))


def log_cert_infos(asn1cert: rfc9480.CMPCertificate):
    """Log the information of the certificate and return the extracted information.

    :param asn1cert: The certificate to be logged.
    :return: The public key, the name of the public key algorithm and the signature.
    """
    tmp = get_subject_and_issuer(asn1cert)
    tmp += "\nSignature algorithm: " + may_return_oid_to_name(asn1cert["tbsCertificate"]["signature"]["algorithm"])
    tmp += "\nPublic key algorithm: " + may_return_oid_to_name(
        asn1cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
    )
    tmp += "\nCatalyst Extension: \n"
    extension = validate_catalyst_extensions(asn1cert)
    tmp += "Catalyst AltPubKey: " + may_return_oid_to_name(extension["spki"]["algorithm"]["algorithm"])
    tmp += "\nCatalyst AltSigAlg: " + may_return_oid_to_name(extension["alg_id"]["algorithm"])

    pub_key = extension["spki"]["subjectPublicKey"].asOctets()

    name = may_return_oid_to_name(extension["spki"]["algorithm"]["algorithm"])
    # print(tmp)
    return pub_key, name, extension["signature"]


def _try2(asn1cert: rfc9480.CMPCertificate, pub_key: bytes, name: str, signature: bytes) -> bool:
    """Try all possible combinations of alternative signature data and verify the signature.

    :param asn1cert: The certificate to be verified.
    :param pub_key: The public key of the certificate.
    :param name: The name of the public key algorithm.
    :param signature: The signature to be verified.
    :return: Whether the verification was successful.
    """
    # verify the key size.
    MLDSAPublicKey.from_public_bytes(pub_key, name)
    data = extract_alt_signature_data(asn1cert["tbsCertificate"])
    out = ML_DSA(name).verify(pk=pub_key, m=data, sig=signature, ctx=b"")

    if not out:
        raise InvalidAltSignature("Verification failed for the alternative certificate.")

    print(f"The Catalyst certificate has been successfully verified with {name}.")


def test_catalyst():
    """Test the catalyst certificates."""
    pem_files = get_catalyst_certs()

    for pem_file in pem_files:
        with open(pem_file, "rb") as file:
            cert = parse_certificate(file.read())
            print_chain_subject_and_issuer([cert])
            pub_key, name, signature = log_cert_infos(cert)
            _try2(cert, pub_key, name, signature)


def test_cameleon():
    """Test the chameleon certificates."""
    pem_files = get_chameleon_certs()

    for pem_file in pem_files:
        with open(pem_file, "rb") as file:
            cert = parse_certificate(file.read())
            print_chain_subject_and_issuer([cert])
            delta_cert = build_delta_cert_from_paired_cert(cert)
            print_chain_subject_and_issuer([delta_cert])


test_catalyst()
test_cameleon()
