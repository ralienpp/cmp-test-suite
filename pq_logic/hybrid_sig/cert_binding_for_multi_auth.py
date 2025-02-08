# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""

Related Certificates for Use in Multiple Authentications within a Protocol

Based on:
draft-ietf-lamps-cert-binding-for-multi-auth-06

https://datatracker.ietf.org/doc/draft-ietf-lamps-cert-binding-for-multi-auth/
"""

import email
import logging
import time
from datetime import datetime
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5652, rfc6402, rfc9480
from pyasn1_alt_modules.rfc7906 import BinaryTime
from resources import certextractutils, certutils, cmputils, cryptoutils, envdatautils, utils
from resources.asn1utils import get_set_bitstring_names
from resources.ca_kga_logic import validate_issuer_and_serial_number_field
from resources.certbuildutils import build_cert_from_csr
from resources.convertutils import pyasn1_time_obj_to_py_datetime
from resources.exceptions import BadAsn1Data
from resources.oid_mapping import get_hash_from_oid, may_return_oid_to_name
from resources.typingutils import PrivateKey, Strint
from robot.api.deco import keyword, not_keyword
from unit_tests.utils_for_test import convert_to_crypto_lib_cert

from pq_logic.hybrid_structures import RelatedCertificate, RequesterCertificate
from pq_logic.tmp_oids import id_aa_relatedCertRequest, id_relatedCert


@keyword(name="Prepare RequesterCertificate")
def prepare_requester_certificate(  # noqa: D417 Missing argument descriptions in the docstring
    cert_a: rfc9480.CMPCertificate,
    cert_a_key: PrivateKey,
    uri: str,
    bad_pop: bool = False,
    hash_alg: Optional[str] = None,
    invalid_serial_number: bool = False,
    invalid_issuer: bool = False,
    freshness: Strint = 0,
    request_time: Optional[Strint] = None,
) -> RequesterCertificate:
    """Prepare the RequesterCertificate structure.

    Used to provide an association to `cert_A` for the newly generated certificate.
    If the CA is a different one the URI SHOULD be a dataURI, containing inline degenerate PKCS#7 consisting
    of all the certificates and CRLs required to validate Cert A. If same CA SHOULD be a URL.

    Arguments:
    ---------
        - `cert_a`: Certificate A as CMPCertificate.
        - `cert_a_key`: The private key corresponding to the related certificate.
        - `uri`: URL location of Cert A or the complete chain of Cert A, all certificate contained must be DER-encoded.
        - `bad_pop`: Whether to manipulate the signature. Defaults to `False`.
        - `hash_alg`: The hash algorithm to use for the certificate, if the private key is ed25519. Defaults to `None`.
        - `invalid_serial_number`: Whether to manipulate the serial number. Defaults to `False`.
        - `invalid_issuer`: Whether to manipulate the issuer. Defaults to `False`.
        - `freshness`: A value to modify The freshness of the BinaryTime. Defaults to `0`.
        - `request_time`: The time of the request. Defaults to `None`.

    Returns:
    -------
        - The populated `RequesterCertificate` structure.

    Raises:
    ------
        - ValueError: If the hash algorithm could not be determined.

    Examples:
    --------
    | ${req_cert}= | Prepare RequesterCertificate | ${cert_a} | ${cert_a_key} | ${uri} |
    | ${req_cert}= | Prepare RequesterCertificate | ${cert_a} | ${cert_a_key} | ${uri} | bad_pop=True |

    """
    # get current UNIX time
    current_time = request_time or (int(time.time()) + int(freshness))
    current_time = int(current_time)

    bin_time = BinaryTime(current_time)
    cert_id = envdatautils.prepare_issuer_and_serial_number(
        cert=cert_a, modify_serial_number=invalid_serial_number, modify_issuer=invalid_issuer
    )

    req_cert = RequesterCertificate()
    req_cert["requestTime"] = bin_time
    req_cert["certID"] = cert_id
    req_cert["locationInfo"] = uri

    # As of section 3.1
    # last part: the signature field contains a digital signature over the concatenation of
    # DER encoded requestTime and IssuerAndSerialNumber.
    data = encoder.encode(bin_time) + encoder.encode(cert_id)

    # As of section 3.q signed with the signature algorithm associated with the private key
    # of the certificate.
    if hash_alg is None:
        # could be None for ed25519, ed448, and ML-DSA, SLH-DSA and maybe more in the
        # future.
        oid = cert_a["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]
        hash_alg = get_hash_from_oid(oid, only_hash=True)

    if isinstance(cert_a_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)) and hash_alg is None:
        # This solution is not inside the draft.
        # TODO maybe file an issue on github or ask if this is allowed solution.
        hash_alg = get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"])

    signature = cryptoutils.sign_data(data=data, key=cert_a_key, hash_alg=hash_alg)

    logging.info(f"Signature: {signature}")
    if bad_pop:
        signature = utils.manipulate_first_byte(signature)

    req_cert["signature"] = univ.BitString.fromOctetString(signature)
    return req_cert


@keyword(name="Add CSR relatedCertRequest Attribute")
def add_csr_related_cert_request_attribute(  # noqa: D417 Missing argument descriptions in the docstring
    csr: rfc6402.CertificationRequest, requester_cert: RequesterCertificate
):
    """Add the relatedCertRequest attribute to the CSR.

    Arguments:
    ---------
        - `csr`: The CSR to which the attribute will be added.
        - `requester_cert`: The RequesterCertificate to include.

    Returns:
    -------
        - The updated CSR.

    Examples:
    --------
    | ${csr}= | Add CSR relatedCertRequest Attribute | ${csr} | ${requester_cert} |

    """
    rel_cert_req_attr = rfc5652.Attribute()
    rel_cert_req_attr["attrType"] = id_aa_relatedCertRequest
    attr_val = rfc5652.AttributeValue(encoder.encode(requester_cert))
    rel_cert_req_attr["attrValues"].append(attr_val)

    csr["certificationRequestInfo"]["attributes"].append(rel_cert_req_attr)

    return csr


def _get_related_cert_sig(cert: rfc9480.CMPCertificate) -> Optional[bytes]:
    """Extract the signature from the `RelatedCertificate` extension.

    :param cert: The certificate from which to extract the extension.
    :return: The signature value (as bytes) if the extension is present, otherwise `None`.
    :raises BadAsn1Data: If the extension decoded had a remainder.
    """
    for ext in cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] == id_relatedCert:
            if ext["critical"]:
                logging.info("This extension SHOULD NOT be marked critical.")

            sig = ext["extnValue"].asOctets()
            obj, rest = decoder.decode(sig, asn1Spec=RelatedCertificate())
            if rest:
                raise BadAsn1Data("`RelatedCertificate`")
            return obj.asOctets()

    return None


def validate_related_cert_extension(  # noqa: D417 Missing argument descriptions in the docstring
    cert_a: rfc9480.CMPCertificate, related_cert: rfc9480.CMPCertificate, hash_alg: Optional[str] = None
) -> None:
    """Extract the `RelatedCertificate` extension from a given certificate.

    This function retrieves the RelatedCertificate extension from a certificate,
    if present, and extracts the hash of the related certificate and then validates
    the hash against the hash algorithm used by signing the certificate.

    Arguments:
    ---------
        - `cert_a`: The certificate from which to extract the RelatedCertificate extension.
        - `related_cert`: The related certificate which should contain the hash of the related certificate.
        - `hash_alg`: Currently supports adding a hash for ML-DSA or Ed-keys as an example. Defaults to `None`.

    Raises:
    ------
        - `ValueError`: If the certificate does not contain the RelatedCertificate extension.
        - `ValueError`: If the certificate hash is different.
        - `ValueError`: If the related certificate is not found.
        - `ValueError`: If the EKU and KU bits are not set or missing.

    Examples:
    --------
    | Validate Related Certificate Extension | ${cert_a} | ${related_cert} |
    | Validate Related Certificate Extension | ${cert_a} | ${related_cert} | hash_alg="sha256" |

    """
    signature = _get_related_cert_sig(cert_a)
    if not signature:
        raise ValueError("The Certificate did not contain the RelatedCertificate extension.")

    hash_alg = hash_alg or get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"], only_hash=True)
    cert_hash = cmputils.calculate_cert_hash(cert=cert_a, hash_alg=hash_alg)
    if cert_hash != signature:
        raise ValueError(f"The certificate hash is not the same, we used hash_alg: {hash_alg}")

    validate_ku_and_eku_related_cert(cert_a=cert_a, related_cert=related_cert)


def get_related_cert_from_list(  # noqa: D417 Missing argument descriptions in the docstring
    certs: List[rfc9480.CMPCertificate], cert_a: rfc9480.CMPCertificate
) -> rfc9480.CMPCertificate:
    """Get the related certificate from a list of certificates.

    Arguments:
    ---------
        - `certs`: The list of certificates to search.
        - `cert_a`: The certificate for which to find the related certificate.

    Returns:
    -------
        - The related certificate.

    Raises:
    ------
        - ValueError: If the related certificate is not found.

    Examples:
    --------
    | ${related_cert}= | Get Related Cert From List | ${certs} | ${cert_a} |

    """
    hash_alg = get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"], only_hash=True)
    signature = _get_related_cert_sig(cert_a)
    if signature is None:
        raise ValueError("The Certificate did not contain the RelatedCertificate extension.")

    for cert in certs:
        cert_hash = cmputils.calculate_cert_hash(cert=cert, hash_alg=hash_alg)
        if cert_hash == signature:
            return cert
    raise ValueError("No related certificate found.")


def _negative_testing():
    # validations:
    # MUST only include a certificate in the extension that is listed and validated in
    # the relatedCertRequest attribute of the CSR submitted by the requesting entity.
    pass


######################
# Server Side function
######################

# other server side functions are currently not included.


@keyword(name="Validate KU and EKU Related Cert")
def validate_ku_and_eku_related_cert(  # noqa: D417 Missing argument descriptions in the docstring
    cert_a: rfc9480.CMPCertificate, related_cert: rfc9480.CMPCertificate
) -> None:
    """Validate the key usage (KU) and extended key usage (EKU) of a related certificate.

    Ensure that the cert_a has at least the same KU and EKU bits set.

    Arguments:
    ---------
        - ´cert_a´: The certificate being issued (Cert B), which defines the required KU and EKU.
        - ´related_cert´: The related certificate being validated.

    Raises:
    ------
        - ValueError: If EKU and KU bits are not set or missing.

    Examples:
    --------
    | Validate KU and EKU Related Cert | ${cert_a} | ${related_cert} |

    """
    # MUST ensure that the related certificate at least contains the KU bits and EKU
    # OIDs being asserted in the certificate being issued

    eku_cert_a = certextractutils.get_field_from_certificate(cert_a, extension="eku")
    eku_cert_b = certextractutils.get_field_from_certificate(cert_a, extension="eku")

    if eku_cert_a is not None:
        for eku_oid in eku_cert_b:
            if eku_oid not in related_cert:
                raise ValueError()

    ku_cert_a = certextractutils.get_field_from_certificate(cert_a, extension="key_usage")
    ku_cert_b = certextractutils.get_field_from_certificate(related_cert, extension="key_usage")

    if ku_cert_a is not None:
        set_a = set(get_set_bitstring_names(ku_cert_a))  # type: ignore
        set_b = set(get_set_bitstring_names(ku_cert_b))  # type: ignore

        if ku_cert_b is None or set_a - set_b:
            raise ValueError()


@not_keyword
def extract_related_cert_request_attribute(csr: rfc6402.CertificationRequest) -> RequesterCertificate:
    """Extract the relatedCertRequest attribute from a given CSR.

    Retrieves the `relatedCertRequest` attribute from the CSR and decodes it to return the contained
    `RequesterCertificate`.

    :param csr: The `CSR` from which the attribute will be extracted.
    :return: The decoded `RequesterCertificate` object.
    :raises ValueError: If the `relatedCertRequest` attribute is not found in the CSR.
    """
    attributes = csr["certificationRequestInfo"]["attributes"]

    for attr in attributes:
        if attr["attrType"] == id_aa_relatedCertRequest:
            attr_values = attr["attrValues"]
            if len(attr_values) != 1:
                raise ValueError("Unexpected number of values in relatedCertRequest attribute.")
            requester_cert_der = attr_values[0]
            requester_cert, _ = decoder.decode(requester_cert_der, asn1Spec=RequesterCertificate())
            return requester_cert

    raise ValueError("The relatedCertRequest attribute was not found in the CSR.")


@not_keyword
def process_mime_message(mime_data: bytes):
    """Parse a MIME message and extracts application/pkcs7-mime content.

    :param mime_data: Raw MIME message as bytes.
    :return: Decoded CMS content (as bytes).
    """
    message = email.message_from_bytes(mime_data)

    # Look for the application/pkcs7-mime part
    for part in message.walk():
        if part.get_content_type() == "application/pkcs7-mime":
            payload = part.get_payload(decode=True)  # Decode base64
            return payload

    raise ValueError("No application/pkcs7-mime part found in the message.")


def validate_multi_auth_binding_csr(  # noqa: D417 Missing argument descriptions in the docstring
    csr: rfc6402.CertificationRequest,
    load_chain: bool = False,
    max_freshness_seconds: Strint = 500,
    trustanchors: str = "./data/trustanchors",
    allow_os_store: bool = False,
    crl_check: bool = False,
) -> rfc9480.CMPCertificate:
    """Process a CSR containing the `relatedCertRequest` attribute.

    Expected the CSR`s Proof-of-Possession (PoP) to be verified.

    Arguments:
    ---------
        - `csr`: The CertificationRequest to process.
        - `max_freshness_seconds`: How fresh the `BinaryTime` must be. Defaults to `500`.
        - `load_chain`: Whether to load a chain or a single certificate. Defaults to `False`.
        - `trustanchors`: The directory containing the trust anchors. Defaults to `./data/trustanchors`.
        - `allow_os_store`: Whether to allow the OS trust store. Defaults to `False`.
        - `crl_check`: Whether to check the CRL. Defaults to `False`.

    Returns:
    -------
        - The related certificate.

    Raises:
    ------
        - `ValueError`: If the `BinaryTime` is not fresh or the certificate chain is invalid.
        - `InvalidSignature`: If the PoP of the related certificate is invalid.
        - `ValueError`: If the last certificate in the chain is not a trust anchor.
        - `ValueError`: If the certificate chain is not valid.

    Examples:
    --------
    | ${related_cert}= | Validate Multi Auth Binding CSR | ${csr} |

    """
    attributes = extract_related_cert_request_attribute(csr)

    request_time = int(attributes["requestTime"])
    current_time = int(time.time())
    if abs(current_time - request_time) > int(max_freshness_seconds):
        raise ValueError("BinaryTime is not sufficiently fresh.")

    location_info = attributes["locationInfo"]
    signature = attributes["signature"].asOctets()

    cert_chain = utils.load_certificate_from_uri(location_info, load_chain=load_chain)
    cert_a = cert_chain[0]

    extensions = certextractutils.extract_extension_from_csr(csr)
    # For certificate chains, this extension MUST only be included in the end-entity certificate.
    if extensions is not None:
        ca_extn = certextractutils.get_extension(extensions, rfc5280.id_ce_basicConstraints)
        if ca_extn["cA"]:
            raise ValueError("The `Cert B` MUST be an end entity certificate.")

    # validate binding
    public_key = certutils.load_public_key_from_cert(cert_a)
    hash_alg = get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"], only_hash=True)

    sig_name = may_return_oid_to_name(cert_a["tbsCertificate"]["signature"]["algorithm"])
    logging.info(f"Signature algorithm: {sig_name}")

    if hash_alg is None:
        raise ValueError(f"The hash algorithm could not be determined. Signature algorithm was: {sig_name}")

    validate_issuer_and_serial_number_field(attributes["certID"], cert_a)
    # extra the bound value to verify the signature
    data = encoder.encode(attributes["requestTime"]) + encoder.encode(attributes["certID"])

    cryptoutils.verify_signature(data=data, hash_alg=hash_alg, public_key=public_key, signature=signature)

    certutils.certificates_are_trustanchors(cert_chain[-1], trustanchors=trustanchors, allow_os_store=allow_os_store)
    certutils.verify_cert_chain_openssl(cert_chain=cert_chain, crl_check=crl_check)
    return cert_a


# Technically should be changed to CertTemplate and/or CSR.
# MUST include chain check.


@not_keyword
def server_side_validate_cert_binding_for_multi_auth(ee_cert, related_cert) -> None:
    """Validate the certificate binding for multiple authentications on the server side.

    :param ee_cert: The certificate being issued (Cert B), which defines the required KU and EKU.
    :param related_cert: The related certificate (Cert A) being validated.
    """
    # Only on ee-certificates
    extn = certextractutils.get_extension(ee_cert["extensions"], rfc5280.id_ce_basicConstraints)

    if extn is not None:
        if extn["cA"]:
            raise ValueError("The `Cert A` is a CA certificate.")

    # MUST ensure that the related certificate at least contains the KU bits and EKU
    # OIDs being asserted in the certificate being issued
    validate_ku_and_eku_related_cert(ee_cert, related_cert)

    # SHOULD determine that all certificates are valid at the time of issuance.
    # The usable overlap of validity periods is a Subscriber concern.

    now = datetime.now()

    val_cert_a = related_cert["tbsCertificate"]["validity"]
    cert_b = ee_cert["tbsCertificate"]["validity"]

    rel_cert_not_valid_before = pyasn1_time_obj_to_py_datetime(val_cert_a["notBefore"])
    rel_cert_not_valid_after = pyasn1_time_obj_to_py_datetime(val_cert_a["notAfter"])

    cert_b_not_valid_before = pyasn1_time_obj_to_py_datetime(cert_b["notBefore"])
    cert_b_not_valid_after = pyasn1_time_obj_to_py_datetime(cert_b["notAfter"])

    if not (rel_cert_not_valid_after <= now <= rel_cert_not_valid_before):
        raise ValueError("Cert A is not valid at the time of issuance.")
    if not (cert_b_not_valid_before <= now <= cert_b_not_valid_after):
        raise ValueError("Cert B is not valid at the time of issuance.")
    if rel_cert_not_valid_after < rel_cert_not_valid_before:
        logging.info("Cert A and Cert B do not have an overlapping validity period.")


def _convert_to_crypto_lib_cert(cert: rfc9480.CMPCertificate) -> x509.Certificate:
    """Ensure the function calling this method, can work with certificates from the 'cryptography' library."""
    return x509.load_der_x509_certificate(encoder.encode(cert))


def generate_certs_only_message(cert_path: str, cert_dir: str) -> bytes:
    """Generate a CMS 'certs-only' message containing Cert A and its intermediate certificates.

    :param cert_path: Path to the end-entity certificate (Cert A).
    :param cert_dir: The directory where the chain is stored.
    :return: DER-encoded CMS 'certs-only' message as bytes.
    """
    ee_cert = certutils.parse_certificate(utils.load_and_decode_pem_file(cert_path))
    cert_chain = certutils.build_cert_chain_from_dir(ee_cert, cert_chain_dir=cert_dir)

    cms_message = pkcs7.PKCS7SignatureBuilder().set_data(b"")
    for cert in cert_chain:
        cms_message = cms_message.add_certificate(convert_to_crypto_lib_cert(cert))

    cms_der = cms_message.sign(serialization.Encoding.DER, [])
    return cms_der


@keyword(name="Prepare RelatedCertificate Extension")
def prepare_related_cert_extension(  # noqa: D417 Missing argument descriptions in the docstring
    cert_a: rfc9480.CMPCertificate, hash_alg: Optional[str] = None, critical: bool = False
) -> rfc5280.Extension:
    """Prepare the RelatedCertificate extension for a x509 certificate.

    Arguments:
    ---------
        - `cert_a`: The certificate for which to prepare the extension.
        - `hash_alg`: The hash algorithm to use for the certificate. Defaults to `None`.
        (must be provided for ed25519 and ML-DSA.)
        - `critical`: Whether the extension should be marked as critical. Defaults to `False`.

    Returns:
    -------
        - The prepared extension.

    Raises:
    ------
        - ValueError: If the hash algorithm could not be determined.

    Examples:
    --------
    | ${extn}= | Prepare RelatedCertificate Extension | ${cert_a} |
    | ${extn}= | Prepare RelatedCertificate Extension | ${cert_a} | critical=True |

    """
    # Notes:
    # For certificate chains, this extension MUST only be included in the end-entity certificate.

    # TODO tell the specifier to fix for sig algorithm without hash!
    # ed25519 and ML-DSA.

    # for negative testing or ed-keys and so on.
    hash_alg = hash_alg or get_hash_from_oid(cert_a["tbsCertificate"]["signature"]["algorithm"], only_hash=True)

    if hash_alg is None:
        raise ValueError("The hash algorithm could not be determined.")

    cert_hash = cmputils.calculate_cert_hash(cert=cert_a, hash_alg=hash_alg)
    extension = rfc5280.Extension()
    extension["extnID"] = id_relatedCert
    # This extension SHOULD NOT be marked critical.
    # As of section 4.1
    extension["critical"] = critical
    extension["extnValue"] = univ.OctetString(encoder.encode(RelatedCertificate(cert_hash)))

    return extension


@keyword(name="Build Related Cert From CSR")
def build_related_cert_from_csr(  # noqa: D417 Missing argument descriptions in the docstring
    csr: rfc6402.CertificationRequest,
    ca_key: PrivateKey,
    ca_cert: rfc9480.CMPCertificate,
    related_cert: Optional[rfc9480.CMPCertificate] = None,
    critical: bool = False,
    **kwargs,
) -> rfc9480.CMPCertificate:
    """Build the related certificate from a CSR.

    Arguments:
    ---------
       - `csr`: The CSR from which to build the related certificate.
       - `ca_key`: The private key of the CA.
       - `ca_cert`: The CA certificate matching the private key.
       - `related_cert`: The related certificate. Defaults to `None`.
       - `critical`: Whether the extension should be marked as critical. Defaults to `False`.

    **kwargs:
    ---------
       - `trustanchors`: The directory containing the trust anchors. Defaults to `./data/trustanchors`.
       - `allow_os_store`: Whether to allow the OS trust store. Defaults to `False`.
       - `crl_check`: Whether to check the CRL. Defaults to `False`.
       - `max_freshness_seconds`: How fresh the `BinaryTime` must be. Defaults to `500`.
       - `load_chain`: Whether to load a chain or a single certificate, from the URI. Defaults to `False`.

    Returns:
    -------
       - The related certificate.

    Raises:
    ------
       - ValueError: If the `BinaryTime` is not fresh or the certificate chain is invalid.
       - InvalidSignature: If the POP of the related certificate is invalid.
       - ValueError: If the last certificate in the chain is not a trust anchor.
       - ValueError: If the certificate chain is not valid.

    Examples:
    --------
    | ${cert}= | Build Related Certificate | ${csr} | ${ca_key} | ${ca_cert} |

    """
    if related_cert is None:
        related_cert = validate_multi_auth_binding_csr(
            csr,
            load_chain=kwargs.get("load_chain", False),
            trustanchors=kwargs.get("trustanchors", "./data/trustanchors"),
            allow_os_store=kwargs.get("allow_os_store", False),
            crl_check=kwargs.get("crl_check", False),
            max_freshness_seconds=kwargs.get("max_freshness_seconds", 500),
        )

    extn = prepare_related_cert_extension(related_cert, critical=critical)

    # build the certificate
    cert = build_cert_from_csr(
        csr=csr,
        ca_key=ca_key,
        ca_cert=ca_cert,
        extensions=[extn],
    )

    return cert
