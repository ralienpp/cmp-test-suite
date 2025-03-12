# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for extracting information from certificates and CSRs.

Like the SubjectKeyIdentifier, KeyUsage, and ExtendedKeyUsage extensions.
The SubjectKeyIdentifier is extracted from a certificate, because this extension needs to be the same
as the `senderKID` for the `PKIHeader` or inside the recipient identifier in the `RecipientInfo` for the `EnvelopedData`
structure, which is used to securely exchange data between two parties.
"""

import logging
from typing import Optional, Union

from pyasn1.codec.der import decoder
from pyasn1.type import base, univ
from pyasn1_alt_modules import rfc5280, rfc6402, rfc9480
from pyasn1_alt_modules.rfc5652 import Attribute
from robot.api.deco import not_keyword

from resources import asn1utils
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import EXTENSION_NAME_2_OID

# TODO refactor.


def cert_contains_extension(  # noqa D417 undocumented-param
    cert_or_extn: Union[rfc9480.CMPCertificate, rfc9480.Extensions],
    name_or_oid: str,
    must_be_non_crit: Optional[bool] = None,
    must_be_crit: Optional[bool] = None,
) -> None:
    """Check if a certificate or extensions object contains the given extension.

    Arguments:
    ---------
        - `cert_or_extn`: The certificate or extensions object to search.
        - `name_or_oid`: The OID or name of the extension.
        - `must_be_non_crit`: If `True`, ensure the extension is non-critical. Defaults to `disabled`.
        - `must_be_crit`: If `True`, ensure the extension is critical. Defaults to `disabled`.

    Raises:
    ------
        - `ValueError`: If the extension is not found.
        - `ValueError`: If the extension is critical and `must_be_non_crit` is `True`.
        - `ValueError`: If the extension is non-critical and `must_be_crit` is `True`.
        - `KeyError`: If the extension name is not found in the mapping.

    Examples:
    --------
    | Cert Contains Extension | ${certificate} | key_usage | must_be_non_crit=${True} |
    | Cert Contains Extension | ${extension} | eku | must_be_crit=${True} |
    | Cert Contains Extension | ${cert_template["extensions"]} | 1.2.840.113549.1.9.14 |

    """
    if "." in name_or_oid:
        oid = univ.ObjectIdentifier(name_or_oid)
    elif name_or_oid in EXTENSION_NAME_2_OID:
        oid = EXTENSION_NAME_2_OID[name_or_oid]
    else:
        raise KeyError(
            f"Extension name not found: {name_or_oid}, a"
            "please have a look at the OID mapping `EXTENSION_NAME_2_OID`."
            f"Currently supported extension names are: {list(EXTENSION_NAME_2_OID.keys())}"
        )

    if isinstance(cert_or_extn, rfc9480.CMPCertificate):
        cert_or_extn = cert_or_extn["tbsCertificate"]["extensions"]

    out = get_extension(
        cert_or_extn,
        oid,
        must_be_non_crit=must_be_non_crit,
        must_be_crit=must_be_crit,
    )

    if out is None:
        name = may_return_oid_to_name(oid)
        raise ValueError(f"Extension {name}:{oid} is not present.")


def extension_must_be_non_critical(  # noqa D417 undocumented-param
    cert_or_extn: Union[rfc9480.CMPCertificate, rfc9480.Extensions], name_or_oid: str
) -> None:
    """Ensure that the extension with the given OID or name is non-critical.

    Arguments:
    ---------
        - `cert_or_extn`: The certificate or extensions object to search.
        - `name_or_oid`: The OID or name of the extension.

    Raises:
    ------
        - `ValueError`: If the extension is critical.

    """
    if "." in name_or_oid:
        oid = univ.ObjectIdentifier(name_or_oid)
    else:
        oid = EXTENSION_NAME_2_OID[name_or_oid]

    extn = get_extension(cert_or_extn["tbsCertificate"]["extensions"], oid, must_be_non_crit=True)

    if extn is None:
        name = may_return_oid_to_name(oid)
        raise ValueError(f"Extension {name}:{oid} is not present.")


# TODO add unit test


@not_keyword
def get_extension(
    extensions: rfc9480.Extensions,
    oid: univ.ObjectIdentifier,
    must_be_non_crit: Optional[bool] = None,
    must_be_crit: Optional[bool] = None,
) -> Optional[rfc5280.Extension]:
    """Extract an extension with the given Object Identifier (OID).

    :param extensions: List of extensions to search.
    :param oid: The OID of the desired extension.
    :param must_be_non_crit: If True, ensure the extension is non-critical. Defaults to disabled.
    :param must_be_crit: If True, ensure the extension is critical. Defaults to disabled.
    :return: The matching extension, or None if not found.
    """
    if not extensions.isValue:
        logging.info("No `extensions` found in the certificate.")
        return None

    for ext in extensions:
        if ext["extnID"] == oid:
            if must_be_non_crit and ext["critical"] and must_be_non_crit is not None:
                raise ValueError("Extension must be non-critical but is critical.")
            if must_be_crit and not ext["critical"] and must_be_crit is not None:
                raise ValueError("Extension must be critical but is non-critical.")
            return ext
    return None


@not_keyword
def get_subject_key_identifier(cert: rfc9480.CMPCertificate) -> Optional[bytes]:
    """Extract the subjectKeyIdentifier from a pyasn1 `CMPCertificate`, if present.

    :param cert: The certificate to extract the extension from.
    :return: `None` if not present. Else digest `Bytes`.
    :raises: `pyasn1.error.PyAsn1Error` if the extension value cannot be decoded.
    """
    extn_val = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_subjectKeyIdentifier)
    if extn_val is None:
        return None
    ski, _ = decoder.decode(extn_val["extnValue"], asn1Spec=rfc5280.SubjectKeyIdentifier())
    return ski.asOctets()


@not_keyword
def get_authority_key_identifier(cert: rfc9480.CMPCertificate) -> Optional[rfc5280.AuthorityKeyIdentifier]:
    """Extract the subjectKeyIdentifier from a pyasn1 `CMPCertificate`, if present.

    :param cert: The certificate to extract the extension from.
    :return: `None` if not present. Else digest `Bytes`.
    :raises: `pyasn1.error.PyAsn1Error` if the extension value cannot be decoded.
    """
    extn_val = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_authorityKeyIdentifier)
    if extn_val is None:
        return None
    return decoder.decode(extn_val["extnValue"], asn1Spec=rfc5280.AuthorityKeyIdentifier())[0]


@not_keyword
def get_basic_constraints(cert: rfc9480.CMPCertificate) -> Optional[rfc5280.BasicConstraints]:
    """Extract the BasicConstraints from a pyasn1 `CMPCertificate`, if present.

    :param cert: The certificate to extract the extension from.
    :return: `None` if not present. Else `BasicConstraints` object.
    :raises: `pyasn1.error.PyAsn1Error` if the extension value cannot be decoded.
    """
    extn_val = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_basicConstraints)
    if extn_val is None:
        return None
    return decoder.decode(extn_val["extnValue"], asn1Spec=rfc5280.BasicConstraints())[0]


def _get_key_usage(cert: rfc9480.CMPCertificate) -> Optional[rfc5280.KeyUsage]:
    """Extract the KeyUsage extension from an `pyasn1` CMPCertificate, if present.

    :param cert: The certificate to extract the extension from.
    :return: The `KeyUsage` object if the `KeyUsage` extension is found, otherwise `None`.
    :raises: `pyasn1.error.PyAsn1Error` if the extension value cannot be decoded.
    """
    key_usage = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_keyUsage)
    if key_usage is None:
        return None
    return decoder.decode(key_usage["extnValue"], asn1Spec=rfc5280.KeyUsage())[0]


@not_keyword
def get_extended_key_usage(cert) -> Optional[rfc5280.ExtKeyUsageSyntax]:
    """Extract the `ExtendedKeyUsage` (EKU) extension from a certificate, if present.

    :param cert: The certificate to extract the extension from.
    :return: The `ExtKeyUsageSyntax` object if the EKU extension is found, or `None` if not present.
    :raises: `pyasn1.error.PyAsn1Error` if the extension value cannot be decoded.
    """
    eku = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_extKeyUsage)
    if eku is None:
        return None
    return decoder.decode(eku["extnValue"], asn1Spec=rfc5280.ExtKeyUsageSyntax())[0]


@not_keyword
def _get_subject_alt_name(cert: rfc9480.CMPCertificate) -> Optional[rfc5280.SubjectAltName]:
    """Extract the `SubjectAltName` extension from a certificate, if present.

    :param cert: The certificate to extract the extension from.
    :return: The `SubjectAltName` object if the SAN extension is found, or `None` if not present.
    """
    extn_val = get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_ce_subjectAltName)
    if extn_val is None:
        return None
    return decoder.decode(extn_val["extnValue"], asn1Spec=rfc5280.SubjectAltName())[0]


def get_field_from_certificate(  # noqa D417 undocumented-param
        cert: rfc9480.CMPCertificate, query: Optional[str] = None, extension: Optional[str] = None
) -> Union[bytes, None, base.Asn1Type]:
    """Retrieve a value from a `pyasn1` CMPCertificate using a specified query or extension.

    Extracts a value from a certificate based on a pyasn1 query or a named certificate
    extension. The default query starts from `tbsCertificate`. If accessing attributes like `serialNumber`,
    it can be parsed directly.

    Note:
    ----
        - The function uses pyasn1 notation (e.g., `serialNumber`)

    Arguments:
    ---------
        - `cert`: The certificate object from which to retrieve the value.
        - `query`: An optional string specifying the field to query in the certificate using pyasn1 notation.
        The path to the value you want to extract, given as a dot-notation.
        - `extension`: An optional string specifying the extension to retrieve from the certificate.

    Supported Extensions:
    --------------------
        - "ski": SubjectKeyIdentifier
        - "key_usage": KeyUsage
        - "eku": ExtendedKeyUsage
        - "aki": AuthorityKeyIdentifier
        - "basic_constraints": BasicConstraints
        - "san": SubjectAltName

    Returns:
    -------
        - Either an A `pyasn1` object representing the value from the certificate if found, or bytes if "ski" is \
        present or `None` if the extension is not present.

    Raises:
    ------
        - `ValueError`: If neither `query` nor `extension` is provided.
        - `NotImplementedError`: If the specified `extension` is not supported by the function.
        - `pyasn1.error.PyAsn1Error` if the extension value cannot be decoded.

    Examples:
    --------
    | ${serial_number}= | Get Field From Certificate | ${certificate} | query="serialNumber" |
    | ${ski}= | Get Field From Certificate | ${certificate} | extension="ski" |
    | ${key_usage}= | Get Field From Certificate | ${certificate} | extension="key_usage" |

    """
    if not (query or extension):
        raise ValueError("Either 'query' or 'extension' must be provided to retrieve a field from the certificate.")

    if cert is None:
        raise ValueError("The parsed `cert` had no value!")

    if query is not None:
        return asn1utils.get_asn1_value(cert, query="tbsCertificate." + query)

    if extension == "ski":
        return get_subject_key_identifier(cert)

    if extension == "key_usage":
        return _get_key_usage(cert)

    if extension == "eku":
        return get_extended_key_usage(cert)

    if extension == "aki":
        return get_authority_key_identifier(cert)

    if extension == "basic_constraints":
        return get_basic_constraints(cert)

    if extension == "san":
        return _get_subject_alt_name(cert)

    raise NotImplementedError(f"Extension name not supported: {extension}")


@not_keyword
def extract_extension_from_csr(csr: rfc6402.CertificationRequest) -> Optional[rfc9480.Extensions]:
    """Extract extensions from a CertificationRequest object if present.

    :param csr: The CSR object from which to extract extensions, if possible.
    :return: The extracted extensions, but only from the first index.
    """
    if not csr["certificationRequestInfo"]["attributes"].isValue:
        return None

    ext_oid = univ.ObjectIdentifier("1.2.840.113549.1.9.14")
    attr: Attribute()

    for attr in csr["certificationRequestInfo"]["attributes"]:
        if attr["attrType"] == ext_oid:
            extn, _ = decoder.decode(attr["attrValues"][0].asOctets(), asn1Spec=rfc9480.Extensions())
            return extn

    return None
