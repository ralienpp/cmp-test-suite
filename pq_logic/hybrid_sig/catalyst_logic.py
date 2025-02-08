# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Handles Catalyst Certificates and related functionality."""
import copy
import logging
from typing import Optional, Union

import pyasn1.error
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc9480
from pyasn1_alt_modules.rfc4210 import CMPCertificate
from resources import certbuildutils, certextractutils, certutils, cryptoutils, keyutils, utils
from resources.convertutils import subjectPublicKeyInfo_from_pubkey
from resources.exceptions import BadAlg, BadAsn1Data
from resources.oid_mapping import get_hash_from_oid
from resources.oidutils import (
    PQ_NAME_2_OID,
    id_ce_altSignatureAlgorithm,
    id_ce_altSignatureValue,
    id_ce_subjectAltPublicKeyInfo,
)
from resources.typingutils import PrivateKey, PrivateKeySig, PublicKey, TradSigPrivKey
from robot.api.deco import keyword, not_keyword

from pq_logic.hybrid_structures import AltSignatureValueExt, SubjectAltPublicKeyInfoExt
from pq_logic.keys.abstract_composite import AbstractCompositeSigPrivateKey
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey


@keyword(name="Prepare SubjectAltPublicKeyInfo Extension")
def prepare_subject_alt_public_key_info_extn(  # noqa: D417 Missing a parameter in the Docstring
    key: Optional[Union[PQSignaturePrivateKey, PQSignaturePublicKey]],
    critical: bool,
    spki: Optional[rfc5280.SubjectPublicKeyInfo] = None,
) -> rfc5280.Extension:
    """Prepare the `SubjectAltPublicKeyInfo` extension.

    Arguments:
    ---------
        - `public_key`: The alternative public or private key.
        - `critical`: Whether the extension is critical.
        - `spki`: The `SubjectPublicKeyInfo` structure. Defaults to `None`.

    Returns:
    -------
        - The populated `Extension` structure.

    Raises:
    ------
        - `ValueError`: If neither `key` nor `spki` is provided.

    Examples:
    --------
    | ${extn}= | Prepare SubjectAltPublicKeyInfo Extension | ${public_key} | critical=True |

    """

    if spki is None and key is None:
        raise ValueError("Either `key` or `spki` must be provided.")

    if spki is None:
        if isinstance(key, PQSignaturePrivateKey):
            key = key.public_key()

        spki = subjectPublicKeyInfo_from_pubkey(key)

    spki_ext = rfc5280.Extension()
    spki_ext["extnID"] = id_ce_subjectAltPublicKeyInfo
    spki_ext["critical"] = critical
    spki_ext["extnValue"] = univ.OctetString(encoder.encode(spki))
    return spki_ext


@keyword(name="Prepare AltSignatureAlgorithm Extension")
def prepare_alt_sig_alg_id_extn(  # noqa: D417 Missing a parameter in the Docstring
    alg_id: Optional[rfc5280.AlgorithmIdentifier] = None,
    critical: bool = False,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
    use_pre_hash: bool = False,
    key: Optional[PrivateKeySig] = None,
) -> rfc5280.Extension:
    """Prepare the altSignatureAlgorithm extension.

    Arguments:
    ---------
        - `alg_id`: The alternative AlgorithmIdentifier.
        - `critical`: Whether the extension is critical. Defaults to `False`.
        - `hash_alg`: The hash algorithm to use. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for signing. Defaults to `False`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `key`: The key to prepare the signature algorithm for. Defaults to `None`.

    Returns:
    -------
        - The populated `Extension` structure.

    Raises:
    ------
        - `ValueError`: If neither `alg_id` nor `key` is provided.

    Examples:
    --------
    | ${extn}= | Prepare AltSignatureAlgorithm Extension | ${alg_id} | critical=True |
    | ${extn}= | Prepare AltSignatureAlgorithm Extension | key=${key} | use_rsa_pss=True |

    """
    if alg_id is None and key is None:
        raise ValueError("Either `alg_id` or `key` must be provided.")

    if key is not None:
        alg_id = certbuildutils.prepare_sig_alg_id(
            signing_key=key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss, use_pre_hash=use_pre_hash
        )

    alt_signature_algorithm_extension = rfc5280.Extension()
    alt_signature_algorithm_extension["extnID"] = id_ce_altSignatureAlgorithm
    alt_signature_algorithm_extension["critical"] = critical
    alt_signature_algorithm_extension["extnValue"] = univ.OctetString(encoder.encode(alg_id))

    return alt_signature_algorithm_extension


@keyword(name="Prepare AltSignatureValue Extension")
def prepare_alt_signature_value_extn(  # noqa: D417 Missing a parameter in the Docstring
    signature: bytes, critical: bool
) -> rfc5280.Extension:
    """Prepare the AltSignatureValue extension.

    Arguments:
    ---------
        - `signature`: The alternative signature bytes.
        - `critical`: Whether the extension is critical.

    Returns:
    -------
        - The populated `Extension` structure.

    Examples:
    --------
    | ${extn}= | Prepare AltSignatureValue Extension | ${signature} | critical=True |

    """
    alt_signature_value_extension = rfc5280.Extension()
    alt_signature_value_extension["extnID"] = id_ce_altSignatureValue
    alt_signature_value_extension["critical"] = critical
    alt_signature_value_extension["extnValue"] = univ.OctetString(
        encoder.encode(AltSignatureValueExt.fromOctetString(signature))
    )
    return alt_signature_value_extension


@not_keyword
def extract_alt_signature_data(
    cert: rfc9480.CMPCertificate,
    exclude_alt_extensions: bool = False,
    only_tbs_cert: bool = False,
    exclude_signature_field: bool = False,
    exclude_first_spki: bool = False,
) -> bytes:
    """Prepare the data to be signed for the `altSignatureValue` extension by excluding the altSignatureValue extension.

    :param cert: The certificate to prepare data from.
    :param exclude_alt_extensions: Whether to exclude alternative extensions for the signature verification.
    :param only_tbs_cert: Whether to only include the `tbsCertificate` part of the certificate and
    exclude the `signatureAlgorithm` field.
    :param exclude_signature_field: Whether to exclude the `signature` field from the data. Defaults to `False`.
    :param exclude_first_spki: Whether to exclude the first `subjectPublicKeyInfo` field from the data.
    Defaults to `False`.
    :return: DER-encoded bytes of the data to be signed.
    """

    der_data = copy.deepcopy(encoder.encode(cert))
    tmp_cert = decoder.decode(der_data, asn1Spec=rfc9480.CMPCertificate())[0]

    tbs_cert = tmp_cert["tbsCertificate"]

    data = b""

    for field in tbs_cert.keys():
        if field == "extensions":
            pass
        elif field == "subjectPublicKeyInfo" and exclude_first_spki:
            pass
        elif field == "signature" and not exclude_signature_field:
            data += encoder.encode(tbs_cert[field])
        else:
            if tbs_cert[field].isValue:
                data += encoder.encode(tbs_cert[field])

    new_extn = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

    exclude_extn = (
        [id_ce_altSignatureValue]
        if not exclude_alt_extensions
        else [id_ce_altSignatureValue, id_ce_altSignatureAlgorithm, id_ce_subjectAltPublicKeyInfo]
    )

    for x in tmp_cert["tbsCertificate"]["extensions"]:
        if x["extnID"] not in exclude_extn:
            new_extn.append(x)

    tmp_cert["tbsCertificate"]["extensions"] = new_extn
    data = encoder.encode(tbs_cert)

    if tmp_cert["signatureAlgorithm"].isValue and not only_tbs_cert:
        data += encoder.encode(tmp_cert["signatureAlgorithm"])

    return data


def sign_cert_catalyst(  # noqa: D417 Missing a parameter in the Docstring
    cert: rfc9480.CMPCertificate,
    pq_key: PQSignaturePrivateKey,
    trad_key: TradSigPrivKey,
    pq_hash_alg: Optional[str] = None,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
    critical: bool = False,
    bad_alt_sig: bool = False,
):
    """Sign the certificate with both traditional and alternative algorithms and adding the catalyst extensions.

    Arguments:
    ---------
        - `cert`: The certificate to sign.
        - `pq_key`: The post-quantum private key for alternative signing.
        - `trad_key`: The traditional private key for traditional signing.
        - `pq_hash_alg`: Hash algorithm for the post-quantum signature. Defaults to `None`.
        - `hash_alg`: Hash algorithm for the traditional signature. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for traditional signing. Defaults to `False`.
        - `critical`: Whether the catalyst extensions are critical. Defaults to `False`.
        - `bad_alt_sig`: Whether to manipulate the alternative signature to be invalid. Defaults to `False`.

    Returns:
    -------
        - The signed certificate.

    Examples:
    --------
    | ${cert}= | Sign Cert Catalyst | ${cert} | ${pq_key} | ${trad_key} |
    | ${cert}= | Sign Cert Catalyst | ${cert} | ${pq_key} | ${trad_key} | pq_hash_alg=sha512 |

    """
    alt_alg_id = certbuildutils.prepare_sig_alg_id(pq_key, hash_alg=pq_hash_alg, use_rsa_pss=use_rsa_pss)
    trad_alg_id = certbuildutils.prepare_sig_alg_id(trad_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)

    cert["tbsCertificate"]["signature"] = trad_alg_id
    cert["signatureAlgorithm"] = trad_alg_id

    cert["tbsCertificate"]["extensions"].append(prepare_alt_sig_alg_id_extn(alt_alg_id, critical=critical))

    cert["tbsCertificate"]["extensions"].append(
        prepare_subject_alt_public_key_info_extn(key=pq_key.public_key(), critical=critical)
    )

    alt_sig_data = extract_alt_signature_data(cert)

    alt_signature = cryptoutils.sign_data(data=alt_sig_data, key=pq_key, hash_alg=pq_hash_alg)
    if bad_alt_sig:
        if isinstance(pq_key, AbstractCompositeSigPrivateKey):
            alt_signature = utils.manipulate_composite_sig(alt_signature)
        else:
            alt_signature = utils.manipulate_first_byte(alt_signature)

    alt_extn = prepare_alt_signature_value_extn(signature=alt_signature, critical=critical)
    cert["tbsCertificate"]["extensions"].append(alt_extn)

    return certbuildutils.sign_cert(signing_key=trad_key, cert=cert, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss)


# TODO update to check for other algorithms.


def validate_catalyst_extensions(  # noqa: D417 Missing a parameter in the Docstring
    cert: rfc9480.CMPCertificate, sig_alg_must_be: Optional[str] = None
) -> Union[None, dict]:
    """Check if the certificate contains all required catalyst extensions.

    Required Extensions:
    --------------------
    - subjectAltPublicKeyInfo
    - altSignatureAlgorithm
    - altSignatureValue

    Arguments:
    ---------
       - `cert`: The certificate to check for the extensions.
       - `sig_alg_must_be`: The signature algorithm name to be expected for the alternative signature.
       (e.g., "ml-dsa-44", "ml-dsa-44-sha512" can only be a pq-algorithm).
       Defaults to `None`.

    Returns:
    -------
        - A dictionary with extension values if all are present, else `None`.
        (keys are: "signature", "spki", "alg_id")

    Raises:
    ------
        - `ValueError`: If only some catalyst extensions are present.
        - `BadAlg`: If the signature algorithm does not match the expected value.
        - `KeyError`: If the signature algorithm is not PQ-signature algorithm.
        - `BadAsn1Data`: If extensions are malformed.

    Examples:
    --------
    | ${catalyst_ext}= | Validate Catalyst Extensions | ${cert} |
    | ${catalyst_ext}= | Validate Catalyst Extensions | ${cert} | sig_alg_must_be=ml-dsa-44 |

    """
    required_extensions = {id_ce_subjectAltPublicKeyInfo, id_ce_altSignatureAlgorithm, id_ce_altSignatureValue}

    if not cert["tbsCertificate"]["extensions"].isValue:
        return None

    extensions = {}
    for ext in cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] in required_extensions:
            extensions[ext["extnID"]] = ext["extnValue"]

    if len(extensions) == 0:
        return None
    elif len(extensions) != 3:
        raise ValueError("Certificate must include either all or none of the catalyst extensions.")

    try:
        subject_alt_public_key_info = decoder.decode(
            extensions[id_ce_subjectAltPublicKeyInfo], asn1Spec=rfc5280.SubjectPublicKeyInfo()
        )[0]

        alt_signature_algorithm = decoder.decode(
            extensions[id_ce_altSignatureAlgorithm], asn1Spec=rfc5280.AlgorithmIdentifier()
        )[0]

        alt_signature_value, rest = decoder.decode(extensions[id_ce_altSignatureValue], asn1Spec=AltSignatureValueExt())

        if rest:
            raise BadAsn1Data("Invalid altSignatureValue extension content.")

        if sig_alg_must_be is not None:
            if "." in sig_alg_must_be:
                if str(alt_signature_algorithm["algorithm"]) != sig_alg_must_be:
                    raise BadAlg(f"Signature algorithm must be {sig_alg_must_be}.")
            else:
                if str(PQ_NAME_2_OID[sig_alg_must_be]) != str(alt_signature_algorithm["algorithm"]):
                    raise BadAlg(f"Signature algorithm must be {sig_alg_must_be}.")

        return {
            "signature": alt_signature_value.asOctets(),
            "spki": subject_alt_public_key_info,
            "alg_id": alt_signature_algorithm,
        }

    except pyasn1.error.PyAsn1Error as e:
        raise BadAsn1Data(f"Invalid extension content or verification error: {e}")


def verify_catalyst_signature(  # noqa: D417 Missing a parameter in the Docstring
    cert: rfc9480.CMPCertificate,
    issuer_cert: Optional[rfc9480.CMPCertificate] = None,
    issuer_pub_key: Optional[PrivateKeySig] = None,
    exclude_alt_extensions: bool = False,
    only_tbs_cert: bool = False,
    sig_alg_must_be: Optional[str] = None,
) -> None:
    """Verify the alternative signature for migrated relying parties.

    First verify traditional signature to ensure certificate authenticity and then
    verify the alternative signature by excluding the altSignatureValue extension.

    Arguments:
    ---------
        - `cert`: The certificate to verify.
        - `issuer_cert`: The issuer's certificate for traditional signature verification. Defaults to `None`.
        - `issuer_pub_key`: The issuer's public key for traditional signature verification. Defaults to `None`.
        - `exclude_alt_extensions`: Whether to exclude alternative extensions for the signature verification.
        - `only_tbs_cert`: Whether to only include the `tbsCertificate` part of the certificate and
        exclude the `signatureAlgorithm` field.
        - `sig_alg_must_be`: The signature algorithm name to be expected for the alternative signature.
        (e.g., "ml-dsa-44", "ml-dsa-44-sha512" can only be a pq-algorithm).
        Defaults to `None`.

    Raises:
    ------
        - `ValueError`: If catalyst extensions are missing or verification fails.
        - `InvalidSignature`: If the traditional signature or the alternative signature verification fails.

    Examples:
    --------
    | Verify Catalyst Signature | ${cert} | ${issuer_cert} |
    | Verify Catalyst Signature | ${cert} | ${issuer_pub_key} | sig_alg_must_be=ml-dsa-44 |

    """
    catalyst_ext = validate_catalyst_extensions(cert=cert, sig_alg_must_be=sig_alg_must_be)
    if catalyst_ext is None:
        raise ValueError("Catalyst extensions are not present, cannot perform migrated verification.")

    if issuer_cert is not None:
        issuer_pub_key = keyutils.load_public_key_from_spki(issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"])
    else:
        issuer_pub_key = issuer_pub_key or keyutils.load_public_key_from_spki(
            cert["tbsCertificate"]["subjectPublicKeyInfo"]
        )

    # Step 1: Verify the traditional signature
    certutils.verify_cert_signature(cert=cert, issuer_pub_key=issuer_pub_key)

    # Step 2: Verify the alternative signature
    pq_pub_key = keyutils.load_public_key_from_spki(catalyst_ext["spki"])
    hash_alg = get_hash_from_oid(catalyst_ext["alg_id"]["algorithm"], only_hash=True)

    alt_sig_data = extract_alt_signature_data(
        cert, exclude_alt_extensions=exclude_alt_extensions, only_tbs_cert=only_tbs_cert
    )

    cryptoutils.verify_signature(
        public_key=pq_pub_key, hash_alg=hash_alg, data=alt_sig_data, signature=catalyst_ext["signature"]
    )

    logging.info("Alternative signature verification succeeded.")


def build_catalyst_cert(  # noqa: D417 Missing a parameter in the Docstring
    trad_key: TradSigPrivKey,
    pq_key: PQSignaturePrivateKey,
    client_key: PrivateKey,
    common_name: str = "CN=Hans Mustermann",
    extensions: Optional[rfc5280.Extensions] = None,
    **kwargs,
) -> CMPCertificate:
    """Generate a catalyst certificate combining traditional and post-quantum keys.

    Arguments:
    ---------
        - `trad_key`: The traditional private key (e.g., RSA) used for signing the certificate.
        - `pq_key`: The post-quantum private key.
        - `client_key`: The client key to create the certificate for.
        - `common_name`: The subject's common name (CN) for the certificate. Defaults to "CN=Hans Mustermann".

        - `extensions`: Optional extensions to include in the certificate.

    **kwargs:
    ---------
        - `critical`: Whether the extensions are critical. Defaults to `False`.
        - `hash_alg`: The hash algorithm to use. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for signing. Defaults to `False`.
        - `alt_hash_alg`: The hash algorithm to use for the post-quantum signature. Defaults to `None`.

    Returns:
    -------
        - The created `CMPCertificate`.

    Examples:
    --------
    | ${cert}= | Build Catalyst Cert | ${trad_key} | ${pq_key} | ${client_key} |

    """
    tbs_cert = certbuildutils.prepare_tbs_certificate(
        subject=common_name,
        signing_key=trad_key,
        public_key=client_key.public_key(),
        use_rsa_pss=kwargs.get("use_rsa_pss", False),
        extensions=extensions,
    )

    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = tbs_cert
    return sign_cert_catalyst(
        cert,
        trad_key=trad_key,
        pq_key=pq_key,
        hash_alg=kwargs.get("hash_alg", "sha256"),
        pq_hash_alg=kwargs.get("alt_hash_alg"),
        critical=kwargs.get("critical", False),
        use_rsa_pss=kwargs.get("use_rsa_pss", False),
    )


def load_catalyst_public_key(  # noqa: D417 Missing a parameter in the Docstring
    extensions: rfc9480.Extensions,
) -> PublicKey:
    """Load a public key from the `AltPublicKeyInfo` extension.

    Arguments:
    ---------
        - `extensions`: The extensions to load the public key from.

    Returns:
    -------
        - The loaded public key.

    Raises:
    ------
        - `ValueError`: If the extension is not found.
        - `ValueError`: If the public key cannot be loaded.
        - `BadAsn1Data`: If the extension contains remainder data.

    Examples:
    --------
    | ${public_key}= | Load Catalyst Public Key | ${extensions} |

    """
    extn_alt_spki = certextractutils.get_extension(extensions, id_ce_subjectAltPublicKeyInfo)
    if extn_alt_spki is None:
        raise ValueError("AltPublicKeyInfo extension not found.")

    spki, rest = decoder.decode(extn_alt_spki["extnValue"].asOctets(), SubjectAltPublicKeyInfoExt())
    if rest:
        raise BadAsn1Data("The alternative public key extension contains remainder data.", overwrite=True)
    alt_issuer_key = keyutils.load_public_key_from_spki(spki)
    return alt_issuer_key


@keyword(name="Sign CRL Catalyst")
def sign_crl_catalyst(  # noqa: D417 Missing a parameter in the Docstring
    crl: rfc5280.CertificateList,
    ca_private_key: PrivateKeySig,
    alt_private_key: Optional[PrivateKeySig] = None,
    include_alt_public_key: bool = False,
    hash_alg: str = "sha256",
    alt_hash_alg: Optional[str] = None,
    use_pre_hash: bool = False,
    use_rsa_pss: bool = False,
    critical: bool = False,
    bad_sig: bool = False,
    bad_alt_sig: bool = False,
) -> rfc5280.CertificateList:
    """Sign a CRL with a CA certificate and private key.

    Can also be used to sign the CRL with an alternative key.

    Arguments:
    ---------
       - `crl`: The CRL to sign.
       - `ca_private_key`: The CA private key to use for signing.
       - `alt_private_key`: An alternative private key to use for signing. Defaults to `None`.
       - `include_alt_public_key`: Whether to include the alternative public key in the CRL extensions.
            Defaults to `False`.
       - `hash_alg`: The hash algorithm to use. Defaults to "sha256".
       - `alt_hash_alg`: The hash algorithm to use for the alternative signature. Defaults to `None`.
       (if not provided, will use the same as `hash_alg`)
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `use_rsa_pss`: Whether to use RSA-PSS for signing. Defaults to `False`.
        - `critical`: Whether the extensions are critical. Defaults to `False`.
        - `bad_sig`: Whether to manipulate the signature to be invalid. Defaults to `False`.
        - `bad_alt_sig`: Whether to manipulate the alternative signature to be invalid. Defaults to `False`.

    Returns:
    -------
         - The signed CRL.

    Examples:
    --------
    | ${crl}= | Sign CRL Catalyst | ${crl} | ${ca_private_key} | ${alt_private_key} |
    | ${crl}= | Sign CRL Catalyst | ${crl} | ${ca_private_key} | ${alt_private_key} | include_alt_public_key=True |

    """
    crl["signatureAlgorithm"] = certbuildutils.prepare_sig_alg_id(
        signing_key=ca_private_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg, use_pre_hash=use_pre_hash
    )

    if alt_private_key is not None:
        extn = prepare_alt_sig_alg_id_extn(
            alg_id=None,
            hash_alg=alt_hash_alg or hash_alg,
            key=alt_private_key,
            use_pre_hash=use_pre_hash,
            use_rsa_pss=use_rsa_pss,
            critical=critical,
        )

        crl["tbsCertList"]["crlExtensions"].append(extn)
        if include_alt_public_key:
            extn = prepare_subject_alt_public_key_info_extn(
                key=alt_private_key.public_key(),
                critical=critical,
            )
            crl["tbsCertList"]["crlExtensions"].append(extn)

        data = encoder.encode(crl["tbsCertList"]) + encoder.encode(crl["signatureAlgorithm"])
        alt_sig_value = cryptoutils.sign_data(data=data, key=alt_private_key, hash_alg=alt_hash_alg or hash_alg)

        if bad_alt_sig:
            if isinstance(alt_private_key, AbstractCompositeSigPrivateKey):
                alt_sig_value = utils.manipulate_composite_sig(alt_sig_value)
            else:
                alt_sig_value = utils.manipulate_first_byte(alt_sig_value)

        alt_sig_ext = prepare_alt_signature_value_extn(signature=alt_sig_value, critical=critical)
        crl["tbsCertList"]["crlExtensions"].append(alt_sig_ext)

    crl_tbs = encoder.encode(crl["tbsCertList"])
    crl_signature = cryptoutils.sign_data(data=crl_tbs, key=ca_private_key, hash_alg=hash_alg)

    if bad_sig:
        if isinstance(ca_private_key, AbstractCompositeSigPrivateKey):
            crl_signature = utils.manipulate_composite_sig(crl_signature)
        else:
            crl_signature = utils.manipulate_first_byte(crl_signature)

    crl["signature"] = univ.BitString.fromOctetString(crl_signature)

    return crl
