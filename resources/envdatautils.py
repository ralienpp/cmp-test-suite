# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utilities for the CMP `EnvelopedData` structure to securely transport data."""

import logging
import os
from typing import List, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPublicKey
from pq_logic.migration_typing import HybridKEMPrivateKey, KEMPublicKey
from pq_logic.pq_utils import get_kem_oid_from_key, is_kem_public_key
from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import (
    rfc4055,
    rfc4211,
    rfc5280,
    rfc5652,
    rfc5753,
    rfc5958,
    rfc8018,
    rfc9480,
    rfc9481,
    rfc9629,
)
from robot.api.deco import keyword, not_keyword

from resources import certbuildutils, certextractutils, keyutils, utils
from resources.convertutils import copy_asn1_certificate, str_to_bytes
from resources.copyasn1utils import copy_name
from resources.cryptoutils import (
    compute_aes_cbc,
    compute_ansi_x9_63_kdf,
    compute_pbkdf2_from_parameter,
    perform_ecdh,
    sign_data,
)
from resources.oid_mapping import compute_hash, get_alg_oid_from_key_hash, sha_alg_name_to_oid
from resources.oidutils import KEY_WRAP_NAME_2_OID
from resources.prepareutils import prepare_name
from resources.protectionutils import (
    compute_kdf_from_alg_id,
    get_rsa_oaep_padding,
    prepare_kdf,
    prepare_pbkdf2_alg_id,
    prepare_wrap_alg_id,
)
from resources.typingutils import PrivateKey, PrivateKeySig, PublicKey


@not_keyword
def get_aes_length(alg_name: str) -> int:
    """Retrieve the AES key length in bits for the specified key wrap algorithm.

    :param alg_name: The name of the key wrap algorithm (e.g., "aes128-wrap", "aes192-wrap", "aes256-wrap").
    :return: The key length in bits corresponding to the specified algorithm.
    :raises ValueError: If the algorithm name is not recognized.
    """
    if alg_name not in KEY_WRAP_NAME_2_OID:
        raise ValueError(f"Unrecognized algorithm name: {alg_name}")

    if "128" in alg_name:
        return 16
    if "192" in alg_name:
        return 24
    if "256" in alg_name:
        return 32

    raise ValueError(f"Unable to determine key length for algorithm: {alg_name}")


@not_keyword
def prepare_encrypted_content_info(
    cek: bytes,
    data_to_protect: bytes,
    for_signed_data: bool = True,
    iv: Optional[bytes] = None,
    enc_oid: Optional[univ.ObjectIdentifier] = None,
) -> rfc5652.EncryptedContentInfo:
    """Create an `EncryptedContentInfo` with AES-CBC encryption for the signed data.

    This function prepares the `EncryptedContentInfo` structure, which holds the encrypted content
    in the `EnvelopedData` structure of a CMP message. It uses AES-CBC encryption with a fixed IV
    (for testing purposes) to encrypt the signed data using the provided content encryption key.

    :param cek: AES key for encrypting the signed data.
    :param data_to_protect: The signed data to encrypt.
    :param for_signed_data: If True, the content type is set to `id_signedData`. Defaults to True.
    :param iv: Optional initialization vector for AES-CBC encryption. Defaults to `None`.
    :param enc_oid: Optional Object Identifier for the content encryption algorithm. Defaults to `None`.
    :return: An `EncryptedContentInfo` containing the encrypted content.
    """
    if len(cek) == 32:
        oid = rfc9481.id_aes256_CBC
    elif len(cek) == 24:
        oid = rfc9481.id_aes192_CBC
    else:
        oid = rfc9481.id_aes128_CBC

    iv = iv or os.urandom(16)

    enc_content_info = rfc5652.EncryptedContentInfo()

    enc_oid = enc_oid or rfc5652.id_signedData if for_signed_data else rfc5652.id_encryptedData

    enc_content_info["contentType"] = enc_oid
    enc_content_info["contentEncryptionAlgorithm"]["algorithm"] = oid
    enc_content_info["contentEncryptionAlgorithm"]["parameters"] = encoder.encode(
        univ.OctetString(iv)
    )

    encrypted_content = compute_aes_cbc(decrypt=False, iv=iv, key=cek, data=data_to_protect)

    enc_content = rfc5652.EncryptedContent(encrypted_content).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )

    enc_content_info["encryptedContent"] = enc_content

    return enc_content_info


@not_keyword
def prepare_enveloped_data(
    recipient_infos: Union[rfc5652.RecipientInfo, List[rfc5652.RecipientInfo]],
    cek: bytes,
    data_to_protect: bytes,
    version: int = 2,
    target: Optional[rfc9480.EnvelopedData] = None,
    enc_oid: Optional[univ.ObjectIdentifier] = None,
) -> rfc5652.EnvelopedData:
    """Create an `EnvelopedData` structure with encrypted content and recipient information.

    The `EnvelopedData` structure is used in CMP messages to encapsulate encrypted content
    and the information needed by recipients to decrypt it. This function assembles the
    `EnvelopedData` structure by combining the encrypted content and recipient information.

    :param recipient_infos: List of recipient information structures, specifying how each
    recipient can decrypt the content.
    :param cek: AES key for encrypting the signed data.
    :param data_to_protect: The signed data to encrypt and include in the `EnvelopedData`.
    :param version: Version of the `EnvelopedData` structure. Defaults to 2.
    :param target: An optional `EnvelopedData` structure to populate. Defaults to `None`.
    :param enc_oid: Optional Object Identifier for the content encryption algorithm. Defaults to `None`.
    :return: An `EnvelopedData` containing the encrypted content and recipient info.
    """
    if target is None:
        target = rfc5652.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    target["version"] = version
    infos = rfc5652.RecipientInfos()
    if not isinstance(recipient_infos, (rfc5652.RecipientInfos, list)):
        recipient_infos = [recipient_infos]


    for recipient_info in recipient_infos:
        infos.append(_prepare_recip_info(recipient_info))


    target["encryptedContentInfo"] = prepare_encrypted_content_info(
        cek=cek, data_to_protect=data_to_protect, enc_oid=enc_oid
    )

    target["recipientInfos"] = infos

    return target


@keyword(name="Prepare Recipient Identifier")
def prepare_recipient_identifier(  # noqa D417 undocumented-param
    cert: Optional[rfc9480.CMPCertificate] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    ski: Optional[bytes] = None,
    key: Optional[PublicKey] = None,
    bad_ski: bool = False,
) -> rfc5652.RecipientIdentifier:
    """Prepare a RecipientIdentifier used for kari and ktri.

    Used to identify the certificate used for the key transport.

    Arguments:
    ---------
        - `cert`: A certificate to extract the identifier from. Defaults to `None`.
        - `issuer_and_ser`: An IssuerAndSerialNumber structure to use. Defaults to `None`.
        - `ski`: A Subject Key Identifier as bytes. Defaults to `None`.
        - `key`: A public key to compute the identifier from. Defaults to `None`.
        - `bad_ski`: If True, the Subject Key Identifier is modified. Defaults to `False`.

    Returns:
    -------
        - The populated `RecipientIdentifier` structure.

    Raises:
    ------
        - ValueError: If neither a certificate nor an issuer and serial number is provided or a key.

    """
    recip_id = rfc5652.RecipientIdentifier()

    if key is None and cert is None and issuer_and_ser is None and ski is None:
        raise ValueError("Either a certificate, an issuer and serial number, or a key must be provided.")

    if issuer_and_ser is not None:
        recip_id["issuerAndSerialNumber"] = issuer_and_ser
        return recip_id

    if key is not None:
        ski = x509.SubjectKeyIdentifier.from_public_key(key)

    elif cert is not None:
        ski = ski or certextractutils.get_field_from_certificate(cert, extension="ski")

    if bad_ski and ski is not None:
        ski = utils.manipulate_first_byte(ski)

    if ski is not None:
        recip_id["subjectKeyIdentifier"] = rfc5652.SubjectKeyIdentifier(ski).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
    else:
        recip_id["issuerAndSerialNumber"] = prepare_issuer_and_serial_number(cert)
    return recip_id


@keyword(name="Prepare IssuerAndSerialNumber")
def prepare_issuer_and_serial_number(
    cert: Optional[rfc9480.CMPCertificate] = None,
    modify_serial_number: bool = False,
    modify_issuer: bool = False,
    issuer: Optional[str] = None,
    serial_number: Optional[Union[str, int]] = None,
) -> rfc5652.IssuerAndSerialNumber:
    """Extract issuer and serial number from a certificate.

    Creates an `IssuerAndSerialNumber` structure, which uniquely identifies
    a certificate by its issuer's distinguished name and its serial number. It's used when
    the certificate lacks a SubjectKeyIdentifier extension.

    Arguments:
    ---------
        - `cert`: Certificate from which to extract the issuer and serial number.
        - `modify_serial_number`: If True, increment the serial number by 1. Defaults to `False`.
        - `modify_issuer`: If True, modify the issuer common name. Defaults to `False`.
        - `issuer`: The issuer's distinguished name to use. Defaults to `None`.
        - `serial_number`: The serial number to use. Defaults to `None`.

    Returns:
    -------
        - The populated `IssuerAndSerialNumber` structure.

    Raises:
    ------
        - ValueError: If neither a certificate nor an issuer and serial number is provided.

    Examples:
    --------
    | ${issuer_and_ser}= | Prepare IssuerAndSerialNumber | cert=${cert} | modify_serial_number=True |
    | ${issuer_and_ser}= | Prepare IssuerAndSerialNumber | issuer=${issuer} | serial_number=${serial_number} |

    """
    if cert is None and (issuer is None or serial_number is None):
        raise ValueError("Either a certificate or a issuer and serial number must be provided.")

    iss_ser_num = rfc5652.IssuerAndSerialNumber()

    if issuer:
        iss_ser_num["issuer"] = prepare_name(issuer)
    elif not modify_issuer:
        iss_ser_num["issuer"] = copy_name(rfc9480.Name(), cert["tbsCertificate"]["issuer"])
    else:
        data = certbuildutils.modify_common_name_cert(cert, issuer=True)
        iss_ser_num["issuer"] = prepare_name(data)

    if serial_number is None:
        serial_number = int(cert["tbsCertificate"]["serialNumber"])

    if modify_serial_number:
        serial_number += 1
    iss_ser_num["serialNumber"] = rfc5280.CertificateSerialNumber(serial_number)
    return iss_ser_num


@not_keyword
def prepare_signer_identifier(cert: rfc9480.CMPCertificate) -> rfc5652.SignerIdentifier:
    """Create a `SignerIdentifier` to identify the CMP protection certificate.

    Prepares the `SignerIdentifier` used in the `SignerInfo` structure
    to specify the certificate corresponding to the signing key (CMP protection certificate).
    It uses the SubjectKeyIdentifier extension if present; otherwise, it falls back to
    using the issuer and serial number.

    :param cert: Certificate to derive the identifier from (CMP protection certificate).
    :return: A `SignerIdentifier` structure identifying the signer.
    """
    ski = certextractutils.get_field_from_certificate(cert, extension="ski")
    sid = rfc5652.SignerIdentifier()
    if ski is not None:
        val = rfc5652.SubjectKeyIdentifier(ski).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        sid["subjectKeyIdentifier"] = val
    else:
        sid["issuerAndSerialNumber"] = prepare_issuer_and_serial_number(cert)

    return sid


def prepare_signed_attributes(message_digest: bytes) -> rfc5652.SignedAttributes:
    """Create `SignedAttributes` with content type and message digest.

    The `SignedAttributes` structure includes attributes that are signed along with the content.
    This function prepares the mandatory attributes: content type and message digest, which are
    necessary for signature verification in CMP.

    :param message_digest: Digest of the content to be signed.
    :return: A `SignedAttributes` structure containing the necessary attributes.
    """
    signed_attrs = rfc5652.SignedAttributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    attr_content_type = rfc5652.Attribute()
    attr_content_type.setComponentByName("attrType", rfc5652.id_contentType)
    # must be set like this.
    attr_content_type.setComponentByName(
        "attrValues", univ.SetOf().setComponentByPosition(0, rfc5958.id_ct_KP_aKeyPackage)
    )

    attr_msg_dig = rfc5652.Attribute()
    attr_msg_dig.setComponentByName("attrType", rfc5652.id_messageDigest)
    # must be set like this.
    attr_msg_dig.setComponentByName(
        "attrValues", univ.SetOf().setComponentByPosition(0, univ.OctetString(message_digest))
    )

    signed_attrs.setComponentByPosition(0, attr_content_type)
    signed_attrs.setComponentByPosition(1, attr_msg_dig)

    signed_attrs2 = rfc5652.SignedAttributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    der_data = encoder.encode(signed_attrs)
    data, rest = decoder.decode(der_data, signed_attrs2)
    if rest != b"":
        raise ValueError("The decoding of the SignedAttributes failed")

    return data


@not_keyword
def prepare_encapsulated_content_info(content: bytes, override_oid: bool = False) -> rfc5652.EncapsulatedContentInfo:
    """Create an `EncapsulatedContentInfo` with the provided content.

    The `EncapsulatedContentInfo` structure wraps the content that is to be signed or encrypted.
    This function prepares this structure with the specified content type and the actual content.

    :param content: Content data to encapsulate.
    :param override_oid: If True, use an alternate OID for negative testing (e.g., to simulate errors).
    Which is `id_at_commonName`. Defaults to False. The correct OID is `id_ct_KP_aKeyPackage`.
    :return: An `EncapsulatedContentInfo` structure containing the content.
    """
    encap_content_info = rfc5652.EncapsulatedContentInfo()
    encap_content_info["eContentType"] = rfc5958.id_ct_KP_aKeyPackage if not override_oid else rfc5280.id_at_commonName
    econtent = univ.OctetString(content).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    encap_content_info["eContent"] = econtent

    return encap_content_info

# TODO fix for composite-sig-key,
# fix for pq-keys
def prepare_signer_info(
    signing_key: PrivateKeySig,
    cert: rfc9480.CMPCertificate,
    e_content: bytes,
    sig_hash_name: str,
    digest_hash_name: Optional[str] = None,
    bad_sig: bool = False,
    version: int = 3,
) -> rfc5652.SignerInfo:
    """Create a `SignerInfo` structure for signing content.

    The `SignerInfo` structure provides information about the signer and the signature.
    This function prepares the `SignerInfo`, including setting the appropriate version,
    digest algorithm, signature algorithm, and signed attributes. It also generates the
    signature over the encapsulated content.

    :param signing_key: Private key used for signing.
    :param cert: Certificate corresponding to the signing key (CMP protection certificate).
    :param e_content: Content to sign (typically the DER-encoded `EncapsulatedContentInfo`).
    :param sig_hash_name: Hash algorithm for signature (e.g., "sha256").
    :param digest_hash_name: Hash algorithm for digest calculation. Defaults to `sig_hash_name`.
    :param bad_sig: Whether to modify the signature of the signed_info. Defaults to `False`.
    `EncapsulatedContentInfo` inside the `SignerInfo` structure.  Defaults to False.
    :param version: The CMSVersion for the structure.
    :return: A `SignerInfo` structure ready to be included in `SignedData`.
    """
    digest_hash_name = digest_hash_name or sig_hash_name
    message_digest = compute_hash(digest_hash_name, e_content)

    # Prepare signature and digest algorithm identifiers
    sig_alg_id = rfc5652.SignatureAlgorithmIdentifier()
    sig_alg_id["algorithm"] = get_alg_oid_from_key_hash(signing_key, hash_alg=sig_hash_name)

    dig_alg_id = rfc5652.DigestAlgorithmIdentifier()
    dig_alg_id["algorithm"] = sha_alg_name_to_oid(digest_hash_name)

    # Create SignerInfo structure
    signer_info = rfc5652.SignerInfo()
    signer_info["version"] = version
    signer_info["digestAlgorithm"] = dig_alg_id
    signer_info["signatureAlgorithm"] = sig_alg_id
    signer_info["signedAttrs"] = prepare_signed_attributes(message_digest)
    signer_info["sid"] = prepare_signer_identifier(cert)

    # Generate signature over the signed attributes
    encap_content_info = prepare_encapsulated_content_info(e_content)
    der_encap_content_info = encoder.encode(encap_content_info)

    signature = sign_data(der_encap_content_info, signing_key, sig_hash_name)
    signature += b"" if not bad_sig else b"AA"
    signer_info["signature"] = univ.OctetString(signature)

    return signer_info


def prepare_signer_infos(
    signing_key: PrivateKeySig,
    cert: rfc9480.CMPCertificate,
    e_content: bytes,
    sig_hash_name: str,
    digest_hash_name: Optional[str] = None,
    add_another: bool = False,
    negative_signature: bool = False,
) -> rfc5652.SignerInfos:
    """Create a `SignerInfos` set with one or more `SignerInfo` entries.

    The `SignerInfos` structure is a set of `SignerInfo` entries. This function prepares
    this structure, optionally adding multiple `SignerInfo` entries for negative testing.

    :param signing_key: Private key used for signing.
    :param cert: Certificate corresponding to the signing key (CMP protection certificate).
    :param e_content: Content to sign.
    :param sig_hash_name: Hash algorithm for signature.
    :param digest_hash_name: Hash algorithm for digest calculation. Defaults to `sig_hash_name`.
    :param add_another: If `True`, add another `SignerInfo` for negative testing.
    :param negative_signature: A boolean flag that, if True, modifies the signature of the signed_info.
    `EncapsulatedContentInfo` inside the `SignerInfo` structure.  Defaults to False.
    :return: A `SignerInfos` structure containing one or more `SignerInfo` entries.
    """
    signer_infos = rfc5652.SignerInfos()
    signer_info = prepare_signer_info(
        signing_key=signing_key,
        cert=cert,
        e_content=e_content,
        digest_hash_name=digest_hash_name,
        sig_hash_name=sig_hash_name,
        bad_sig=negative_signature,
    )
    signer_infos.append(signer_info)

    if add_another:
        signer_infos.append(signer_info)

    return signer_infos


def prepare_certificates_for_kga(certs: List[rfc9480.CMPCertificate]) -> rfc5652.CertificateSet:
    """Prepare a `CertificateSet` for a list of certificates.

    Constructs a `CertificateSet` containing multiple certificates, enabling
    recipient systems to verify that the certificate identifying the KGA is trusted and
    allow to generate a private key for us.

    :param certs: List of certificates to include (e.g., KGA certificate chain).
    :return: The populated `CertificateSet` structure, with the correct tagging.
    """
    certificates = rfc5652.CertificateSet().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    for cert in certs:
        new_cert = rfc5652.CertificateChoices()
        new_cert["certificate"] = copy_asn1_certificate(cert)
        certificates.append(new_cert)

    return certificates


def prepare_signed_data(
    signing_key: ec.EllipticCurvePrivateKey,
    cert: rfc9480.CMPCertificate,
    sig_hash_name: str,
    e_content: Optional[bytes] = None,
    digest_hash_name: Optional[str] = None,
    negative_signature: bool = False,
    cert_chain: Optional[List[rfc9480.CMPCertificate]] = None,
    private_keys: Optional[List[PrivateKey]] = None,
) -> rfc5652.SignedData:
    """Prepare a `SignedData` structure for the provided content, key, and certificate.

    Creates `SignedData` structure as defined in RFC 5652, including digest
    algorithm identifiers, encapsulated content, certificates, and signer information.

    :param e_content: The content to be signed, provided as a byte string.
    :param signing_key: The private key used for signing.
    :param cert: A `CMPCertificate` object used for KGA.
    :param sig_hash_name: The hash algorithm name to use for signing.
    :param digest_hash_name: The hash algorithm name to use for digest calculation. Defaults to `sig_hash_name`.
    :param negative_signature: A boolean flag that, if True, modifies the signature of the signed_info.
    `EncapsulatedContentInfo` inside the `SignerInfo` structure.  Defaults to False.
    :param cert_chain: Optional The certificate chain of the KGA `CMPCertificate`. Defaults to cert.
    :param private_keys: A list of private keys to parse inside the asymmetric key package structure.
    :return: The populated `SignedData` structure.
    """
    if e_content is None and private_keys is None:
        raise ValueError("Either `e_content` or `private_keys` must be provided.")

    digest_hash_name = digest_hash_name or sig_hash_name

    if private_keys is not None:
        # Generate content from private keys if provided
        e_content = encoder.encode(prepare_asymmetric_key_package(private_keys))

    encap_content_info = prepare_encapsulated_content_info(e_content)

    signed_data = rfc5652.SignedData()
    signed_data["version"] = 3

    digest_alg_set = rfc5652.DigestAlgorithmIdentifiers()
    digest_alg_id = rfc5652.DigestAlgorithmIdentifier()
    digest_alg_id["algorithm"] = sha_alg_name_to_oid(digest_hash_name)
    digest_alg_set.append(digest_alg_id)
    signed_data["digestAlgorithms"] = digest_alg_set

    # pyasn1-alt-modules automatically re-orders them after decoding.
    # print_chain_subject_and_issuer([cert["certificate"] for cert in certs])
    signed_data["certificates"] = prepare_certificates_for_kga(cert_chain or [cert])

    signed_data["encapContentInfo"] = encap_content_info
    signed_data["signerInfos"] = prepare_signer_infos(
        signing_key=signing_key,
        cert=cert,
        e_content=e_content,
        sig_hash_name=sig_hash_name,
        digest_hash_name=digest_hash_name,
        add_another=False,
        negative_signature=negative_signature,
    )

    # to show the different order after decoding
    # print_chain_subject_and_issuer([cert["certificate"] for cert in data["certificates"]])
    return signed_data


def prepare_asymmetric_key_package(
    private_keys: List[PrivateKey],
) -> rfc5958.AsymmetricKeyPackage:
    """Create an `AsymmetricKeyPackage` containing private keys.

    The `AsymmetricKeyPackage` structure is used to transport private keys securely.
    This function prepares the package by including the provided private keys.

    :param private_keys: List of private keys to include (e.g., newly generated keys).
    :return: An `AsymmetricKeyPackage` structure containing the private keys.
    """
    asym_key_package = rfc5958.AsymmetricKeyPackage()
    for key in private_keys:
        asym_key_package.append(prepare_one_asymmetric_key(private_key=key))
    return asym_key_package


def prepare_one_asymmetric_key(
    private_key,
    version: str = "v2",
) -> rfc5958.OneAsymmetricKey:
    """Create a `OneAsymmetricKey` structure for a private key.

    Wraps a private key into the `OneAsymmetricKey` structure,
    including the algorithm identifier and the public key. It's used when
    preparing an `AsymmetricKeyPackage`.

    :param private_key: Private key to include.
    :param version: Version of the structure. Defaults to "v2".
    :return: A `OneAsymmetricKey` structure containing the private key.
    """
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    if int(rfc5958.Version(version)) == 0:
        one_asym_key, _ = decoder.decode(private_key_bytes, asn1Spec=rfc4211.PrivateKeyInfo())
        return private_key_bytes

    one_asym_key, _ = decoder.decode(private_key_bytes, asn1Spec=rfc5958.OneAsymmetricKey())
    one_asym_key["version"] = rfc5958.Version(version)

    if isinstance(private_key, rsa.RSAPrivateKey):
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1
        )
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
        )
    else:
        public_key_bytes = private_key.public_key().public_bytes_raw()

    public_key_bit_str = (
        rfc5958.PublicKey()
        .fromOctetString(public_key_bytes)
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
    )
    one_asym_key["publicKey"] = public_key_bit_str

    return one_asym_key


def _get_rsa_kari_alg_id(use_rsa_oaep: bool) -> rfc5652.KeyEncryptionAlgorithmIdentifier:
    """Prepare the KeyEncryptionAlgorithmIdentifier based on whether RSA-OAEP is used.

    :param use_rsa_oaep: Boolean indicating whether to use RSA-OAEP or RSA PKCS#1 v1.5.
    :return: A KeyEncryptionAlgorithmIdentifier object configured accordingly.
    """
    key_enc_alg_oaep = rfc5652.KeyEncryptionAlgorithmIdentifier()
    if not use_rsa_oaep:
        key_enc_alg_oaep["algorithm"] = rfc9481.rsaEncryption
        return key_enc_alg_oaep

    oaep_params = rfc4055.RSAES_OAEP_params()
    oaep_params["hashFunc"]["algorithm"] = rfc4055.id_sha384
    oaep_params["maskGenFunc"]["algorithm"] = rfc4055.id_mgf1
    oaep_params["maskGenFunc"]["parameters"] = encoder.encode(rfc4055.id_sha256)

    key_enc_alg_oaep["algorithm"] = rfc4055.id_RSAES_OAEP
    key_enc_alg_oaep["parameters"] = oaep_params
    return key_enc_alg_oaep


def _encrypt_rsa_oaep(key: rsa.RSAPublicKey, alg_id: rfc5280.AlgorithmIdentifier, content_enc_key):
    """Encrypt the content encryption key using RSA encryption with specified padding.

    :param key: The RSA private key used for encryption.
    :param alg_id: The AlgorithmIdentifier specifying the encryption algorithm and parameters.
    :param content_enc_key: The content encryption key to be encrypted.
    :return: The encrypted content encryption key.
    """
    if alg_id["parameters"].isValue:
        padding_val = get_rsa_oaep_padding(alg_id["parameters"])
    else:
        padding_val = padding.PKCS1v15()

    return key.encrypt(plaintext=content_enc_key, padding=padding_val)


@not_keyword
def prepare_ktri(
    ee_key: rsa.RSAPublicKey,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate],
    cek: bytes,
    use_rsa_oaep: bool = True,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
) -> rfc5652.RecipientInfo:
    """Prepare a KeyTransRecipientInfo object for testing.

    :param ee_key: The RSA public key of the end entity.
    :param cmp_protection_cert: The certificate of the server.
    :param cek: The content encryption key to be encrypted.
    :param use_rsa_oaep: Boolean indicating whether to use RSA-OAEP or RSA PKCS#1 v1.5 padding.
    :param issuer_and_ser: The `IssuerAndSerialNumber` structure to use. Defaults to None.
    :param rid: The `RecipientIdentifier` structure to use. Defaults to `None`.
    :return: A RecipientInfo object containing the KeyTransRecipientInfo.
    """
    if isinstance(ee_key, rsa.RSAPublicKey):
        key_enc_alg_id = _get_rsa_kari_alg_id(use_rsa_oaep=use_rsa_oaep)
        encrypted_key = _encrypt_rsa_oaep(key=ee_key, alg_id=key_enc_alg_id, content_enc_key=cek)
    else:
        raise ValueError(f"Unsupported key type: {type(ee_key)}")

    # Version MUST be 2 for KTRI.
    ktri = prepare_key_transport_recipient_info(
        version=2,
        key_enc_alg_id=key_enc_alg_id,
        cert=cmp_protection_cert,
        encrypted_key=encrypted_key,
        issuer_and_ser=issuer_and_ser,
        rid=rid,
    )

    return _prepare_recip_info(ktri)

@not_keyword
def prepare_key_transport_recipient_info(
    version: int = 2,
    key_enc_alg_oid: univ.ObjectIdentifier = rfc9481.id_RSAES_OAEP,
    encrypted_key: Optional[bytes] = None,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
    key_enc_alg_id: Optional[rfc5280.AlgorithmIdentifier] = None,
    **kwargs,
) -> rfc5652.KeyTransRecipientInfo:
    """Create a `KeyTransRecipientInfo` structure for key transport encryption.

    The `KeyTransRecipientInfo` structure is used in CMS `EnvelopedData` to specify
    a recipient that uses key transport algorithms (e.g., RSA) to decrypt the content encryption key.
    This function prepares this structure by setting the recipient identifier and key encryption algorithm,
    which are necessary for the recipient to recover the content encryption key.

    :param version: Version of the CMS structure. Defaults to 2.
    :param key_enc_alg_oid: OID for the key encryption algorithm. Defaults to RSAES-OAEP.
    :param encrypted_key: Encrypted key material (the content encryption key encrypted with the recipient's public key).
    :param cmp_protection_cert: Certificate to extract the recipient identifier from. Used to set the `rid` if provided.
    are not provided. Defaults to `None`.
    :param rid: `RecipientIdentifier` structure. If provided, `cert`, `ski`, and `issuer_and_ser` are ignored.
    Defaults to `None`.
    :param key_enc_alg_id: `AlgorithmIdentifier` for the key encryption algorithm. If provided,
    `key_enc_alg_oid` is ignored.
    :return: A `KeyTransRecipientInfo` structure ready to be included in `RecipientInfo`.
    """
    ktri_structure = rfc5652.KeyTransRecipientInfo()
    ktri_structure["version"] = rfc5652.CMSVersion(version)

    rid = rid or prepare_recipient_identifier(cert=cmp_protection_cert,
                                              issuer_and_ser=kwargs.get("issuer_and_ser"),
                                              ski=kwargs.get("ski"),
                                              bad_ski=kwargs.get("bad_ski"),
                                              )

    ktri_structure["rid"] = rid

    if key_enc_alg_id is not None:
        # Ensure that parameters are properly encoded
        key_enc_alg_id, _ = decoder.decode(encoder.encode(key_enc_alg_id), asn1Spec=rfc5280.AlgorithmIdentifier())
        ktri_structure["keyEncryptionAlgorithm"] = key_enc_alg_id
    else:
        alg_id = rfc5652.KeyEncryptionAlgorithmIdentifier()
        alg_id["algorithm"] = key_enc_alg_oid
        ktri_structure["keyEncryptionAlgorithm"] = alg_id

    if encrypted_key is not None:
        ktri_structure["encryptedKey"] = rfc5652.EncryptedKey(encrypted_key)

    return ktri_structure


# TODO refactor to remove issuer_and_ser
def prepare_kari(
    public_key: ECDHPublicKey,
    recip_private_key: ECDHPrivateKey,
    cek: Optional[bytes] = None,
    recip_cert: Optional[rfc9480.CMPCertificate] = None,
    hash_alg: str = "sha256",
    issuer_and_ser: rfc5652.IssuerAndSerialNumber = None,
    oid: univ.ObjectIdentifier = rfc9481.dhSinglePass_stdDH_sha256kdf_scheme,
) -> rfc5652.KeyAgreeRecipientInfo:
    """Prepare a KeyAgreeRecipientInfo object for testing.

    :param public_key: The public key of the recipient.
    :param recip_private_key: The private key of the sender.
    :param cek: The content encryption key to be encrypted.
    :param recip_cert: The certificate of the recipient.
    :param hash_alg: The hash algorithm to use for key derivation.
    :param issuer_and_ser: The optional `IssuerAndSerialNumber` structure to use. Defaults to None.
    :param oid: The Object Identifier for the key agreement algorithm.
    Defaults to dhSinglePass-stdDH-sha256kdf-scheme.
    :return: The populated `KeyAgreeRecipientInfo` structure.
    """
    ecc_cms_info = encoder.encode(
        prepare_ecc_cms_shared_info(key_wrap_oid=rfc9481.id_aes256_wrap, entity_u_info=None, supp_pub_info=32)
    )

    # TODO fix for other oids.

    shared_secret = perform_ecdh(recip_private_key, public_key)
    k = compute_ansi_x9_63_kdf(shared_secret, 32, ecc_cms_info, hash_alg=hash_alg)
    encrypted_key = aes_key_wrap(key_to_wrap=cek, wrapping_key=k)

    # Version MUST be 3 for KARI.
    kari = prepare_key_agreement_recipient_info(
        version=3,
        cmp_cert=recip_cert,
        encrypted_key=encrypted_key,
        key_agreement_oid=oid,
        ecc_cms_info=ecc_cms_info,
        issuer_and_ser=issuer_and_ser,
    )

    return kari


def _prepare_recip_info(
    info_obj: Union[
        rfc5652.KeyAgreeRecipientInfo,
        rfc9629.KEMRecipientInfo,
        rfc5652.KeyTransRecipientInfo,
        rfc5652.PasswordRecipientInfo,
        rfc5652.RecipientInfo,
    ],
) -> rfc5652.RecipientInfo:
    """Prepare a RecipientInfo object with the underlying populated structure.

    :param info_obj: The structure to set. (e.g, `KeyAgreeRecipientInfo` or `KEMRecipientInfo`)
    :return: The populated `RecipientInfo` object.
    """
    recip_info = rfc5652.RecipientInfo()

    if isinstance(info_obj, rfc5652.RecipientInfo):
        return info_obj

    if isinstance(info_obj, rfc5652.KeyAgreeRecipientInfo):
        recip_info.setComponentByName("kari", info_obj)

    elif isinstance(info_obj, rfc9629.KEMRecipientInfo):
        ori = rfc5652.OtherRecipientInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)
        )

        ori["oriType"] = rfc9629.id_ori_kem
        ori["oriValue"] = info_obj
        recip_info["ori"] = ori

    elif isinstance(info_obj, rfc5652.KeyTransRecipientInfo):
        recip_info.setComponentByName("ktri", info_obj)

    elif isinstance(info_obj, rfc5652.PasswordRecipientInfo):
        recip_info.setComponentByName("pwri", info_obj)

    else:
        raise ValueError(f"Unsupported recipient info object: {type(info_obj)}")

    return recip_info


@keyword(name="Prepare RecipientInfo")
def prepare_recip_info(
    public_key_recip: Optional[PublicKey],
    private_key: Optional[ECDHPrivateKey] = None,
    cert_recip: Optional[rfc9480.CMPCertificate] = None,
    password: Optional[Union[str, bytes]] = None,
    cek: Optional[Union[bytes, str]] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
    use_rsa_oaep: bool = True,
    salt: Optional[Union[bytes, str]] = None,
    kdf_name: Optional[str] = "pbkdf2",
) -> rfc5652.RecipientInfo:
    """Prepare the appropriate RecipientInfo structure based on the type of the recipient's public key.

    Arguments:
    ---------
        - `public_key_recip`: The public key of the recipient.
        - `private_key`: The private key for key agreement (EC), if required.
        - `cert_recip`: The sender's certificate (used in some KEM flows or RSA).
        (For KEMRI is it the certificate of the recipient, For KARI, KTRI the CMP protection certificate).
        - `cek`: The content encryption key (32 random bytes if not supplied).
        - `issuer_and_ser`: IssuerAndSerialNumber structure.
        - `password`: The password for the password recipient info structure.
        - `use_rsa_oaep`: Whether to use RSA OAEP (True) or PKCS#1 v1.5 (False).
        - `salt`: The salt value for the PasswordRecipientInfo structure. Defaults to 32 random bytes.
        (can be used for negative testing, by setting to same value for CMP-protection-salt (MAC-protection)).
        - `kdf_name`: The key derivation function to use for the PasswordRecipientInfo or KEMRecipientInfo structure.
        Defaults to "pbkdf2".
        (which is the only allowed for PasswordRecipientInfo,).

    Returns:
    -------
        - The populated `RecipientInfo` structure.

    Raises:
    ------
        - ValueError: If the public key type is not supported.
        - ValueError: If a password is not provided for the password recipient info structure.
        - ValueError: If The ECDH private key was not provided for EC key exchange.
        - ValueError: If neither a certificate nor an issuer and serial number is provided.

    """
    if cek is None:
        cek = os.urandom(32)
    cek = str_to_bytes(cek)

    if isinstance(public_key_recip, rsa.RSAPublicKey):
        return prepare_ktri(
            ee_key=public_key_recip,
            cmp_protection_cert=cert_recip,
            cek=cek,
            use_rsa_oaep=use_rsa_oaep,
            issuer_and_ser=issuer_and_ser,
            rid=rid,
        )

    if isinstance(public_key_recip, ec.EllipticCurvePublicKey):
        if private_key is None:
            raise ValueError("An ECDH private key must be provided for EC key exchange.")
        kari = prepare_kari(
            public_key=public_key_recip,
            recip_private_key=private_key,
            issuer_and_ser=issuer_and_ser,
            cek=cek,
            recip_cert=cert_recip,
        )
        return _prepare_recip_info(kari)

    if is_kem_public_key(
        public_key_recip,
    ):
        kem_recip_info = prepare_kem_recip_info(
            recip_cert=cert_recip,
            public_key_recip=public_key_recip,
            cek=cek,
            rid=rid,
            issuer_and_ser=issuer_and_ser,
            kdf_name=kdf_name,
        )
        return _prepare_recip_info(kem_recip_info)

    if password is None and public_key_recip is None:
        raise ValueError(
            "A password must be provided for password recipient info structure, or a public key"
            "for key agreement or key transport recipient info structure, or KEM recipient info."
        )

    if password is not None:
        pwri = prepare_password_recipient_info(password=password, cek=cek, salt=salt, kdf_name=kdf_name)
        return _prepare_recip_info(pwri)

    raise ValueError(f"Unsupported public key type: {type(public_key_recip)}")


@keyword(name="Prepare EncryptedKey For POPO")
def prepare_enc_key_for_popo(
    enc_key_with_id: rfc4211.EncKeyWithID,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    recip_info: Optional[rfc5652.RecipientInfo] = None,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
    for_agreement: bool = None,
    version: Optional[int] = None,
    cek: Optional[bytes] = None,
    private_key: Optional[ECDHPrivateKey] = None,
) -> rfc4211.ProofOfPossession:
    """Prepare an EncKeyWithID structure for the `ProofOfPossession` structure.

    Used to prove the possession of a private key by sending the encrypted key to the CA/RA.

    Note:
    ----
       - For `KTRI` and `KARI`, the rid field must be set to the CMP protection certificate.


    Arguments:
    ---------
        - `enc_key_with_id`: The EncKeyWithID structure to include.
        - `ca_cert`: The CA certificate to use for encryption.
        - `recip_info`: The recipient information structure to include. Which is used to encrypt the CEK.
        - `for_agreement`: Whether the Proof-of-Possession is for a key agreement (True) or key encipherment (False).
        - `version`: The version of the EnvelopedData structure. If None, it is set based on the recipient info.
        - `cek`: The content encryption key to use. Defaults to 32 random bytes.
        - `private_key`: The private key used for key agreement. Defaults to `None`.

    Returns:
    -------
        - The populated `ProofOfPossession` structure.

    """
    if version is None:
        version = 0 if recip_info.getName() in ["ori", "pwri"] else 2

    cek = cek or os.urandom(32)
    env_data = rfc9480.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))

    if recip_info is None:
        recip_info = prepare_recip_info(
            public_key_recip=None,
            private_key=private_key,
            cek=cek,
            cert_recip=ca_cert,
            rid=rid,
        )

    env_data = prepare_enveloped_data(
        cek=cek,
        recipient_infos=recip_info,
        target=env_data,
        enc_oid=rfc4211.id_ct_encKeyWithID,
        version=version,
        data_to_protect=encoder.encode(enc_key_with_id),
    )

    if not for_agreement:
        index = 2
        option = "keyEncipherment"
    else:
        index = 3
        option = "keyAgreement"

    popo_priv_key = rfc4211.POPOPrivKey().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, index)
    )
    popo_priv_key["encryptedKey"] = env_data

    popo_structure = rfc4211.ProofOfPossession()
    popo_structure[option] = popo_priv_key

    return popo_structure


@not_keyword
def build_env_data_for_exchange(
    public_key_recip: PublicKey,
    data: bytes,
    private_key: Optional[ECDHPrivateKey] = None,
    cert_sender: Optional[rfc9480.CMPCertificate] = None,
    cek: Optional[Union[str, bytes]] = None,
    target: Optional[rfc9480.EnvelopedData] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    use_rsa_oaep: bool = True,
    enc_oid: Optional[univ.ObjectIdentifier] = None,
    hybrid_key_recip: Optional[AbstractHybridRawPublicKey] = None,
) -> rfc9480.EnvelopedData:
    """Build an EnvelopedData structure for the provided public key and data.

    Prepare an EnvelopedData structure for the provided public key and data.
    The EnvelopedData structure is used in CMP messages to securely transport encrypted content.

    :param public_key_recip: The public key of the recipient.
    :param data: The data to be encrypted.
    :param private_key: The private key used for key agreement.
    :param cert_sender: The certificate of the sender.
    :param cek: The content encryption key to use. Defaults to 32 random bytes.
    :param target: An optional `EnvelopedData` structure to populate. Defaults to None.
    :param use_rsa_oaep: Boolean indicating whether to use RSA-OAEP or RSA PKCS#1 v1.5 padding.
    :param issuer_and_ser: An optional `IssuerAndSerialNumber` structure to use. Defaults to `None`.
    :param enc_oid: The OID for the content type. Defaults to `None`.
    :param hybrid_key_recip: The hybrid key recipient to use for encryption. Defaults to None.
    :return: The populated `EnvelopedData` structure.
    """
    if cek is None:
        cek = os.urandom(32)

    cek = str_to_bytes(cek)

    if isinstance(public_key_recip, rsa.RSAPublicKey):
        kari = prepare_ktri(
            ee_key=public_key_recip,
            cmp_protection_cert=cert_sender,
            cek=cek,
            use_rsa_oaep=use_rsa_oaep,
            issuer_and_ser=issuer_and_ser,
        )
        return prepare_enveloped_data(
            recipient_infos=[kari], cek=cek, target=target, data_to_protect=data, enc_oid=enc_oid
        )

    if isinstance(public_key_recip, ECDHPublicKey):
        if private_key is None or not isinstance(private_key, ECDHPrivateKey):
            raise ValueError("Private key must be provided for EC key exchange.")

        kari = prepare_kari(
            public_key=public_key_recip,
            recip_private_key=private_key,
            issuer_and_ser=issuer_and_ser,
            cek=cek,
            recip_cert=cert_sender,
        )
        kari = _prepare_recip_info(kari)
        return prepare_enveloped_data(
            recipient_infos=[kari], cek=cek, target=target, data_to_protect=data, enc_oid=enc_oid
        )

    if is_kem_public_key(public_key_recip):
        kem_recip_info = prepare_kem_recip_info(
            recip_cert=cert_sender,
            public_key_recip=public_key_recip,
            cek=cek,
            issuer_and_ser=issuer_and_ser,
            hybrid_key_recip=hybrid_key_recip,
        )
        kem_recip_info = _prepare_recip_info(kem_recip_info)
        return prepare_enveloped_data(
            recipient_infos=[kem_recip_info], cek=cek, target=target, data_to_protect=data, enc_oid=enc_oid
        )

    raise ValueError(f"Unsupported public key type: {type(public_key_recip)}")


def prepare_kem_recip_info(
    version: int = 0,
    rid: Optional[rfc5652.RecipientIdentifier] = None,
    recip_cert: Optional[rfc9480.CMPCertificate] = None,
    public_key_recip: Optional[KEMPublicKey] = None,
    kdf_name: str = "hkdf",
    ukm: Optional[bytes] = None,
    cek: Optional[Union[bytes, str]] = None,
    hash_alg: str = "sha256",
    wrap_name: str = "aes256-wrap",
    encrypted_key: Optional[bytes] = None,
    kek_length: Optional[int] = None,
    kemct: Optional[bytes] = None,
    hybrid_key_recip: Optional[HybridKEMPrivateKey] = None,
    shared_secret: Optional[bytes] = None,
    kem_oid: Optional[univ.ObjectIdentifier] = None,
    **kwargs,
) -> rfc9629.KEMRecipientInfo:
    """Prepare a KEMRecipientInfo structure.

    Either with provided values or by deriving them from encapsulation and encryption mechanisms.

    :param version: The version number. Defaults to 0.
    :param rid: Recipient Identifier. Defaults to None.
    :param recip_cert: Server certificate containing the server's public key. Defaults to None.
    :param public_key_recip: Public key of the recipient. Defaults to None.
    :param kdf_name: The name of the key derivation function. Defaults to "hkdf".
    :param ukm: User keying material, used as salt. Defaults to a random 32 bytes.
    :param cek: Content Encryption Key to encrypt. Defaults to a random 32 bytes.
    :param hash_alg: Hash algorithm for HKDF. Defaults to "sha256".
    :param wrap_name: Key wrap algorithm name. Defaults to "aes256-wrap".
    :param encrypted_key: Pre-encrypted key. Defaults to None.
    :param kek_length: Length of the KEK in bytes. Defaults to None.
    :param kemct: KEM ciphertext. Defaults to None.
    :param hybrid_key_recip: The hybrid key recipient to use for encryption. Defaults to None.
    :param shared_secret: The shared secret to use for key derivation. Defaults to None.
    :param kem_oid: The Object Identifier for the KEM algorithm. Defaults to None.
    :return: A populated `KEMRecipientInfo` structure.
    :raises ValueError: If neither kemct nor (ee_private_key and server_cert) are provided.
    """
    key_enc_key = None

    rid = rid or prepare_recipient_identifier(cert=recip_cert,
                                              issuer_and_ser=kwargs.get("issuer_and_ser"),
                                              ski=kwargs.get("ski"),
                                              bad_ski=kwargs.get("bad_ski"),
                                              )
    cek = str_to_bytes(cek or os.urandom(32))

    kem_recip_info = rfc9629.KEMRecipientInfo()
    kem_recip_info["version"] = univ.Integer(version)
    kem_recip_info["rid"] = rid

    if kem_oid is not None:
        kem_recip_info["kem"]["algorithm"] = kem_oid

    if kemct is not None:
        kem_recip_info["kemct"] = univ.OctetString(kemct)

    if kemct is not None and (shared_secret is not None or encrypted_key is not None):
        pass

    elif public_key_recip is None and recip_cert is not None:
        server_pub_key = keyutils.load_public_key_from_spki(recip_cert["tbsCertificate"]["subjectPublicKeyInfo"])
        if not is_kem_public_key(server_pub_key):
            raise ValueError(f"The server's public key is not a `KEMPublicKey`. Got: {type(server_pub_key).__name__}.")

        if kem_oid is None:
            kem_recip_info["kem"]["algorithm"] = get_kem_oid_from_key(server_pub_key)

        if hybrid_key_recip is None:
            shared_secret, kemct = server_pub_key.encaps()
        else:
            shared_secret, kemct = hybrid_key_recip.encaps(server_pub_key)

        if not kem_recip_info["kemct"].isValue:
            kem_recip_info["kemct"] = univ.OctetString(kemct)

    elif public_key_recip:
        if not is_kem_public_key(public_key_recip):
            raise ValueError(
                f"The server's public key is not a `KEMPublicKey`. Got: {type(public_key_recip).__name__}."
            )

        if kem_oid is None:
            kem_recip_info["kem"]["algorithm"] = get_kem_oid_from_key(public_key_recip)

        if hybrid_key_recip is None:
            shared_secret, kemct = public_key_recip.encaps()
        else:
            shared_secret, kemct = hybrid_key_recip.encaps(public_key_recip)  # type: ignore

        logging.debug("Computed Shared secret %s", shared_secret.hex())
        if kemct is not None:
            kem_recip_info["kemct"] = univ.OctetString(kemct)

    else:
        raise ValueError("Either `kemct` or `server_cert` or the `public_key` must be provided.")

    kem_recip_info["kdf"] = prepare_kdf(kdf_name=kdf_name, hash_alg=hash_alg)
    if shared_secret is not None:
        key_enc_key = compute_kdf_from_alg_id(
            kdf_alg_id=kem_recip_info["kdf"], ss=shared_secret, ukm=ukm, length=kek_length or get_aes_length(wrap_name)
        )

    if encrypted_key is None:
        encrypted_key = keywrap.aes_key_wrap(wrapping_key=key_enc_key, key_to_wrap=cek)

    if ukm is not None:
        kem_recip_info["ukm"] = rfc9629.UserKeyingMaterial(ukm).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

    kem_recip_info["wrap"] = prepare_wrap_alg_id(wrap_name)
    kem_recip_info["encryptedKey"] = encrypted_key
    kem_recip_info["kekLength"] = kek_length or get_aes_length(wrap_name)

    return kem_recip_info


def prepare_mqv_user_keying_material(
    ephemeral_key: ec.EllipticCurvePrivateKey, added_ukm: Optional[bytes] = None
) -> rfc5753.MQVuserKeyingMaterial:
    """Create an `MQVuserKeyingMaterial` structure for MQV key agreement.

    In MQV key agreement, the ephemeral public key and optional additional
    user keying material (ukm) are included in the `MQVuserKeyingMaterial`.
    This function prepares this structure for use in `EnvelopedData`.

    :param ephemeral_key: Ephemeral EC private key to derive the public key.
    :param added_ukm: Additional user keying material. Defaults to None.
    :return: An `MQVuserKeyingMaterial` structure containing the ephemeral public key and UKM.
    """
    mqv_ukm = rfc5753.MQVuserKeyingMaterial()
    public_key_der = ephemeral_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    originator_public_key, _ = decoder.decode(public_key_der, rfc5753.OriginatorPublicKey())
    mqv_ukm["ephemeralPublicKey"] = originator_public_key

    if added_ukm is not None:
        added_ukm_field = univ.OctetString(added_ukm).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        mqv_ukm["addedukm"] = added_ukm_field

    return mqv_ukm


def prepare_key_agreement_algorithm_identifier(
    oid: univ.ObjectIdentifier,
    key_wrap_oid: univ.ObjectIdentifier = rfc9481.id_aes256_wrap,
    length: int = 32,
    entity_u_info: Optional[bytes] = None,
) -> rfc5280.AlgorithmIdentifier:
    """Create an `AlgorithmIdentifier` for key agreement with ECC_CMS_SharedInfo.

    Prepares the key encryption algorithm identifier used in key agreement
    recipient info (`KeyAgreeRecipientInfo`). It includes the necessary parameters
    for deriving the key, such as the key wrap algorithm and shared information.

    :param oid: OID for the key agreement algorithm.
    :param key_wrap_oid: OID for the key wrap algorithm. Defaults to AES-256 wrap.
    :param length: Length of the key to derive in bytes. Defaults to 32.
    :param entity_u_info: Optional entity user information. Defaults to None.
    :return: An `AlgorithmIdentifier` structure ready to be included in `KeyAgreeRecipientInfo`.
    """
    key_enc_alg_id = rfc5280.AlgorithmIdentifier()
    key_enc_alg_id["algorithm"] = oid
    ecc_cms_info = prepare_ecc_cms_shared_info(
        key_wrap_oid=key_wrap_oid, supp_pub_info=length, entity_u_info=entity_u_info
    )
    key_enc_alg_id["parameters"] = encoder.encode(ecc_cms_info)
    return key_enc_alg_id


def prepare_ecc_cms_shared_info(
    key_wrap_oid: univ.ObjectIdentifier,
    supp_pub_info: int = 32,
    entity_u_info: Optional[bytes] = None,
) -> rfc5753.ECC_CMS_SharedInfo:
    """Create an `ECC_CMS_SharedInfo` structure.

    The `ECC_CMS_SharedInfo` provides additional shared information needed
    for key derivation in ECC-based key agreement. This function prepares
    this structure with the specified key wrap algorithm and other parameters.

    :param key_wrap_oid: OID for the key wrap algorithm.
    :param supp_pub_info: Length of the key to derive in bytes.
    :param entity_u_info: Optional entity user information. Used to ensure a
    unique key.
    :return: An `ECC_CMS_SharedInfo` structure containing the shared info.
    """
    ecc_cms_info = rfc5753.ECC_CMS_SharedInfo()
    ecc_cms_info["keyInfo"]["algorithm"] = key_wrap_oid

    if entity_u_info is not None:
        ecc_cms_info["entityUInfo"] = univ.OctetString(entity_u_info).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

    if supp_pub_info is not None:
        supp_pub_info_bytes = supp_pub_info.to_bytes(4, byteorder="big")
        ecc_cms_info["suppPubInfo"] = univ.OctetString(supp_pub_info_bytes).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )

    return ecc_cms_info


@keyword(name="Prepare OriginatorIdentifierOrKey")
def prepare_originator_identifier_or_key(
    cert: Optional[rfc9480.CMPCertificate] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    invalid_ski: bool = False,
) -> rfc5652.OriginatorIdentifierOrKey:
    """Create an `OriginatorIdentifierOrKey` from a certificate.

    The `OriginatorIdentifierOrKey` identifies the sender in the key agreement.
    This function prepares this structure by using the SubjectKeyIdentifier
    extension if present; otherwise, it uses the issuer and serial number.

    Arguments:
    ---------
        - `cert`: The certificate to derive the originator identifier from (typically CMP protection certificate).
        - `issuer_and_ser`: The `IssuerAndSerialNumber` structure to set inside the `rid`. Defaults to `None`.
        - `invalid_ski`: If `True`, manipulates the first byte of the SKI. Defaults to `False`.

    Returns:
    -------
        - The populated `OriginatorIdentifierOrKey` structure.

    Raises:
    ------
        - ValueError: If neither a certificate nor issuer and serial number are provided.

    """
    if cert is None and issuer_and_ser is None:
        raise ValueError("Either a certificate or issuer and serial number must be provided.")

    ski = None
    if cert is not None:
        ski = certextractutils.get_field_from_certificate(cert, extension="ski")

    originator = rfc5652.OriginatorIdentifierOrKey().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )

    if issuer_and_ser is not None:
        originator["issuerAndSerialNumber"] = issuer_and_ser

    elif ski is not None:
        if invalid_ski:
            ski = utils.manipulate_first_byte(ski)
        val = rfc5652.SubjectKeyIdentifier(ski).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        originator["subjectKeyIdentifier"] = val

    else:
        originator["issuerAndSerialNumber"] = prepare_issuer_and_serial_number(cert)

    return originator


def prepare_recipient_encrypted_key(
    cmp_cert: rfc9480.CMPCertificate,
    encrypted_key: Optional[bytes],
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
) -> rfc5652.RecipientEncryptedKey:
    """Create a `RecipientEncryptedKey` structure.

    The `RecipientEncryptedKey` contains the encrypted key for a recipient.
    This function prepares this structure by specifying the recipient identifier
    and the encrypted key.

    :param cmp_cert: Certificate of the recipient (typically the CMP protection certificate).
    :param encrypted_key: Encrypted key material.
    :param issuer_and_ser: `IssuerAndSerialNumber` structure to set inside the `rid`. Defaults to `None`.
    :return: A `RecipientEncryptedKey` structure ready to be included in `KeyAgreeRecipientInfo`.
    """
    recip_enc_key = rfc5652.RecipientEncryptedKey()
    recip_enc_key["rid"] = prepare_recipient_identifier(cert=cmp_cert, issuer_and_ser=issuer_and_ser)
    if encrypted_key is not None:
        recip_enc_key["encryptedKey"] = encrypted_key
    return recip_enc_key


def prepare_recipient_encrypted_keys(
    cmp_prot_cert: rfc9480.CMPCertificate,
    enc_key: bytes,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    negative_size: bool = False,
):
    """Prepare a `RecipientEncryptedKeys` structure with one or more `RecipientEncryptedKey` entries.

    The `RecipientEncryptedKeys` contains the encrypted keys which are wrapped and then used to
    decrypt the private keys.

    :param cmp_prot_cert: A `CMPCertificate` object representing the recipient's certificate.
    :param enc_key: The encrypted key material as bytes.
    :param issuer_and_ser: Optional `IssuerAndSerialNumber` structure to set inside the `rid`.
    :param negative_size: If `True`, adds a duplicate entry for negative testing. Defaults to `False`.
    :return: The populated `RecipientEncryptedKeys` structure.
    """
    recipient_encrypted_keys = rfc5652.RecipientEncryptedKeys()

    recipient_encrypted_key = prepare_recipient_encrypted_key(cmp_prot_cert, enc_key, issuer_and_ser=issuer_and_ser)
    recipient_encrypted_keys.append(recipient_encrypted_key)
    if negative_size:
        recipient_encrypted_keys.append(recipient_encrypted_key)

    return recipient_encrypted_keys


def prepare_key_agreement_recipient_info(
    cmp_cert: rfc9480.CMPCertificate,
    key_agreement_oid: univ.ObjectIdentifier,
    encrypted_key: Optional[bytes] = None,
    key_wrap_oid: univ.ObjectIdentifier = rfc9481.id_aes256_wrap,
    version: int = 3,
    ukm: Optional[bytes] = None,
    negative_size: bool = False,
    length: int = 32,
    entity_u_info: Optional[bytes] = None,
    ecc_cms_info: Optional[bytes] = None,
    issuer_and_ser_orig: Optional[rfc5652.IssuerAndSerialNumber] = None,
    issuer_and_ser: Optional[rfc5652.IssuerAndSerialNumber] = None,
    originator: Optional[rfc5652.OriginatorIdentifierOrKey] = None,
) -> rfc5652.KeyAgreeRecipientInfo:
    """Create a `KeyAgreeRecipientInfo` structure for key agreement.

    The `KeyAgreeRecipientInfo` provides information needed by recipients
    to perform key agreement and obtain the content encryption key.
    This function assembles this structure with the necessary parameters.

    :param cmp_cert: Certificate of the recipient (typically the CMP protection certificate).
    :param key_agreement_oid: OID for the key agreement algorithm.
    :param encrypted_key: Optional encrypted key material.
    :param key_wrap_oid: OID for the key wrap algorithm.
    :param version: Version of the CMS structure. Defaults to 3.
    :param ukm: Optional user keying material.
    :param negative_size: If True, adds duplicate entries for negative testing.
    :param length: Length of the shared ECC information in bytes.
    :param entity_u_info: Optional entity user information.
    :param ecc_cms_info: Optional pre-encoded ECC CMS shared information.
    :param issuer_and_ser_orig: Optional `IssuerAndSerialNumber` structure to set inside the `originator`
    field. Defaults to `None`. Filled with the cmp-protection-cert.
    :param issuer_and_ser: Optional `IssuerAndSerialNumber` structure to set inside the `rid`.
    :param originator: The `OriginatorIdentifierOrKey` structure to set inside the `originator` field.
    Defaults to `None`. Filled with the cmp-protection-cert.
    (MUST be populated for POP.)
    :return: A `KeyAgreeRecipientInfo` structure ready to be included in `EnvelopedData`.
    """
    key_agree_info = rfc5652.KeyAgreeRecipientInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
    )
    key_agree_info["version"] = version
    key_agree_info["originator"] = originator or prepare_originator_identifier_or_key(
        cert=cmp_cert, issuer_and_ser=issuer_and_ser_orig or issuer_and_ser
    )

    if ukm is not None:
        ukm_field = rfc5652.UserKeyingMaterial(ukm).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
        key_agree_info["ukm"] = ukm_field

    recipient_encrypted_key = prepare_recipient_encrypted_key(
        cmp_cert=cmp_cert, encrypted_key=encrypted_key, issuer_and_ser=issuer_and_ser
    )
    recip_keys = rfc5652.RecipientEncryptedKeys()
    recip_keys.append(recipient_encrypted_key)
    if negative_size:
        # Add duplicate recipient encrypted key for negative testing
        recip_keys.append(recipient_encrypted_key)

    key_agree_info["recipientEncryptedKeys"] = recip_keys
    key_enc_alg_id = rfc5280.AlgorithmIdentifier()
    key_enc_alg_id["algorithm"] = key_agreement_oid

    key_enc_alg_id["parameters"] = ecc_cms_info or encoder.encode(
        prepare_ecc_cms_shared_info(key_wrap_oid=key_wrap_oid, entity_u_info=entity_u_info, supp_pub_info=length)
    )

    key_agree_info.setComponentByName("keyEncryptionAlgorithm", key_enc_alg_id)

    return key_agree_info

def _prepare_aes_warp_alg_id(wrap_name: Optional[str], cek_length: int, fill_params_rand: bool = False) -> rfc5280.AlgorithmIdentifier:
    """Prepare an AlgorithmIdentifier for AES key wrap algorithm.

    :param wrap_name: Name of the AES key wrap algorithm (e.g., "aes256-wrap"). Defaults to `None`.
    :param cek_length: Length of the content encryption key in bytes.
    :param fill_params_rand: If `True`, fill the parameters with random data. Defaults to `False`.
    (**MUST** be absent for AES key wrap algorithms.)
    :return: The populated `AlgorithmIdentifier` structure.
    """

    if wrap_name is None:
        if cek_length == 16:
            wrap_name = "aes128-wrap"
        elif cek_length == 32:
            wrap_name = "aes256-wrap"
        elif cek_length == 24:
            wrap_name = "aes192-wrap"
        else:
            raise ValueError(f"Unsupported AES key wrap length: {cek_length}. Expected 16, 24, or 32 bytes."
                             f"If used for negative nesting testing, provide the key wrap algorithm name."
                             f"(`wrap_name`)")

    oid = KEY_WRAP_NAME_2_OID.get(wrap_name)
    if oid is None:
        raise KeyError(f"Unsupported AES key wrap algorithm: {wrap_name}. Supported are: {KEY_WRAP_NAME_2_OID.keys()}")

    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid

    if fill_params_rand:
        alg_id["parameters"] = univ.OctetString(os.urandom(32))

    return alg_id

@keyword(name="Prepare PasswordRecipientInfo")
def prepare_password_recipient_info(
    password: Union[str, bytes],
    version: Union[str, int] = 0,
    cek: Optional[bytes] = None,
    kdf_name: str = "pbkdf2",
    bad_encrypted_key: bool = False,
    exclude_kdf_alg_id: bool = False,
    **params,
) -> rfc5652.PasswordRecipientInfo:
    """Prepare a `PasswordRecipientInfo` structure for password-based encryption.

    The `PasswordRecipientInfo` structure is used to encrypt the content encryption key (CEK)
    using a password and a key derivation function (KDF). This function prepares the structure
    with the necessary parameters.

    Arguments:
    ----------
        - `password`: The password to use for encryption.
        - `version`: The version number for the `PasswordRecipientInfo` structure. Defaults to `0`.
        - `cek`: The content encryption key to encrypt. Defaults to a random 32-byte key.
        - `kdf_name`: The key derivation function to use. Defaults to "pbkdf2".
        (which is the only one allowed for `PasswordRecipientInfo`).
        - `bad_encrypted_key`: If `True`, manipulate the first byte of the encrypted key. Defaults to `False`.
        - `exclude_kdf_alg_id`: If `True`, excludes the key derivation algorithm identifier. Defaults to `False`.

    **params:
    ---------
        - `salt` (str, bytes): The salt value for the PasswordRecipientInfo structure. Defaults to 32 random bytes.
        (will be interpreted as hex if it starts with "0x").
        - `iterations` (str, int): The number of iterations for the key derivation function. Defaults to `100000`.
        - `key_length` (str, int): The length of the derived key. Defaults to 32.
        - `hash_alg` (str): The hash algorithm to use for the key derivation function. Defaults to "sha256".
        - `wrap_name` (str): The name of the AES key wrap algorithm (e.g., "aes256-wrap"). Defaults to `None`.

    Returns:
    --------
        - A `PasswordRecipientInfo` structure ready to be included in `EnvelopedData`.

    Raises:
    -------
        - NotImplementedError: If an unsupported KDF is provided. (only supports "pbkdf2").
    """
    cek = cek or os.urandom(32)
    cek = str_to_bytes(cek)

    if kdf_name == "pbkdf2":
        salt = params.get("salt", os.urandom(32))
        salt = str_to_bytes(salt)
        pbkdf2 = prepare_pbkdf2_alg_id(salt=salt,
                                       iterations=int(params.get("iterations", 100000)),
                                       key_length=int(params.get("key_length", 32)),
                                       hash_alg=params.get("hash_alg", "sha256")
                                       )

        encrypted_key = wrap_key_password_based_key_management_technique(
            password=password, key_to_wrap=cek, parameters=pbkdf2["parameters"]
        )

    else:
        raise NotImplementedError(f"Unsupported KDF: {kdf_name}")

    pwri = rfc5652.PasswordRecipientInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
    )
    pwri["version"] = int(version)

    if not exclude_kdf_alg_id:
        pwri["keyDerivationAlgorithm"] = pbkdf2.subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0), cloneValueFlag=True
        )

    if params.get("aes_wrap"):
        pwri["keyEncryptionAlgorithm"] = _prepare_aes_warp_alg_id(params.get("wrap_name"), len(cek))


    pwri["keyEncryptionAlgorithm"]["algorithm"] = rfc9481.id_aes256_wrap

    if bad_encrypted_key:
        encrypted_key = utils.manipulate_first_byte(encrypted_key)

    pwri["encryptedKey"] = rfc5652.EncryptedKey(encrypted_key)
    return pwri

@not_keyword
def wrap_key_password_based_key_management_technique(
    password: Union[str, bytes], parameters: rfc8018.PBKDF2_params, key_to_wrap: bytes
) -> bytes:
    """Derive a key from a password using PBKDF2 parameters and wrap the given AES key using the derived key.

    :param password: The password used to derive the key.
    :param parameters: The PBKDF2 parameters used to derive the key.
    :param key_to_wrap: The AES key to be wrapped.
    :return: The wrapped (encrypted) AES key.
    """
    password = str_to_bytes(password)
    derive_key = compute_pbkdf2_from_parameter(parameters, key=password)
    logging.debug("Prepare PWRI - Derived Key: %s", derive_key.hex())
    return aes_key_wrap(wrapping_key=derive_key, key_to_wrap=key_to_wrap)
