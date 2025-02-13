# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains functionally which is only needed to test a client CMP-implementation."""

import logging
import os
import random
from typing import Dict, List, Optional, Sequence, Tuple, Union

import pyasn1.error
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pq_logic import pq_compute_utils
from pq_logic.key_pyasn1_utils import parse_key_from_one_asym_key
from pq_logic.keys.abstract_pq import PQKEMPublicKey
from pq_logic.migration_typing import HybridKEMPrivateKey, HybridKEMPublicKey
from pq_logic.pq_utils import get_kem_oid_from_key, is_kem_public_key
from pq_logic.trad_typing import CA_RESPONSE, ECDHPrivateKey, ECDHPublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5652, rfc9480
from robot.api.deco import keyword, not_keyword

from resources import (
    ca_kga_logic,
    certbuildutils,
    certutils,
    cmputils,
    compareutils,
    envdatautils,
    keyutils,
    protectionutils,
    utils,
)
from resources.asn1_structures import CAKeyUpdContent, CertResponseTMP, ChallengeASN1, PKIMessageTMP
from resources.certextractutils import get_extension, get_field_from_certificate
from resources.convertutils import copy_asn1_certificate, str_to_bytes
from resources.cryptoutils import compute_aes_cbc, perform_ecdh
from resources.exceptions import BadAsn1Data, BadPOP, BadRequest, NotAuthorized
from resources.extra_issuing_logic import is_null_dn
from resources.oid_mapping import compute_hash, get_hash_from_oid, sha_alg_name_to_oid
from resources.prepareutils import prepare_name
from resources.typingutils import PrivateKey, PrivateKeySig, PublicKey


def _prepare_issuer_and_ser_num_for_challenge(cert_req_id: int) -> rfc5652.IssuerAndSerialNumber:
    """Prepare the issuer and serial number for the challenge.

    :param cert_req_id: The certificate request ID.
    :return: The populated `IssuerAndSerialNumber` structure.
    """
    issuer_and_ser_num = rfc5652.IssuerAndSerialNumber()
    issuer_and_ser_num["issuer"] = prepare_name("Null-DN")
    issuer_and_ser_num["serialNumber"] = univ.Integer(cert_req_id)
    return issuer_and_ser_num


def _prepare_rand(
    sender: Optional[Union[rfc9480.GeneralName, str]],
    rand_int: Optional[int] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc9480.Rand:
    """Prepare the `Rand` structure for the challenge.

    :param sender: The sender of the message.
    :param rand_int: The random number to use. Defaults to `None`.
    :param cert: The certificate to use to populate the `Rand` sender field. Defaults to `None`.
    :return: The populated `Rand` structure.
    :raises ValueError: If neither `sender` nor `cert` is provided.
    """
    if sender is None and cert is None:
        raise ValueError("Either `sender` or `cert` must be provided.")

    rand_obj = rfc9480.Rand()
    if rand_int is None:
        rand_int = int.from_bytes(os.urandom(4), "big")

    if isinstance(sender, str):
        sender = cmputils.prepare_general_name("directoryName", sender)

    if cert:
        tmp = cert["tbsCertificate"]["subject"]
        sender = rfc9480.GeneralName()
        sender["directoryName"]["rdnSequence"] = tmp["rdnSequence"]

    rand_obj["sender"] = sender
    rand_obj["int"] = rand_int
    return rand_obj


def _prepare_witness_val(
    challenge_obj: ChallengeASN1, hash_alg: Optional[str], rand: rfc9480.Rand, bad_witness: bool
) -> ChallengeASN1:
    """Get the witness value for the challenge.

    :param challenge_obj: The challenge object.
    :param hash_alg: The hash algorithm to use. Defaults to `None`.
    :param rand: The random number to use.
    :param bad_witness: Whether to manipulate the witness value. Defaults to `False`.
    (witness is the hash of the integer.)
    :return: The updated challenge object.
    """
    witness = b""
    if hash_alg:
        challenge_obj["owf"] = protectionutils.prepare_sha_alg_id(hash_alg or "sha256")
        num_bytes = (int(rand["int"])).to_bytes(4, "big")
        witness = compute_hash(hash_alg, num_bytes)
        logging.info("valid witness value: %s", witness.hex())

    if bad_witness:
        if not hash_alg:
            witness = os.urandom(32)
        else:
            witness = utils.manipulate_first_byte(witness)

    challenge_obj["witness"] = univ.OctetString(witness)
    return challenge_obj


@not_keyword
def prepare_challenge(
    public_key: PublicKey,
    ca_key: Optional[PrivateKey] = None,
    bad_witness: bool = False,
    hash_alg: Optional[str] = None,
    rand_sender: str = "CN=CMP-Test-Suite CA",
    rand_int: Optional[int] = None,
    iv: Union[str, bytes] = b"AAAAAAAAAAAAAAAA",
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
) -> Tuple[ChallengeASN1, Optional[bytes], Optional[rfc9480.InfoTypeAndValue]]:
    """Prepare a challenge for the PKIMessage.

    :param public_key: The public key of the end-entity (EE).
    :param ca_key: The private key of the CA/RA.
    :param bad_witness: Whether to manipulate the witness value. Defaults to `False`.
    :param hash_alg: The hash algorithm to use. Defaults to `None`.
    :param rand_sender: The sender inside the Rand structure. Defaults to "CN=CMP-Test-Suite CA".
    :param rand_int: The random number to use. Defaults to `None`.
    :param iv: The initialization vector to use, for AES-CBC. Defaults to `b"AAAAAAAAAAAAAAAA"`.
    :param ca_cert: The CA certificate to use to populate the `Rand` sender field. Defaults to `None`.
    :return: The populated `Challenge` structure, the shared secret, and the info value (for KEMs/HybridKEMs).
    :raises ValueError: If the public key type is invalid. Must be either EC or KEM key.
    If neither `sender` nor `cert` is provided.
    """
    challenge_obj = ChallengeASN1()
    info_val: Optional[rfc9480.InfoTypeAndValue] = None

    rand = _prepare_rand(sender=rand_sender, rand_int=rand_int, cert=ca_cert)
    data = encoder.encode(rand)
    challenge_obj = _prepare_witness_val(
        challenge_obj=challenge_obj, rand=rand, hash_alg=hash_alg, bad_witness=bad_witness
    )

    if isinstance(public_key, RSAPublicKey):
        enc_data = public_key.encrypt(data, padding=padding.PKCS1v15())
        challenge_obj["challenge"] = univ.OctetString(enc_data)
        return challenge_obj, None, None

    if isinstance(public_key, ECDHPublicKey):
        shared_secret = perform_ecdh(ca_key, public_key)
    elif isinstance(public_key, PQKEMPublicKey):
        shared_secret, ct = public_key.encaps()
        info_val = protectionutils.prepare_kem_ciphertextinfo(key=public_key, ct=ct)
    elif is_kem_public_key(public_key):
        shared_secret, ct = public_key.encaps(ca_key)
        info_val = protectionutils.prepare_kem_ciphertextinfo(key=public_key, ct=ct)
    else:
        raise ValueError(f"Invalid public key type, to prepare a challenge: {type(public_key).__name__}")

    enc_data = compute_aes_cbc(key=shared_secret, data=data, iv=str_to_bytes(iv), decrypt=False)

    challenge_obj["challenge"] = univ.OctetString(enc_data)
    return challenge_obj, shared_secret, info_val


@keyword(name="Prepare Challenge Encrypted Rand")
def prepare_challenge_enc_rand(  # noqa: D417 Missing argument descriptions in the docstring
    public_key: PublicKey,
    rand_sender: Optional[Union[rfc9480.GeneralName, str]] = None,
    rand_int: Optional[int] = None,
    hash_alg: Optional[str] = None,
    bad_witness: bool = False,
    cert_req_id: int = 0,
    private_key: Optional[PrivateKey] = None,
    hybrid_kem_key: Optional[HybridKEMPrivateKey] = None,
    challenge: Optional[Union[str, bytes]] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
) -> ChallengeASN1:
    """Prepare a `Challenge` structure with an encrypted random number.

    Arguments:
    ---------
        - `public_key`: The public key of the end-entity (EE), used to create the `EnvelopedData` structure.
        - `sender`: The sender of the message, to set in the `Rand` structure.
        Either a `GeneralName` or a string.
        - `rand_int`: The random number to be encrypted. Defaults to `None`.
        (a random number is generated if not provided)
        - `private_key`: The private key of the server (CA/RA). Defaults to `None`.
        - `hash_alg`: The hash algorithm to use to hash the random number (e.g., "sha256"). Defaults to `None`.
        - `bad_witness`: The hash of the challenge. Defaults to an empty byte string.
        - `cert_req_id`: The certificate request ID , used in the `rid` field. Defaults to `0`.
        - `hybrid_kem_key`: The hybrid KEM key to use. Defaults to `None`.
        - `challenge`: The challenge to use. Defaults to an empty byte string.
        - `ca_cert`: The CA certificate to use to populate the `Rand` sender field. Defaults to `None`.

    Returns:
    -------
        - The populated `Challenge` structure.

    Raises:
    ------
        - `ValueError`: If the public key type is invalid.
        - `ValueError`: If neither `sender` nor `ca_cert` is provided.

    Examples:
    --------
    | ${challenge}= | Prepare Challenge Encrypted Rand | ${public_key} | ${sender} |
    | ${challenge}= | Prepare Challenge Encrypted Rand | ${public_key} | ${sender} | rand_int=1 | bad_witness=True |

    """
    challenge_obj = ChallengeASN1()

    rand_obj = _prepare_rand(sender=rand_sender, rand_int=rand_int, cert=ca_cert)

    env_data = rfc9480.EnvelopedData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    issuer_and_ser = _prepare_issuer_and_ser_num_for_challenge(cert_req_id)
    env_data = envdatautils.build_env_data_for_exchange(
        public_key_recip=public_key,
        data=encoder.encode(rand_obj),
        private_key=private_key,
        target=env_data,
        issuer_and_ser=issuer_and_ser,
        hybrid_key_recip=hybrid_kem_key,
        enc_oid=rfc5652.id_data,
    )

    challenge_obj = _prepare_witness_val(
        challenge_obj=challenge_obj, rand=rand_obj, hash_alg=hash_alg, bad_witness=bad_witness
    )

    challenge = challenge or b""
    challenge = str_to_bytes(challenge)

    challenge_obj["encryptedRand"] = env_data
    challenge_obj["challenge"] = univ.OctetString(challenge)
    return challenge_obj


@not_keyword
def prepare_oob_cert_hash(ca_cert: rfc9480.CMPCertificate, hash_alg: str = "sha256") -> rfc9480.OOBCertHash:
    """Prepare an `OOBCertHash` from a CA certificate.

    :param ca_cert: The OOB CA certificate.
    :param hash_alg: The hash algorithm to use (e.g., "sha256").
    :return: The populated `OOBCertHash` structure.
    """
    sig = compute_hash(hash_alg, encoder.encode(ca_cert))

    oob_cert_hash = rfc9480.OOBCertHash()
    oob_cert_hash["hashAlg"]["algorithm"] = sha_alg_name_to_oid(hash_alg)
    oob_cert_hash["certId"] = rfc9480.CertId()
    oob_cert_hash["certId"]["issuer"] = ca_cert["tbsCertificate"]["issuer"]
    oob_cert_hash["certId"]["serialNumber"] = ca_cert["tbsCertificate"]["serialNumber"]
    oob_cert_hash["hashVal"] = univ.BitString.fromOctetString(sig)

    return oob_cert_hash


@keyword(name="Validate OOBCertHash")
def validate_oob_cert_hash(  # noqa: D417 Missing argument descriptions in the docstring
    ca_cert: rfc9480.OOBCert, oob_cert_hash: rfc9480.OOBCertHash
) -> None:
    """Validate an `OOBCertHash` against a CA certificate.

    Arguments:
    ---------
        - `ca_cert`: The OOB CA certificate.
        - `oob_cert_hash`: The OOB cert hash to validate.

    Raises:
    ------
        - ValueError: If the OOB cert hash is invalid.

    Examples:
    --------
    | Validate OOBCertHash | ${ca_cert} | ${oob_cert_hash} |

    """
    hash_name = get_hash_from_oid(oob_cert_hash["hashAlg"]["algorithm"])
    sig = compute_hash(hash_name, encoder.encode(oob_cert_hash))

    if sig != oob_cert_hash["hashVal"].asOctets():
        raise ValueError("Invalid OOB cert hash")

    if ca_cert["tbsCertificate"]["issuer"] != oob_cert_hash["certId"]["issuer"]:
        raise ValueError("Invalid OOB cert issuer")

    if ca_cert["tbsCertificate"]["serialNumber"] != oob_cert_hash["certId"]["serialNumber"]:
        raise ValueError("Invalid OOB cert serial number")

    # Validate as of rfc4210bis-15 Section 5.2.5. Out-of-band root CA Public Key:
    #
    # 1. MUST be self-signed
    # 2. MUST have the same issuer and subject.
    if not certutils.check_is_cert_signer(ca_cert, ca_cert):
        raise ValueError("CA cert is not self-signed")

    # 3. If the subject field contains a "NULL-DN", then both subjectAltNames and issuerAltNames
    # extensions MUST be present and have exactly the same value

    if is_null_dn(ca_cert["tbsCertificate"]["subject"]):
        logging.info("Subject is NULL-DN")
        extn_san = get_extension(ca_cert["tbsCertificate"]["extensions"], rfc5280.id_ce_subjectAltName)
        extn_ian = get_extension(ca_cert["tbsCertificate"]["extensions"], rfc5280.id_ce_issuerAltName)

        logging.info("SubjectAltName: %s", extn_san.prettyPrint())
        logging.info("IssuerAltName: %s", extn_ian.prettyPrint())

        if extn_ian is None:
            raise ValueError("IssuerAltName missing")
        if extn_san is None:
            raise ValueError("SubjectAltName missing")

        if extn_san["critical"] != extn_ian["critical"]:
            raise ValueError("SubjectAltName and IssuerAltName must have same criticality.")

        if extn_san["extnValue"].asOctets() != extn_ian["extnValue"].asOctets():
            raise ValueError("SubjectAltName and IssuerAltName must have same value")

    # Validate other self-signed features.
    # 4. The values of all other extensions must be suitable for a self-signed certificate
    # (e.g., key identifiers for subject and issuer must be the same).
    certutils.validate_certificate_pkilint(ca_cert)


def _prepare_cert_with_cert(
    cert: rfc9480.CMPCertificate,
    signing_key: PrivateKeySig,
    use_rsa_pss: bool = True,
    hash_alg: str = "sha256",
    issuer: Optional[rfc9480.Name] = None,
) -> rfc9480.CMPCertificate:
    """Prepare a `CMPCertificate` with a `CMPCertificate`

    :param cert: The `CMPCertificate` to create the new one from and sign.
    :param signing_key: The key to sign the certificate with.
    :param use_rsa_pss: Whether to use RSA-PSS or not. Defaults to True.
    :param hash_alg: The hash algorithm to use (e.g. "sha256").
    :param issuer: The certificate issuer to sign the certificate with.
    :return: The populated `CMPCertificate` structure.
    :raises ValueError: If the signing key is not allowed to be used for signing.
    """
    cert_with_cert = rfc9480.CMPCertificate()
    cert = copy_asn1_certificate(cert, cert_with_cert)

    if issuer is not None:
        cert["tbsCertificate"]["issuer"] = issuer

    sig_alg = certbuildutils.prepare_sig_alg_id(signing_key=signing_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg)

    cert["tbsCertificate"]["signature"] = sig_alg
    cert_with_cert["tbsCertificate"] = cert["tbsCertificate"]

    cert_with_cert["signature"] = certbuildutils.sign_cert(
        signing_key, cert=cert, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss
    )
    return cert_with_cert


# New structure as of RFC4210bis-15.


@not_keyword
def build_ckuann(
    new_cert: rfc9480.CMPCertificate,
    old_cert: rfc9480.CMPCertificate,
    new_key,
    old_key,
    use_new: bool = False,
    use_root_ca_key_update: bool = False,
    sender: str = "",
    recipient: str = "",
    pvno: int = 3,
    **kwargs,
):
    """Build a `CAKeyUpdAnnContent` PKIMessage.

    :param new_cert: The new CA certificate to be installed as trust anchor.
    :param old_cert: The old CA certificate, which was the trust anchor.
    :param new_key: The private key corresponding to the new CA certificate.
    :param old_key: The private key corresponding to the old CA certificate.
    :param use_new: Whether to use the new structure or the old one.
    :param use_root_ca_key_update: Whether to use the root CA key update or not.
    :param sender: The sender of the message.
    :param recipient: The recipient of the message.
    :param pvno: The version of the message.
    :return: The populated `PKIMessage` structure.
    """
    body = rfc9480.PKIBody()

    # if ckuann, the pvno cmp2021 (3) MUST be used.
    # for RootCaKeyUpdateContent else pvno 2
    body_content = rfc9480.CAKeyUpdAnnContent().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 15)
    )

    body["ckuann"] = body_content

    if not certutils.check_is_cert_signer(new_cert, new_cert):
        new_with_new = _prepare_cert_with_cert(new_cert, signing_key=new_key)
    else:
        new_with_new = new_cert

    old_with_new = _prepare_cert_with_cert(old_cert, signing_key=new_key, issuer=new_cert["tbsCertificate"]["issuer"])
    new_with_old = _prepare_cert_with_cert(new_cert, issuer=old_cert["tbsCertificate"]["issuer"], signing_key=old_key)

    if not use_new:
        body_content["newWithNew"] = new_with_new
        body_content["oldWithNew"] = old_with_new
        body_content["newWithOld"] = new_with_old

    else:
        body_content = CAKeyUpdContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 15))

        body_name = "cAKeyUpdAnnV3" if use_root_ca_key_update else "cAKeyUpdAnnV2"

        body_content[body_name]["newWithNew"] = new_with_new
        body_content[body_name]["oldWithNew"] = old_with_new
        body_content[body_name]["newWithOld"] = new_with_old

    pki_message = cmputils.prepare_pki_message(pvno=pvno, sender=sender, recipient=recipient, **kwargs)
    pki_message["body"] = body
    return pki_message


@keyword("Get CertReqMsg From PKIMessage")
def get_cert_req_msg_from_pkimessage(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: rfc9480.PKIMessage, index: int = 0
) -> rfc4211.CertReqMsg:
    """Extract the certificate request from a PKIMessage.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to extract the certificate request from.
        - `index`: The index of the certificate request to extract. Defaults to `0`.

    Returns:
    -------
        - The certificate request message.

    Raises:
    ------
        - ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
        - IndexError: If the index is out of range.

    Examples:
    --------
    | ${cert_req_msg}= | Get CertReqMsg From PKIMessage | ${pki_message} |
    | ${cert_req_msg}= | Get CertReqMsg From PKIMessage | ${pki_message} | index=0 |

    """
    body_name = pki_message["body"].getName()
    if body_name in {"ir", "cr", "kur", "crr"}:
        return pki_message["body"][body_name][index]

    raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, crr")


def validate_cert_request_cert_id(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: rfc9480.PKIMessage, cert_req_id: Union[str, int] = 0
) -> None:
    """Validate the certificate request certificate ID.

    Used for LwCMP to ensure the certReqId in the PKIMessage matches
    either one or minus one for p10cr.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to validate.
        - `cert_req_id`: The index of the certificate request to validate. Defaults to `0`.

    Raises:
    ------
        - ValueError: If the certificate request ID in the PKIMessage is invalid.

    """
    cert_req_id = int(cert_req_id)
    cert_req = get_cert_req_msg_from_pkimessage(pki_message)
    body_name = pki_message["body"].getName()
    cert_id = cert_req["certReqId"]
    if body_name in {"ir", "cr", "kur", "crr"}:
        if cert_id != cert_req_id:
            raise ValueError("Invalid certReqId in PKIMessage.")
    elif body_name == "p10cr":
        if -1 != pki_message["body"]["p10cr"]["certReqId"]:
            raise ValueError("Invalid certReqId in PKIMessage,`p10cr` expects -1.")
    else:
        raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, crr or p10cr")


@not_keyword
def get_public_key_from_cert_req_msg(cert_req_msg: rfc4211.CertReqMsg) -> PublicKey:
    """Extract the public key from a certificate request message.

    :param cert_req_msg: The certificate request message.
    :return: The extracted public key.
    :raises ValueError: If the public key type is invalid.
    """
    spki = cert_req_msg["certReq"]["certTemplate"]["publicKey"]

    old_spki = rfc5280.SubjectPublicKeyInfo()
    old_spki["algorithm"] = spki["algorithm"]
    old_spki["subjectPublicKey"] = spki["subjectPublicKey"]

    return keyutils.load_public_key_from_spki(old_spki)


def _verify_pop_signature(
    pki_message: rfc9480.PKIMessage,
) -> None:
    """Verify the POP signature in the PKIMessage.

    :param pki_message: The PKIMessage to verify the POP signature for.
    :raises BadAsn1Data: If the CertRequest encoding fails.
    :raises BadPOP: If the POP verification fails.
    :raises InvalidSignature: If the signature verification fails.
    """
    body_name = pki_message["body"].getName()

    try:
        cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message)
        popo: rfc4211.ProofOfPossession = cert_req_msg["popo"]
        if not popo["signature"].isValue:
            raise ValueError("POP signature is missing in the PKIMessage.")

        popo_sig = popo["signature"]
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        pq_compute_utils.verify_signature_with_alg_id(
            public_key=public_key,
            alg_id=popo_sig["algorithmIdentifier"],
            data=encoder.encode(cert_req_msg["certReq"]),
            signature=popo_sig["signature"].asOctets(),
        )

        if cert_req_msg["regInfo"].isValue:
            logging.debug("regInfo is present in the CertReqMsg,but server logic is not supported yet.")

    except pyasn1.error.PyAsn1Error as err:
        raise BadAsn1Data("Failed to encode the CertRequest.", overwrite=True) from err

    except InvalidSignature as err:
        raise BadPOP(f"POP verification for `{body_name}` failed.") from err


def _verify_ra_verified(
    pki_message: rfc9480.PKIMessage,
    allowed_ra_dir: str,
    trustanchor: Optional[str] = None,
    allow_os_store: bool = False,
    strict: bool = True,
) -> None:
    """Verify the raVerified in the PKIMessage.

    :param pki_message: The PKIMessage to verify the raVerified for.
    :param trustanchor: The trust anchor to use for verification. Defaults to `None`.
    :param allowed_ra_dir: The allowed RA directory. Defaults to `None`.
    :param allow_os_store: Allow the OS store. Defaults to `False`.
    :param strict: Whether the RA certificate must have the `cmcRA` EKU bit set.
    Defaults to `True`.
    """
    ra_certs = certutils.load_certificates_from_dir(allowed_ra_dir)
    may_ra_cert = pki_message["extraCerts"][0]
    result = certutils.cert_in_list(may_ra_cert, ra_certs)

    if not result:
        raise NotAuthorized("RA certificate not in allowed RA directory.")

    eku_cert = get_field_from_certificate(may_ra_cert, extension="eku")
    certutils.validate_cmp_extended_key_usage(eku_cert, ext_key_usages="cmcRA", strict="STRICT" if strict else "LAX")

    cert_chain = certutils.build_cmp_chain_from_pkimessage(
        pki_message,
    )
    try:
        certutils.certificates_must_be_trusted(
            cert_chain=cert_chain, trustanchors=trustanchor, allow_os_store=allow_os_store
        )
    except InvalidSignature as err:
        raise NotAuthorized("RA certificate not trusted.") from err


def verify_popo_for_cert_request(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: rfc9480.PKIMessage,
    allowed_ra_dir: str = "data/trusted_ras",
    trustanchor: Optional[str] = None,
    allow_os_store: bool = False,
    cert_req_index: Union[int, str] = 0,
    must_have_ra_eku_set: bool = True,
) -> None:
    """Verify the Proof-of-Possession (POP) for a certificate request.

    Arguments:
    ---------
       - `pki_message`: The pki message to verify the POP for.
       - `allowed_ra_dir`: The allowed RA directory, filed with trusted RA certificates.
         Defaults to `data/trusted_ras`.
       - `trustanchor`: The trust anchor to use for verification. Defaults to `None`.
       - `allow_os_store`: Whether to allow the OS store. Defaults to `False`.
       - `cert_req_index`: The index of the certificate request to verify the POP for. Defaults to `0`.
       - `must_have_ra_eku_set`: Whether Extended Key Usage (EKU) CMP-RA bit must be set. Defaults to `True`.

    Raises:
    ------
        - ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
        - ValueError: If the POP structure is invalid
        - ValueError: If the public key type is invalid.
        - NotImplementedError: If the request is for key agreement.
        - BadPOP: If the POP verification fails.
        - NotAuthorized: If the RA certificate is not trusted.

    """
    if pki_message["body"].getName() not in {"ir", "cr", "kur", "crr"}:
        raise ValueError(f"Invalid PKIMessage body: {pki_message['body'].getName()} Expected: ir, cr, kur, crr")

    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message, index=cert_req_index)
    name = cert_req_msg["popo"].getName()

    if name == "raVerified":
        _verify_ra_verified(pki_message, allowed_ra_dir, trustanchor, allow_os_store, must_have_ra_eku_set)
    elif name == "signature":
        verify_sig_pop_for_pki_request(pki_message)
    elif name == "keyEncipherment":
        public_key = get_public_key_from_cert_req_msg(cert_req_msg=cert_req_msg)

        if not is_kem_public_key(public_key):
            raise ValueError("Invalid public key type, for `keyEncipherment`.")

    elif name == "keyAgreement":
        public_key = get_public_key_from_cert_req_msg(cert_req_msg=cert_req_msg)
        if not isinstance(public_key, ECDHPublicKey):
            raise ValueError("Invalid public key type, for `keyAgreement`.")

    else:
        raise ValueError(
            f"Invalid POP structure: {name}. Expected: raVerified, signature, keyEncipherment, keyAgreement"
        )


@keyword(name="Respond To CertReqMsg")
def respond_to_cert_req_msg(  # noqa: D417 Missing argument descriptions in the docstring
    cert_req_msg: rfc4211.CertReqMsg,
    ca_key: PrivateKey,
    ca_cert: rfc9480.CMPCertificate,
    hybrid_kem_key: Optional[ECDHPrivateKey] = None,
    hash_alg: str = "sha256",
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
) -> [rfc9480.CMPCertificate, Optional[rfc9480.EnvelopedData]]:
    """Respond to a certificate request.

    Note:
    ----
       - Assumes that the `POP` was already verified.

    Arguments:
    ---------
       - `cert_req_msg`: The certificate request message to respond to.
       - `ca_key`: The CA private key to sign the response with.
       - `ca_cert`: The CA certificate matching the CA key.
       - `hybrid_kem_key`: The hybrid KEM key of the CA to use. Defaults to `None`.
       - `hash_alg`: The hash algorithm to use, for signing the certificate. Defaults to "sha256".
       - `extensions`: The extensions to add to the certificate. Defaults to `None`.
       (as an example for OCSP, CRL, etc.)

    Returns:
    -------
         - The certificate and the encrypted certificate, if the request is for key encipherment.

    Raises:
    ------
       - NotImplementedError: If the request is for key agreement.

    Examples:
    --------
    | ${cert} | ${enc_cert}= | Respond To CertReqMsg | ${cert_req_msg} | ${ca_key} | ${ca_cert} |
    | ${cert} | ${enc_cert}= | Respond To CertReqMsg | ${cert_req_msg} | ${ca_key} | ${ca_cert} \
    | ${hybrid_kem_key} | ${hash_alg} |

    """
    name = cert_req_msg["popo"].getName()

    if name in ["raVerified", "signature"]:
        cert = certbuildutils.build_cert_from_cert_template(
            cert_template=cert_req_msg["certReq"]["certTemplate"],
            ca_key=ca_key,
            ca_cert=ca_cert,
            extensions=extensions,
        )
        return cert, None

    elif name == "keyEncipherment":
        cert = certbuildutils.build_cert_from_cert_template(
            cert_template=cert_req_msg["certReq"]["certTemplate"],
            ca_key=ca_key,
            ca_cert=ca_cert,
            extensions=extensions,
        )
        enc_cert = prepare_encr_cert_for_request(
            cert_req_msg=cert_req_msg,
            signing_key=ca_key,
            hash_alg=hash_alg,
            ca_cert=ca_cert,
            new_ee_cert=cert,
            hybrid_kem_key=hybrid_kem_key,
        )

        return cert, enc_cert

    elif name == "keyAgreement":
        raise NotImplementedError("Key agreement is not allowed.")
    else:
        name = cert_req_msg["popo"].getName()
        raise ValueError(f"Invalid POP structure: {name}.")


@keyword(name="Verify POP Signature For PKI Request")
def verify_sig_pop_for_pki_request(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: rfc9480.PKIMessage, cert_index: Union[int, str] = 0
) -> None:
    """Verify the POP in the PKIMessage.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to verify the POP for.
        - `cert_index`: The index of the certificate request to verify the POP for. Defaults to `0`.

    Raises:
    ------
        - ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
        - IndexError: If the index is out of range.
        - BadAsn1Data: If the ASN.1 data is invalid.
        - BadPOP: If the signature is invalid.

    """
    body_name = pki_message["body"].getName()
    if body_name in {"ir", "cr", "kur", "crr"}:
        cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message, index=cert_index)
        popo: rfc4211.ProofOfPossession = cert_req_msg["popo"]
        if not popo["signature"].isValue:
            raise ValueError("POP signature is missing in the PKIMessage.")

        _verify_pop_signature(pki_message)

    elif pki_message["p10cr"]:
        csr = pki_message["p10cr"]
        try:
            pq_compute_utils.verify_csr_signature(csr)
        except InvalidSignature:
            raise BadPOP("POP verification for `p10cr` failed.")

    else:
        raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, crr or p10cr")


def _prepare_ca_body(
    body_name: str,
    responses: Union[Sequence[CertResponseTMP], CertResponseTMP],
    ca_pubs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
) -> rfc9480.PKIBody:
    """Prepare the body for a CA `CertResponse` message.

    :return: The prepared body.
    """
    types_to_id = {"ip": 1, "cp": 3, "kup": 8, "ccp": 14}
    if body_name not in types_to_id:
        raise ValueError(f"Unsupported body_type: '{body_name}'. Expected one of {list(types_to_id.keys())}.")

    body = rfc9480.PKIBody()
    if ca_pubs is not None:
        body[body_name]["caPubs"].extend(ca_pubs)

    if isinstance(responses, CertResponseTMP):
        responses = [responses]

    if responses is None:
        raise ValueError("No responses provided to build the body.")

    body[body_name]["response"].extend(responses)
    return body


def _set_header_fields(request: rfc9480.PKIMessage, kwargs: dict) -> dict:
    """Set header fields for a new PKIMessage, by extracting them from the request."""
    if request["header"]["senderKID"].isValue:
        kwargs["recip_kid"] = kwargs.get("recip_kid") or request["header"]["senderKID"].asOctets()
    else:
        logging.debug("No `senderKID` value set in the request header.")

    kwargs["recip_nonce"] = kwargs.get("recip_nonce") or request["header"]["senderNonce"].asOctets()
    alt_nonce = (
        os.urandom(16) if not request["header"]["recipNonce"].isValue else request["header"]["recipNonce"].asOctets()
    )
    kwargs["sender_nonce"] = kwargs.get("sender_nonce") or alt_nonce
    kwargs["transaction_id"] = kwargs.get("transaction_id") or request["header"]["transactionID"].asOctets()
    return kwargs


def build_cp_from_p10cr(  # noqa: D417 Missing argument descriptions in the docstring
    request: rfc9480.PKIMessage,
    cert: Optional[rfc9480.CMPCertificate] = None,
    set_header_fields: bool = True,
    cert_req_id: Union[int, str] = -1,
    ca_pubs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
    ca_key: Optional[PrivateKey] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    **kwargs,
) -> Tuple[rfc9480.PKIMessage, rfc9480.CMPCertificate]:
    """Build a CMP message for a certificate request.

    Arguments:
    ---------
        - `request`: The PKIMessage containing the certificate request.
        - `cert`: The certificate to build the response for. Defaults to `None`.
        - `set_header_fields`: Whether to patch the header fields, for the exchange. Defaults to `True`.
        (recipNonce, recipKID)
        - `cert_req_id`: The certificate request ID. Defaults to `-1`.
        - `ca_pubs`: The CA certificates to include in the response. Defaults to `None`.
        - `ca_key`: The CA private key to sign the response with. Defaults to `None`.
        - `ca_cert`: The CA certificate matching the CA key. Defaults to `None`.
        - `kwargs`: Additional values to set for the header.

    Returns:
    -------
        - The built PKIMessage.

    Raises:
    ------
        - ValueError: If the request is not a `p10cr`.
        - ValueError: If the CA key and certificate are not provided and the certificate is not provided.

    """
    if request["body"].getName() != "p10cr":
        raise ValueError("Request must be a p10cr to build a CP message for it.")

    if request and set_header_fields:
        kwargs = _set_header_fields(request, kwargs)

    pq_compute_utils.verify_csr_signature(request["body"]["p10cr"])

    if cert is None:
        if ca_key is None or ca_cert is None:
            raise ValueError("Either `cert` or `ca_key` and `ca_cert` must be provided to build a CA CMP message.")

    cert = cert or certbuildutils.build_cert_from_csr(
        csr=request["body"]["p10cr"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        hash_alg=kwargs.get("hash_alg", "sha256"),
        extensions=kwargs.get("extensions"),
    )

    responses = prepare_cert_response(cert=cert, cert_req_id=cert_req_id)
    body = _prepare_ca_body(body_name="cp", responses=responses, ca_pubs=ca_pubs)
    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, cert


def _process_one_cert_request(
    ca_key: PrivateKey,
    ca_cert: rfc9480.CMPCertificate,
    request: rfc9480.PKIMessage,
    cert_index: int,
    eku_strict: bool,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, Optional[rfc5652.EnvelopedData]]:
    """Process a single certificate response.

    :param ca_key: The CA private key to sign the certificate with.
    :param ca_cert: The CA certificate matching the CA key.
    :param request: The PKIMessage containing the certificate request.
    :param cert_index: The index of the certificate to respond to.
    :param eku_strict: The strictness of the EKU bits.
    :param kwargs: The additional values to set for the header.
    :return: The certificate and the optional encrypted certificate.
    """
    verify_popo_for_cert_request(
        pki_message=request,
        allowed_ra_dir=kwargs.get("allowed_ra_dir", "./data/allowed_ras"),
        trustanchor=kwargs.get("trustanchor", "./data/trustanchors"),
        allow_os_store=kwargs.get("allow_os_store", True),
        cert_req_index=cert_index,
        must_have_ra_eku_set=eku_strict,
    )
    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message=request, index=cert_index)
    cert, enc_cert = respond_to_cert_req_msg(
        cert_req_msg=cert_req_msg,
        ca_key=ca_key,
        ca_cert=ca_cert,
        hybrid_kem_key=kwargs.get("hybrid_kem_key"),
        hash_alg=kwargs.get("hash_alg", "sha256"),
        extensions=kwargs.get("extensions"),
    )
    return cert, enc_cert


def _process_cert_requests(
    ca_key: PrivateKey,
    ca_cert: rfc9480.CMPCertificate,
    request: rfc9480.PKIMessage,
    eku_strict: bool,
    **kwargs,
) -> Tuple[List[CertResponseTMP], List[rfc9480.CMPCertificate]]:
    """Process a certificate requests.

    :param ca_key: The CA private key to sign the certificates with.
    :param ca_cert: The CA certificate matching the CA key.
    :param request: The PKIMessage containing the certificate request.
    :param eku_strict: The strictness of the EKU bits.
    :return: The certificate responses and the certificates.
    """
    responses = []
    certs = []

    body_name = request["body"].getName()

    for i in range(len(request["body"][body_name])):
        cert, enc_cert = _process_one_cert_request(
            ca_key=ca_key,
            ca_cert=ca_cert,
            request=request,
            cert_index=i,
            eku_strict=eku_strict,
            **kwargs,
        )
        certs.append(cert)
        cert_req_id = int(request["body"][body_name][i]["certReq"]["certReqId"])
        response = prepare_cert_response(cert=cert, enc_cert=enc_cert, cert_req_id=cert_req_id)

        responses.append(response)

    return responses, certs


def build_cp_cmp_message(  # noqa: D417 Missing argument descriptions in the docstring
    request: Optional[rfc9480.PKIMessage] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc5652.EnvelopedData] = None,
    ca_key: Optional[PrivateKey] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    cert_req_id: Optional[int] = None,
    responses: Optional[Union[Sequence[CertResponseTMP], CertResponseTMP]] = None,
    cert_index: Optional[int] = None,
    eku_strict: bool = True,
    set_header_fields: bool = True,
    **kwargs,
) -> CA_RESPONSE:
    """Build a CMP message for a certificate response.

    Arguments:
    ---------
       - `request`: The PKIMessage containing the certificate request. Defaults to `None`.
       - `cert`: The certificate to build the response for. Defaults to `None`.
       - `enc_cert`: The encrypted certificate to build the response for. Defaults to `None`.
       - `ca_key`: The CA private key to sign the response with. Defaults to `None`.
       - `ca_cert`: The CA certificate matching the CA key. Defaults to `None`.
       - `cert_req_id`: The certificate request ID. Defaults to `None`.
       - `responses`: The certificate responses to include in the response. Defaults to `None`.
       - `cert_index`: The certificate index. Defaults to `None` (if `None`, all requests are processed).
       - `eku_strict`: Whether to strictly enforce the EKU bits, for `raVerified`. Defaults to `True`.
       - `set_header_fields`: Whether to patch the header fields, for the exchange. Defaults to `True`.
       - `kwargs`: Additional values to set for the header.

    Returns:
    -------
        - The built PKIMessage and the certificates.

    """
    certs = []

    if enc_cert is None and cert is None and request is None:
        raise ValueError("Either `cert`, `enc_cert`, or `request` must be provided to build a CA CMP message.")

    if responses is not None:
        pass

    elif enc_cert is not None or cert is not None:
        if cert_req_id is None:
            cert_req_id = 0

        responses = prepare_cert_response(cert=cert, enc_cert=enc_cert, cert_req_id=cert_req_id)

        if cert is not None:
            certs.append(cert)

    elif request is not None:
        if cert_index is not None:
            cert, enc_cert = _process_one_cert_request(
                ca_key=ca_key,
                ca_cert=ca_cert,
                request=request,
                cert_index=cert_index,
                eku_strict=eku_strict,
                **kwargs,
            )
            certs.append(cert)

            if cert_req_id is None:
                cert_req_id = request["body"]["cr"][cert_index]["certReq"]["certReqId"]

            responses = prepare_cert_response(cert=cert, enc_cert=enc_cert, cert_req_id=cert_req_id)

        else:
            responses, certs = _process_cert_requests(
                ca_key=ca_key,
                ca_cert=ca_cert,
                request=request,
                eku_strict=eku_strict,
                **kwargs,
            )

    if request and set_header_fields:
        kwargs = _set_header_fields(request, kwargs)

    body = _prepare_ca_body("ip", responses=responses, ca_pubs=kwargs.get("ca_pubs"))
    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, certs


@keyword(name="Enforce LwCMP For CA")
def enforce_lwcmp_for_ca(  # noqa: D417 Missing argument descriptions in the docstring
    request: rfc9480.PKIMessage,
) -> None:
    """Enforce the Lightweight CMP (LwCMP) for a CA.

    When the request is "ir", "cr", "kur", or "crr", the `certReqId` **MUST** be `0`,
    and only one **MUST** be present.

    Arguments:
    ---------
      - `request`: The PKIMessage to enforce the LwCMP for.

    Raises:
    ------
        - BadRequest: If the `certReqId` is invalid.
        - BadRequest: If the request length is invalid.
        - BadRequest: If the request type is invalid.

    Examples:
    --------
    | Enforce LwCMP For CA | ${request} |

    """
    if request["body"].getName() == "p10cr":
        pass
    elif request["body"].getName() in {"ir", "cr", "kur", "crr"}:
        if len(request["body"][request["body"].getName()]) != 1:
            raise BadRequest("Only one certificate request is allowed for LwCMP.")

        if request["body"][request["body"].getName()][0]["certReq"]["certReqId"] != 0:
            raise BadRequest("Invalid certReqId for LwCMP.")

    elif request["body"].getName() == "certConf":
        if len(request["body"]["certConf"]) != 1:
            raise BadRequest("Only one certificate confirmation is allowed for LwCMP.")

    elif request["body"].getName() == "rr":
        if len(request["body"]["rr"]) != 1:
            raise BadRequest("Only one revocation request is allowed for LwCMP.")

    else:
        raise BadRequest(
            "Invalid PKIMessage body for LwCMP. Expected: ir, cr, kur, crr, rr, certConf or p10cr."
            f"Got: {request['body'].getName()}."
        )


def build_ip_cmp_message(  # noqa: D417 Missing argument descriptions in the docstring
    request: Optional[rfc9480.PKIMessage] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc5652.EnvelopedData] = None,
    ca_pubs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
    responses: Optional[Union[Sequence[CertResponseTMP], CertResponseTMP]] = None,
    exclude_fields: Optional[str] = None,
    set_header_fields: bool = True,
    **kwargs,
) -> CA_RESPONSE:
    """Build a CMP message for an initialization response.

    Arguments:
    ---------
        - `cert`: The certificate to build the response for. Defaults to `None`.
        - `enc_cert`: The encrypted certificate to build the response for. Defaults to `None`.
        - `ca_pubs`: The CA certificates to include in the response. Defaults to `None`.
        - `responses`: The certificate responses to include in the response. Defaults to `None`.
        - `exclude_fields`: The fields to exclude from the response. Defaults to `None`.
        - `request`: The PKIMessage containing the certificate request. Defaults to `None`.
        - `set_header_fields`: Whether to patch the header fields, for the exchange. Defaults to `True`.
        - `kwargs`: Additional values to set for the header.

    **kwargs:
    --------
        - additional values to set for the header.
        - `private_key`: The private key securely wrapped in the `EnvelopedData` structure.
        - `enforce_lwcmp`: Whether to enforce the Lightweight CMP (LwCMP) for the CA. Defaults to `True`.
        - `hash_alg`: The hash algorithm to use for signing the certificate. Defaults to `sha256`.
        - `eku_strict`: Whether to strictly enforce the EKU bits. Defaults to `True`.
        (needed for raVerified)
        - `ca_key`: The CA private key to sign the newly issued certificate with.
        - `ca_cert`: The CA certificate matching the CA key.
        - `cert_req_id`: The certificate request ID. Defaults to `0`, if cert is provided.
        (else parsed from the request)
        - `extensions`: The extensions to include in the certificate. Defaults to `None`.
        (as an eample for OCSP, CRL, etc.)

    Returns:
    -------
        - The built PKIMessage and the certificates.

    Raises:
    ------
        - ValueError: If the CA key and certificate are not provided and the certificate is not provided.


    """
    if enc_cert is None and cert is None and responses is None and request is None:
        raise ValueError(
            "Either `cert`, `enc_cert`, `responses` or `request` must be provided to build a CA CMP message."
        )

    if request and set_header_fields:
        kwargs = _set_header_fields(request, kwargs)

    if responses is not None:
        # TODO think about extracting the certs from the responses.
        certs = [cert] if cert is not None else []

    elif request and cert is None and enc_cert is None:
        kwargs["eku_strict"] = kwargs.get("eku_strict", True)
        if kwargs.get("enforce_lwcmp", True):
            enforce_lwcmp_for_ca(request)
        if request["body"].getName() != "p10cr":
            responses, certs = _process_cert_requests(
                request=request,
                **kwargs,
            )
        else:
            logging.warning("Request was a p10cr, this is not allowed for IP messages.")
            pq_compute_utils.verify_csr_signature(request["body"]["p10cr"])
            cert = certbuildutils.build_cert_from_csr(
                csr=request["body"]["p10cr"],
                ca_key=kwargs.get("ca_key"),
                ca_cert=kwargs.get("ca_cert"),
                hash_alg=kwargs.get("hash_alg", "sha256"),
                extensions=kwargs.get("extensions"),
            )
            cert_req_id = kwargs.get("cert_req_id") or -1
            certs = [cert]
            responses = prepare_cert_response(cert=cert, enc_cert=enc_cert, cert_req_id=cert_req_id)
    else:
        certs = [cert]
        responses = prepare_cert_response(
            cert=cert,
            enc_cert=enc_cert,
            private_key=kwargs.get("private_key"),
            cert_req_id=int(kwargs.get("cert_req_id", 0)),
        )

    body = _prepare_ca_body("ip", responses=responses, ca_pubs=ca_pubs)

    pki_message = cmputils.prepare_pki_message(exclude_fields=exclude_fields, **kwargs)
    pki_message["body"] = body
    return pki_message, certs


def prepare_enc_key(env_data: rfc5652.EnvelopedData, explicit_tag: int = 0) -> rfc9480.EncryptedKey:
    """Prepare an EncryptedKey structure by encapsulating the provided EnvelopedData.

    :param env_data: The EnvelopedData to wrap in the `EncryptedKey` structure.
    :param explicit_tag: The explicitTag id set for the `EncryptedKey` structure
    :return: An `EncryptedKey` object with encapsulated EnvelopedData.
    """
    enc_key = rfc9480.EncryptedKey().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, explicit_tag)
    )

    enc_key["envelopedData"] = env_data
    return enc_key


def prepare_cert_or_enc_cert(
    cert: rfc9480.CMPCertificate, enc_cert: Optional[rfc5652.EnvelopedData] = None
) -> rfc9480.CertOrEncCert:
    """Prepare a CertOrEncCert structure containing either a certificate or encrypted certificate.

    :param cert: A certificate object representing the certificate to include.
    :param enc_cert: An optional EnvelopedData object representing an encrypted certificate.
    :return: A populated CertOrEncCert structure.
    """
    cert_or_enc_cert = rfc9480.CertOrEncCert()
    if cert is not None:
        cert2 = rfc9480.CMPCertificate().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        cert_or_enc_cert["certificate"] = copy_asn1_certificate(cert, cert2)

    if enc_cert is not None:
        enc_key = prepare_enc_key(env_data=enc_cert, explicit_tag=1)
        cert_or_enc_cert["encryptedCert"] = enc_key

    return cert_or_enc_cert


@not_keyword
def prepare_certified_key_pair(
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc9480.EnvelopedData] = None,
    private_key: Optional[rfc9480.EnvelopedData] = None,
) -> rfc9480.CertifiedKeyPair:
    """Prepare a CertifiedKeyPair structure containing certificate or encrypted certificate and an optional private key.

    :param cert: An optional certificate representing the certificate.
    :param enc_cert: An optional EnvelopedData object for the encrypted certificate.
    :param private_key: An optional EnvelopedData object representing the private key.
    :raises ValueError: If both cert and enc_cert are not provided.
    :return: A populated CertifiedKeyPair structure.
    """
    if not cert and not enc_cert:
        raise ValueError("At least one of `cert` or `enc_cert` must be provided to prepare a CertifiedKeyPair.")

    certified_key_pair = rfc9480.CertifiedKeyPair()
    certified_key_pair["certOrEncCert"] = prepare_cert_or_enc_cert(cert=cert, enc_cert=enc_cert)

    if private_key is not None:
        certified_key_pair["privateKey"]["envelopedData"] = private_key

    return certified_key_pair


@keyword(name="Prepare CertResponse")
def prepare_cert_response(
    cert_req_id: Union[str, int] = 0,
    status: str = "accepted",
    text: str = None,
    failinfo: str = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc9480.EnvelopedData] = None,
    private_key: Optional[rfc9480.EnvelopedData] = None,
    rspInfo: Optional[bytes] = None,
) -> CertResponseTMP:
    """Prepare a CertResponse structure for responding to a certificate request.

    :param cert_req_id: The ID of the certificate request being responded to.
    :param status: The status of the certificate request (e.g., "accepted" or "rejected").
    :param text: Optional status text.
    :param failinfo: Optional failure information.
    :param cert: An optional certificate object.
    :param enc_cert: Optional encrypted certificate as EnvelopedData.
    :param private_key: A private key inside the `EnvelopedData` structure
    :param rspInfo: Optional response information. Defaults to `None`.
    :return: A populated CertResponse structure.
    """
    cert_response = CertResponseTMP()
    cert_response["certReqId"] = univ.Integer(int(cert_req_id))
    cert_response["status"] = cmputils.prepare_pkistatusinfo(texts=text, status=status, failinfo=failinfo)

    if cert or enc_cert or private_key:
        cert_response["certifiedKeyPair"] = prepare_certified_key_pair(cert, enc_cert, private_key)

    if rspInfo:
        cert_response["rspInfo"] = univ.OctetString(rspInfo)

    return cert_response


def _verify_encrypted_key_popo(
    popo_priv_key: rfc4211.POPOPrivKey,
    client_public_key: PublicKey,
    ca_key: Optional[PrivateKey] = None,
    password: Optional[str] = None,
    client_cert: Optional[rfc9480.CMPCertificate] = None,
    protection_salt: Optional[bytes] = None,
    expected_name: Optional[str] = None,
) -> None:
    """Verify the `keyEncipherment` and `keyAgreement` POPO processing.

    :param popo_priv_key: The POPOPrivKey structure to verify.
    :param client_public_key: The public key of the client.
    :param ca_key: The CA private key used to unwrap the private key.
    :param password: The password to use for decryption the private key.
    :param client_cert: The client certificate. Defaults to `None`.
    :param protection_salt: The protection salt used to compare to the PWRI protection salt.
    Defaults to `None`.
    :param expected_name: The expected identifier name. Defaults to `None`.
    """
    data = ca_kga_logic.validate_enveloped_data(
        env_data=popo_priv_key["encryptedKey"],
        password=password,
        ee_key=ca_key,
        for_pop=False,
        cmp_protection_cert=client_cert,
        protection_salt=protection_salt,
    )
    enc_key, rest = decoder.decode(data, rfc4211.EncKeyWithID())

    if rest:
        raise BadAsn1Data("EncKeyWithID")

    if not enc_key["identifier"].isValue:
        raise ValueError("EncKeyWithID identifier is missing.")

    if expected_name is not None:
        if enc_key["identifier"]["string"].isValue:
            idf_name = str(enc_key["identifier"]["string"])
            if idf_name != expected_name:
                raise ValueError(f"EncKeyWithID identifier name mismatch. Expected: {expected_name}. Got: {idf_name}")
        else:
            result = compareutils.compare_general_name_and_name(
                enc_key["identifier"]["generalName"], prepare_name(expected_name)
            )
            if not result:
                logging.debug(enc_key["identifier"].prettyPrint())
                raise ValueError("EncKeyWithID identifier name mismatch.")

    data = encoder.encode(enc_key["privateKeyInfo"])

    private_key = parse_key_from_one_asym_key(data)

    if private_key.public_key() != client_public_key:
        raise ValueError("The decrypted key does not match the public key in the certificate request.")


@keyword(name="Process POPOPrivKey")
def process_popo_priv_key(  # noqa: D417 Missing argument descriptions in the docstring
    cert_req_msg: rfc4211.CertReqMsg,
    ca_key: PrivateKey,
    password: Optional[str] = None,
    client_cert: Optional[rfc9480.CMPCertificate] = None,
    protection_salt: Optional[bytes] = None,
    expected_identifier: Optional[str] = None,
    shared_secret: Optional[bytes] = None,
) -> None:
    """`keyEncipherment` and `keyAgreement` POPO processing.

    Arguments:
    ---------
        - `cert_req_msg`: The certificate request message.
        - `ca_key`: The CA private key used to unwrap the private key.
        - `password`: The password to use for decryption the private key. Defaults to `None`.
        - `client_cert`: The client certificate. Defaults to `None`.
        - `protection_salt`: The protection salt used to compare to the PWRI protection salt. Defaults to `None`.
        - `expected_identifier`: The expected identifier name. Defaults to `None`.
        - `shared_secret`: The shared secret to use for key agreement. Defaults to `None`.

    Raises:
    ------
        - ValueError: client public key does not match the private key.
        - ValueError: If the decrypted key does not match the public key in the certificate request.
        - ValueError: If the EncKeyWithID identifier name mismatch.
        - BadAsn1Data: If the EncKeyWithID data is invalid.
        - BadPOP: If the `agreeMac` POP is invalid.
        - NotImplementedError: If the POP structure is not supported.
        Supported are: `encryptedKey`, `agreeMAC` or `subsequentMessage`.

    """
    popo: rfc4211.ProofOfPossession = cert_req_msg["popo"]
    type_name = popo.getName()
    name = popo[type_name].getName()
    popo_priv_key: rfc4211.POPOPrivKey = popo[type_name]
    client_public_key = get_public_key_from_cert_req_msg(cert_req_msg)

    if name == "encryptedKey":
        _verify_encrypted_key_popo(
            popo_priv_key=popo_priv_key,
            client_public_key=client_public_key,
            ca_key=ca_key,
            password=password,
            client_cert=client_cert,
            protection_salt=protection_salt,
            expected_name=expected_identifier,
        )

    elif name == "agreeMAC":
        if not isinstance(client_public_key, ECDHPublicKey) and shared_secret is None:
            raise ValueError("Shared secret or client, public key must be provided for ECDH key agreement.")

        if isinstance(client_public_key, ECDHPublicKey) and shared_secret is None:
            shared_secret = perform_ecdh(private_key=ca_key, public_key=client_public_key)

        mac = protectionutils.compute_mac_from_alg_id(
            key=shared_secret,
            data=encoder.encode(cert_req_msg["certReq"]),
            alg_id=popo_priv_key["agreeMAC"]["algId"],
        )

        if mac != popo_priv_key["agreeMAC"]["value"].asOctets():
            raise BadPOP("Invalid `agreeMAC` value as `POP`.")

    elif name == "subsequentMessage":
        if type_name == "keyAgreement":
            if not isinstance(client_public_key, ECDHPublicKey):
                raise BadRequest("ECDH public key is required for key agreement subsequent message.")
        else:
            if not is_kem_public_key(client_public_key):
                raise BadRequest("KEM public key is required for `keyEncipherment` subsequent message.")

    else:
        raise NotImplementedError(
            f"Invalid POP structure: {name}. Expected: `encryptedKey`, `agreeMAC` or `subsequentMessage`"
        )


@keyword(name="Build Cert from CertReqMsg")
def build_cert_from_cert_req_msg(  # noqa: D417 Missing argument descriptions in the docstring
    request: rfc4211.CertReqMsg,
    ca_signing_key: PrivateKey,
    cert: Optional[rfc9480.CMPCertificate] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    ca_key: Optional[PrivateKey] = None,
    cert_req_id: Optional[Union[str, int]] = None,
) -> CertResponseTMP:
    """Build a certificate from a certificate request message.

    Arguments:
    ---------
       - `request`: The certificate request message.
       - `ca_signing_key`: The CA key to sign the certificate with.
       - `cert`: The certificate to build the response for. Defaults to `None`.
       - `ca_cert`: The CA certificate matching the CA key. Defaults to `None`.
       - `ca_key`: The CA private key to sign the response with. Defaults to `None`.
       - `cert_req_id`: The certificate request ID. Defaults to `None`.

    Returns:
    -------
        - The built certificate response.

    """
    cert_response = CertResponseTMP()

    popo: rfc4211.ProofOfPossession = request["popo"]
    cert_req = request["certReq"]

    if request["regInfo"].isValue:
        logging.debug("regInfo is present in the CertReqMsg,but server logic is not supported yet.")

    if request["popo"]["signature"].isValue:
        cert = cert or certbuildutils.build_cert_from_cert_template(
            cert_req["certTemplate"],
            ca_key=ca_signing_key,
            ca_cert=ca_cert,
        )
    elif popo.getName() == "keyEncipherment":
        cert = certbuildutils.build_cert_from_cert_template(csr=cert_req["certTemplate"])
        process_popo_priv_key(cert_req_msg=request, ca_key=ca_key)

    elif popo.getName() == "keyAgreement":
        raise NotImplementedError("keyAgreement is not supported yet.")

    elif popo.getName() == "raVerified":
        logging.debug("raVerified is present in the CertReqMsg,but is not validate in this function.")

    else:
        raise ValueError(
            f"Invalid POP structure: {popo.getName()}. Expected: `signature`, `keyEncipherment` or `raVerified`"
        )

    if cert_req_id is None:
        cert_req_id = cert_req["certReqId"]
    cert_response["certReqId"] = univ.Integer(int(cert_req_id))

    status = cmputils.prepare_pkistatusinfo(texts="Certificate issued", status="accepted")
    cert_response["status"] = status
    cert_response["certifiedKeyPair"] = prepare_certified_key_pair(cert=cert)
    return cert_response


def _perform_encaps_with_keys(
    public_key: PublicKey,
    hybrid_kem_key: Optional[Union[ECDHPrivateKey, HybridKEMPrivateKey]] = None,
) -> Tuple[bytes, bytes, univ.ObjectIdentifier]:
    """Perform encapsulation with the provided keys.

    :param public_key: The public key to encapsulate.
    :param hybrid_kem_key: The hybrid KEM key to use for encapsulation. Defaults to `None`.
    :return: The shared secret and the encapsulated key.
    :raises ValueError: If the public key is not a KEM public key.
    """
    if not is_kem_public_key(public_key):
        raise ValueError(f"Invalid public key for `keyEncipherment`: {type(public_key)}")

    if isinstance(hybrid_kem_key, HybridKEMPrivateKey):
        ss, ct = hybrid_kem_key.encaps(public_key)  # type: ignore
        kem_oid = get_kem_oid_from_key(hybrid_kem_key)
    elif isinstance(public_key, HybridKEMPublicKey):
        ss, ct = public_key.encaps(hybrid_kem_key)  # type: ignore
        kem_oid = get_kem_oid_from_key(public_key)
    else:
        ss, ct = public_key.encaps()
        kem_oid = get_kem_oid_from_key(public_key)

    return ss, ct, kem_oid


# TODO think about also always returning both certificates.
def prepare_encr_cert_for_request(  # noqa: D417 Missing argument descriptions in the docstring
    cert_req_msg: rfc4211.CertReqMsg,
    signing_key: PrivateKey,
    hash_alg: str,
    ca_cert: rfc9480.CMPCertificate,
    new_ee_cert: Optional[rfc9480.CMPCertificate] = None,
    hybrid_kem_key: Optional[Union[HybridKEMPrivateKey, ECDHPrivateKey]] = None,
    client_pub_key: Optional[PQKEMPublicKey] = None,
    **kwargs,
) -> rfc9480.EnvelopedData:
    """Prepare an encrypted certificate for a request.

    Either used as a challenge for non-signing keys like KEM keys.

    Arguments:
    ---------
       - `cert_req_msg`: The certificate request message.
       - `signing_key`: The CA key to sign the certificate with.
       - `hash_alg`: The hash algorithm to use for signing the certificate (e.g., "sha256").
       - `ca_cert`: The CA certificate matching the CA key.
       - `new_ee_cert`: The new EE certificate to encrypt. Defaults to `None`.
       - `hybrid_kem_key`: The hybrid KEM key to use for encryption. Defaults to `None`.
       - `client_pub_key`: The client public key to use for the RecipientInfo. Defaults to `None`.
       (only used for the newly introduced Catalyst KEM issuing, without using Hybrid KEMs.)

    Returns:
    -------
         - The tagged `EnvelopedData` with the encrypted certificate.

    Raises:
    ------
        - `ValueError`: If the POP type is not `subsequentMessage` with `encrCert`.
        - `ValueError`: If arguments are invalid or missing.

    """
    new_ee_cert = new_ee_cert or certbuildutils.build_cert_from_cert_template(
        cert_template=cert_req_msg["certReq"]["certTemplate"],
        issuer=ca_cert["tbsCertificate"]["subject"],
        ca_key=signing_key,
        hash_alg=hash_alg,
    )

    popo_type = cert_req_msg["popo"]["keyEncipherment"]
    if popo_type.getName() != "subsequentMessage":
        raise ValueError("Only subsequentMessage is supported for KEM keys")

    if str(popo_type["subsequentMessage"]) != "encrCert":
        raise ValueError("Only encrCert is supported for KEM keys")

    spki = new_ee_cert["tbsCertificate"]["subjectPublicKeyInfo"]
    public_key = client_pub_key or keyutils.load_public_key_from_spki(spki)

    target = rfc5652.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    ss, ct, kem_oid = _perform_encaps_with_keys(public_key, hybrid_kem_key)
    cek = kwargs.get("cek") or os.urandom(32)
    kem_recip_info = envdatautils.prepare_kem_recip_info(
        recip_cert=new_ee_cert,
        public_key_recip=public_key,
        cek=cek,
        hybrid_key_recip=hybrid_kem_key,
        kemct=ct,
        shared_secret=ss,
        kem_oid=kem_oid,
    )
    data = encoder.encode(new_ee_cert)
    kem_recip_info = envdatautils.parse_recip_info(kem_recip_info)
    return envdatautils.prepare_enveloped_data(
        recipient_infos=[kem_recip_info],
        cek=cek,
        target=target,
        data_to_protect=data,
        enc_oid=rfc5652.id_data,
    )


@keyword(name="Build pkiconf from CertConf")
def build_pki_conf_from_cert_conf(  # noqa: D417 Missing argument descriptions in the docstring
    request: rfc9480.PKIMessage,
    issued_certs: List[rfc9480.CMPCertificate],
    exclude_fields: Optional[str] = None,
    enforce_lwcmp: bool = True,
    set_header_fields: bool = True,
    **kwargs,
) -> rfc9480.PKIMessage:
    """Build a PKI Confirmation message from a Certification Confirmation message.

    Ensures that the client correly received the certificates.

    Arguments:
    ---------
       - `request`: The CertConf message to build the PKIConf message from.
       - `issued_certs`: The certificates that were issued.
       - `exclude_fields`: The fields to exclude from the PKIConf message. Defaults to `None`.
       - `enforce_lwcmp`: Whether to enforce LwCMP rules. Defaults to `True`.
       - `set_header_fields`: Whether to set the header fields. Defaults to `True`.

    Returns:
    -------
         - The built PKI Confirmation message.

    Raises:
    ------
        - `ValueError`: If the request is not a CertConf message.
        - `ValueError`: If the number of CertConf entries does not match the number of issued certificates.
        - `BadRequest`: If the number of CertStatus's is not one (for LwCMP).
        - `BadRequest`: If the CertReqId is not zero (for LwCMP).
        - `BadRequest`: If the certificate status is not `accepted` or `rejection`.
        - `BadPOP`: If the certificate hash is invalid or not present.

    Examples:
    --------
    | ${pki_conf} | Build PKIConf from CertConf | ${request} | ${issued_certs} |

    """
    if request["body"].getName() != "certConf":
        raise ValueError("Request must be a `certConf` to build a `PKIConf` message from it.")

    cert_conf: rfc9480.CertConfirmContent = request["body"]["certConf"]

    if len(cert_conf) != 1 and enforce_lwcmp:
        raise BadRequest(f"Invalid number of entries in CertConf message.Expected 1 for LwCMP, got {len(cert_conf)}")

    if len(cert_conf) != len(issued_certs):
        raise ValueError("Number of CertConf entries does not match the number of issued certificates.")

    entry: rfc9480.CertStatus
    for entry, issued_cert in zip(cert_conf, issued_certs):
        if entry["certReqId"] != 0 and enforce_lwcmp:
            raise BadRequest("Invalid CertReqId in CertConf message.")

        if not entry["certHash"].isValue:
            raise BadPOP("Certificate hash is missing in CertConf message.")

        if entry["statusInfo"].isValue:
            if str(entry["status"]) == "rejection":
                logging.debug("Certificate status was rejection.")
                continue

            elif str(entry["status"]) != "accepted":
                raise BadRequest(
                    "Invalid certificate status in CertConf message."
                    f"Expected 'accepted' or 'rejection', got {entry['status'].getName()}"
                )

        if entry["hashAlg"].isValue:
            logging.warning(entry["hashAlg"])
            if int(request["header"]["pvno"]) != 3:
                raise BadRequest("Hash algorithm is set in CertConf message, but the version is not 3.")
            # expected to be sha256 or similar,
            # is ensured with the flag `only_hash=False`
            hash_alg = get_hash_from_oid(entry["hashAlg"]["algorithm"], only_hash=False)
        else:
            alg_oid = issued_cert["tbsCertificate"]["signature"]["algorithm"]
            hash_alg = get_hash_from_oid(alg_oid, only_hash=True)

        if hash_alg is None:
            raise ValueError(
                "No hash algorithm found for the certificate signature algorithm,"
                "please use version 3 and set the hash algorithm in the `CertConf` message."
            )

        computed_hash = compute_hash(
            alg_name=hash_alg,
            data=encoder.encode(issued_cert),
        )

        if entry["certHash"].asOctets() != computed_hash:
            raise BadPOP("Invalid certificate hash in CertConf message.")

    if request and set_header_fields:
        kwargs = _set_header_fields(request, kwargs)

    pki_message = cmputils.prepare_pki_message(exclude_fields=exclude_fields, **kwargs)
    pki_message["body"]["pkiconf"] = rfc9480.PKIConfirmContent("").subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 19)
    )

    return pki_message


@not_keyword
def get_correct_ca_body_name(request: rfc9480.PKIMessage) -> str:
    """Get the correct body name for the response.

    :param request: The PKIMessage with the request.
    :return: The correct body name for the response.
    :raises ValueError: If the body name is invalid (allowed are `ir`, `cr`, `kur`, `ccr`).
    """
    body_name = request["body"].getName()
    if body_name == "ir":
        return "ip"

    if body_name in ["cr", "p10cr"]:
        return "cp"

    if body_name == "kur":
        return "kup"

    if body_name == "ccr":
        return "ccp"

    raise ValueError(f"Invalid body name: {body_name}")


@not_keyword
def build_ca_message(
    responses: Union[PKIMessageTMP, Sequence[CertResponseTMP]],
    request: Optional[rfc9480.PKIMessage] = None,
    set_header_fields: bool = True,
    body_name: Optional[str] = None,
    **pki_header_fields,
) -> PKIMessageTMP:
    """Build a PKIMessage for a CA response.

    :param responses: The responses to include in the message.
    :param request: The PKIMessage containing the certificate request. Defaults to `None`.
    :param set_header_fields: Whether to set patch the header fields, for the exchange. Defaults to `True`.
    :param pki_header_fields: Additional key-value pairs to set in the header.
    :param body_name: The name of the body to use for the response. Defaults to `None`.
    :return: The PKIMessage for the CA response.
    """
    body_name = body_name or get_correct_ca_body_name(request)

    if request and set_header_fields:
        pki_header_fields = _set_header_fields(request, pki_header_fields)

    pki_message = cmputils.prepare_pki_message(**pki_header_fields)
    pki_message["body"] = _prepare_ca_body(body_name, responses=responses)
    return pki_message


def _contains_cert(cert_template, certs: Sequence[rfc9480.CMPCertificate]) -> Optional[rfc9480.CMPCertificate]:
    """Check if the certificate template is in the list of certificates.

    :param cert_template: The certificate template to check.
    :param certs: The list of certificates to check.
    :return: The certificate if it is in the list, `None` otherwise.
    """
    for cert in certs:
        if compareutils.compare_cert_template_and_cert(cert_template, cert, strict_subject_validation=True):
            return cert
    return None


def _get_revocation_reason(crl_entry_details: rfc9480.Extensions) -> str:
    """Get the revocation reason from the CRL entry details.

    :param crl_entry_details: The `Extensions` object containing the CRL entry details.
    :return: The revocation reason or `unspecified`, if the reason is not set.
    :raises BadRequest: If the CRL entry details are missing or invalid.
    """
    if crl_entry_details.isValue:
        if len(crl_entry_details) != 1:
            raise BadRequest("Invalid number of entries in CRL entry details.")

        if crl_entry_details[0]["extnID"] != rfc5280.id_ce_cRLReasons:
            raise BadRequest("Invalid extension ID in CRL entry details.")

        crl_reasons = crl_entry_details[0]["extnValue"].asOctets()

        try:
            decoded, rest = decoder.decode(crl_reasons, rfc5280.CRLReason())
        except pyasn1.error.PyAsn1Error:
            raise BadAsn1Data("Failed to decode `CRLReason`", overwrite=True)

        if rest:
            raise BadAsn1Data("CRLReason")

        if int(decoded) not in rfc5280.CRLReason.namedValues.values():
            raise BadRequest("Invalid CRL reason value.")

        return decoded.prettyPrint()

    raise BadRequest("CRL entry details are missing.")


def _prepare_cert_id(cert: rfc9480.CMPCertificate) -> rfc4211.CertId:
    """Prepare a CertId structure from a certificate.

    :param cert: The certificate to prepare the CertId for.
    :return: The CertId structure.
    """
    cert_id = rfc4211.CertId()
    cert_id["issuer"] = cert["tbsCertificate"]["issuer"]
    cert_id["serialNumber"] = int(cert["tbsCertificate"]["serialNumber"])
    return cert_id


# TODO fix for bad order od CertID


def build_rp_from_rr(
    request: rfc9480.PKIMessage,
    shared_secret: Optional[bytes] = None,
    set_header_fields: bool = True,
    certs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
    add_another_details: bool = False,
    crls: Optional[Union[rfc5280.CertificateList, Sequence[rfc5280.CertificateList]]] = None,
    **kwargs,
) -> Tuple[rfc9480.PKIMessage, List[Dict[str, Union[str, rfc9480.CMPCertificate]]]]:
    """Build a PKIMessage for a revocation request.

    :param request: The Revocation Request message.
    :param shared_secret: The shared secret to use for the response. Defaults to `None`.
    :param set_header_fields: Whether to set the header fields. Defaults to `True`.
    :return: The built PKIMessage for the revocation response.
    """
    if kwargs.get("enforce_lwcmp", True):
        enforce_lwcmp_for_ca(request)

    body = rfc9480.PKIBody()
    if set_header_fields:
        kwargs = _set_header_fields(request, kwargs)

    fail_info = None
    if not request["extraCerts"].isValue:
        fail_info = "addInfoNotAvailable"
    else:
        try:
            protectionutils.verify_pkimessage_protection(request, shared_secret=shared_secret)
        except Exception:
            logging.debug("Failed to verify the PKIMessage protection.")
            fail_info = "badMessageCheck"

    if fail_info is not None:
        status_info = cmputils.prepare_pkistatusinfo(
            status="rejection",
            failinfo=fail_info,
            texts="The `extraCerts` field was empty in the revocation request message.",
        )
        body["rp"]["status"].append(status_info)
        pki_message = cmputils.prepare_pki_message(**kwargs)
        pki_message["body"] = body
        return pki_message, []

    status = "accepted"

    data = []

    for entry in request["body"]["rr"]:
        tmp = None
        tmp_status = None

        cert = _contains_cert(
            cert_template=entry["certDetails"],
            certs=certs or [],
        )
        if cert is not None:
            reason = _get_revocation_reason(entry["crlEntryDetails"])
            data.append({"reason": reason, "cert": cert})
        else:
            tmp = "badCertTemplate"
            tmp_status = "rejection"

        _add = tmp or fail_info
        tmp_status = tmp_status or status

        status_info = cmputils.prepare_pkistatusinfo(
            status=tmp_status,
            failinfo=_add,
        )
        body["rp"]["status"].append(status_info)

        if not kwargs.get("enforce_lwcmp", True) and cert is not None:
            body["rp"]["revCerts"].append(_prepare_cert_id(cert))

        if add_another_details:
            body["rp"]["status"].append(status_info)

        if crls:
            if isinstance(crls, rfc5280.CertificateList):
                crls = [crls]
            body["rp"]["crls"].extend(crls)

    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body

    return pki_message, data


@keyword(name="Build POPDecryptionChallenge From Request")
def build_popdecc_from_request(  # noqa D417 undocumented-param
    request: rfc9480.PKIMessage,
    ca_key: Optional[ECDHPrivateKey] = None,
    rand_int: Optional[int] = None,
    cert_req_id: Optional[int] = None,
    request_index: Union[int, str] = 0,
    expected_size: Optional[Union[str, int]] = 1,
    set_header_fields: bool = True,
    rand_sender: Optional[str] = "CN=CMP-Test-Suite",
    bad_witness: bool = False,
    for_pvno: Optional[Union[str, int]] = None,
    **kwargs,
) -> Tuple[rfc9480.PKIMessage, int]:
    """Build a PKIMessage for a POPDecryptionChallenge message.

    Arguments:
    ---------
        - `request`: The PKIMessage as raw bytes.
        - `ca_key`: The CA key to use for the challenge. Defaults to `None`.
        - `rand_int`: The random integer to use for the challenge. Defaults to `None`.
        - `cert_req_id`: The certificate request ID. Defaults to `None`.
        - `request_index`: The index of the request. Defaults to `0`.
        - `set_header_fields`: Whether to set the header fields. Defaults to `True`.
        - `rand_sender`: The random sender to use for the challenge. Defaults to `CN=CMP-Test-Suite`.
        - `bad_witness`: Whether manipulate the witness value. Defaults to `False`.
        - `for_pvno`: The protocol version number.
        (decides the challenge type)
        (hash of the random number)
        - `kwargs`: Additional values to set for the header.

    Kwargs:
    -------
        - `hash_alg`: The hash algorithm to use for the random integer. Defaults to `sha256`.
        - `hybrid_kem_key`: The hybrid KEM key to use for the challenge. Defaults to `None`.
        - `iv`: The initialization vector to use for the challenge. Defaults to `A` * 16.
        - `challenge`: The challenge to use for the POPDecryptionChallenge. Defaults to `b""`.
        (only used for negative testing, with version 3)

    Returns:
    -------
        - The built PKIMessage for the POPDecryptionChallenge.

    Raises:
    ------
        - ValueError: If the request index is invalid.

    Examples:
    --------
    | ${response} = | Build POPDecryptionChallenge From Request | ${request} | ${ca_key} |
    | ${response} = | Build POPDecryptionChallenge From Request | ${request} | ${ca_key} | rand_int=2 |

    """
    request_index = int(request_index)
    body_name = request["body"].getName()
    if int(expected_size) != len(request["body"][body_name]):
        raise BadRequest(
            f"Invalid number of entries in {body_name} message. "
            f"Expected: {expected_size}. Got: {len(request['body'][body_name])}"
        )

    public_key = get_public_key_from_cert_req_msg(cert_req_msg=request["body"][body_name][request_index])

    cert_req_id = cert_req_id or int(request["body"][body_name][request_index]["certReq"]["certReqId"])

    rand_int = rand_int or random.randint(1, 1000)

    for_pvno = for_pvno or request["header"]["pvno"]
    for_pvno = int(for_pvno)

    if set_header_fields:
        kwargs = _set_header_fields(request, kwargs)

    pki_message = cmputils.prepare_pki_message(**kwargs)
    tmp = PKIMessageTMP()
    tmp["header"] = pki_message["header"]

    if for_pvno == 3:
        challenge = prepare_challenge_enc_rand(
            public_key=public_key,
            rand_int=rand_int,
            private_key=ca_key,
            rand_sender=rand_sender,
            bad_witness=bad_witness,
            cert_req_id=cert_req_id,
            challenge=kwargs.get("challenge", b""),
            hash_alg=kwargs.get("hash_alg", None),
            hybrid_kem_key=kwargs.get("hybrid_kem_key"),
        )

    else:
        challenge, _, kem_ct_info = prepare_challenge(
            public_key=public_key,
            ca_key=ca_key,
            rand_int=rand_int,
            bad_witness=bad_witness,
            iv=kwargs.get("iv", "A" * 16),
            rand_sender=rand_sender,
            hash_alg=kwargs.get("hash_alg"),
        )
        if kem_ct_info is not None:
            tmp["header"]["generalInfo"].append(kem_ct_info)

    tmp["body"]["popdecc"].append(challenge)

    return tmp, rand_int  # type: ignore
