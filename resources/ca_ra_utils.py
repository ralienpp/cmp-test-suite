# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains functionally which is only needed to test a client CMP-implementation."""

import logging
import os
import random
from typing import Dict, List, Optional, Sequence, Tuple, Union

import pyasn1.error
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pq_logic import pq_compute_utils, py_verify_logic
from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.abstract_pq import PQKEMPublicKey
from pq_logic.migration_typing import HybridKEMPrivateKey, HybridKEMPublicKey, KEMPublicKey
from pq_logic.pq_compute_utils import sign_data_with_alg_id
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
    prepareutils,
    protectionutils,
    utils,
)
from resources.asn1_structures import CertResponseTMP, ChallengeASN1, PKIBodyTMP, PKIMessageTMP
from resources.asn1utils import get_set_bitstring_names, try_decode_pyasn1
from resources.certextractutils import get_extension
from resources.compareutils import is_null_dn
from resources.convertutils import (
    copy_asn1_certificate,
    ensure_is_verify_key,
    str_to_bytes,
    subjectPublicKeyInfo_from_pubkey,
)
from resources.cryptoutils import compute_aes_cbc, perform_ecdh
from resources.exceptions import (
    AddInfoNotAvailable,
    BadAlg,
    BadAsn1Data,
    BadCertId,
    BadCertTemplate,
    BadDataFormat,
    BadMessageCheck,
    BadPOP,
    BadRequest,
    CertRevoked,
    CMPTestSuiteError,
    InvalidAltSignature,
    NotAuthorized,
    SignerNotTrusted,
)
from resources.keyutils import load_public_key_from_cert_template
from resources.oid_mapping import compute_hash, get_hash_from_oid, may_return_oid_to_name, sha_alg_name_to_oid
from resources.typingutils import PrivateKey, PrivateKeySig, PublicKey
from resources.utils import get_openssl_name_notation


def _prepare_issuer_and_ser_num_for_challenge(cert_req_id: int) -> rfc5652.IssuerAndSerialNumber:
    """Prepare the issuer and serial number for the challenge.

    :param cert_req_id: The certificate request ID.
    :return: The populated `IssuerAndSerialNumber` structure.
    """
    issuer_and_ser_num = rfc5652.IssuerAndSerialNumber()
    issuer_and_ser_num["issuer"] = prepareutils.prepare_name("Null-DN")
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
        public_key: KEMPublicKey
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

    if compareutils.is_null_dn(ca_cert["tbsCertificate"]["subject"]):
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


@not_keyword
def build_cmp_ckuann(
    root_ca_key_update: Optional[rfc9480.RootCaKeyUpdateValue] = None,
    new_cert: Optional[rfc9480.CMPCertificate] = None,
    old_cert: Optional[rfc9480.CMPCertificate] = None,
    new_key: Optional[PrivateKey] = None,
    old_key: Optional[PrivateKey] = None,
    use_new: bool = False,
    sender: str = "",
    recipient: str = "",
    pvno: int = 3,
    **kwargs,
) -> PKIMessageTMP:
    """Build a `CAKeyUpdAnnContent` PKIMessage.

    :param new_cert: The new CA certificate to be installed as trust anchor.
    :param old_cert: The old CA certificate, which was the trust anchor.
    :param new_key: The private key corresponding to the new CA certificate.
    :param old_key: The private key corresponding to the old CA certificate.
    :param use_new: Whether to use the new structure or the old one.
    :param sender: The sender of the message.
    :param recipient: The recipient of the message.
    :param pvno: The version of the message.
    :param root_ca_key_update: The root CA key update value. Defaults to `None`.
    :return: The populated `PKIMessage` structure.
    """
    body = PKIBodyTMP()

    if root_ca_key_update is None and not (new_cert and old_cert and new_key and old_key):
        raise ValueError(
            "Either `root_ca_key_update` or `new_cert`, `old_cert`, `new_key`, and `old_key` must be provided."
        )

    if root_ca_key_update is None:
        root_ca_key_update = prepare_new_root_ca_certificate(
            new_cert=new_cert,
            old_cert=old_cert,
            new_priv_key=new_key,
            old_priv_key=old_key,
            hash_alg=kwargs.get("hash_alg", "sha256"),
            use_rsa_pss=kwargs.get("use_rsa_pss", True),
            use_pre_hash=kwargs.get("use_pre_hash", False),
        )

    if use_new:
        body["ckuann"]["cAKeyUpdAnnV3"]["newWithNew"] = root_ca_key_update["newWithNew"]
        body["ckuann"]["cAKeyUpdAnnV3"]["oldWithNew"] = root_ca_key_update["oldWithNew"]
        body["ckuann"]["cAKeyUpdAnnV3"]["newWithOld"] = root_ca_key_update["newWithOld"]
    else:
        body["ckuann"]["cAKeyUpdAnnV2"]["newWithNew"] = root_ca_key_update["newWithNew"]
        body["ckuann"]["cAKeyUpdAnnV2"]["oldWithNew"] = copy_asn1_certificate(root_ca_key_update["oldWithNew"])
        body["ckuann"]["cAKeyUpdAnnV2"]["newWithOld"] = copy_asn1_certificate(root_ca_key_update["newWithOld"])

    pki_message = cmputils.prepare_pki_message(pvno=pvno, sender=sender, recipient=recipient, **kwargs)
    pki_message["body"] = body
    return pki_message


@keyword("Get CertReqMsg From PKIMessage")
def get_cert_req_msg_from_pkimessage(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: PKIMessageTMP, index: int = 0
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
    if body_name in {"ir", "cr", "kur", "ccr"}:
        return pki_message["body"][body_name][index]

    raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, ccr")


def validate_cert_request_cert_id(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: PKIMessageTMP, cert_req_id: Union[str, int] = 0
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
    return keyutils.load_public_key_from_cert_template(cert_req_msg["certReq"]["certTemplate"], must_be_present=True)  # type: ignore


def _prepare_recip_info_for_kga(
    cek: bytes,
    password: Optional[Union[bytes, str]] = None,
    public_key: Optional[PublicKey] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    ec_priv_key: Optional[ECDHPrivateKey] = None,
) -> rfc5652.RecipientInfo:
    """Prepare the recipient info for the key generation action.

    :param cek: The content encryption key to use.
    :param password: The password to use for encrypting the private key. Defaults to `None`.
    :param public_key: The public key to use for encrypting the private key. Defaults to `None`.
    :param cert: The CMP protection certificate to use for `KARI`, `KTRI`
    or the recipient cert for `KEMRI`. Defaults to `None`.
    :param ec_priv_key: The ECDH private key to use for `KARI`. Defaults to `None`.
    :return: The public key of the newly generated private key and the enveloped data containing the private key.
    :raises ValueError: If neither `password` nor `public_key` is provided or
    if the public key type is invalid.
    """
    if password is None and public_key is None:
        raise ValueError("Either `password` or `public_key` must be provided.")

    if public_key is not None:
        if isinstance(public_key, RSAPublicKey):
            recip_info = envdatautils.prepare_ktri(ee_key=public_key, cek=cek, cmp_protection_cert=cert)
        elif isinstance(public_key, ECDHPublicKey):
            recip_info = envdatautils.prepare_kari(
                public_key=public_key, recip_private_key=ec_priv_key, cek=cek, recip_cert=cert
            )
        elif is_kem_public_key(public_key):
            recip_info = envdatautils.prepare_kem_recip_info(
                public_key_recip=public_key,  # type: ignore
                cek=cek,
                recip_cert=cert,
            )
        else:
            raise ValueError(f"Invalid public key type: {type(public_key).__name__}")
    else:
        recip_info = envdatautils.prepare_password_recipient_info(password=password, cek=cek)

    return recip_info  # type: ignore


def _get_kga_key_from_cert_template(cert_template: rfc4211.CertTemplate) -> PrivateKey:
    """Get the key for the key generation action.

    :param cert_template: The certificate template to get the key from.
    :return: The generated key.
    :raises BadCertTemplate: If the key OID is not recognized or if the public key value is set,
    but not the OID.
    """
    alg_name = "rsa"

    oid = cert_template["publicKey"]["algorithm"]["algorithm"]

    if cert_template["publicKey"].isValue:
        if not cert_template["publicKey"]["algorithm"].isValue:
            raise BadCertTemplate("Public key algorithm is missing in the certificate template.")
        if not cert_template["publicKey"]["subjectPublicKey"].isValue:
            raise BadCertTemplate("Public key value is missing in the certificate template.")
        if cert_template["publicKey"]["subjectPublicKey"].asOctets() != b"":
            raise BadPOP("Public key value is set, but not the `POPO`.")

        tmp = may_return_oid_to_name(oid)

        if "." in tmp:
            raise BadCertTemplate(f"Unknown Public key OID: {tmp}", failinfo="badAlg, badCertTemplate")

        alg_name = tmp.replace("Chempat", "chempat")

    return CombinedKeyFactory.generate_key_from_name(alg_name)


def _prepare_private_key_for_kga(
    new_private_key: PrivateKey,
    pki_message: PKIMessageTMP,
    cert: Optional[rfc9480.CMPCertificate] = None,
    password: Optional[Union[bytes, str]] = None,
    kga_cert_chain: Optional[List[rfc9480.CMPCertificate]] = None,
    hash_alg: str = "sha256",
    kga_key: Optional[PrivateKeySig] = None,
    ec_priv_key: Optional[ECDHPrivateKey] = None,
) -> rfc5652.EnvelopedData:
    """Prepare the private key for the key generation action.

    :param pki_message: The PKIMessage to prepare the private key for.
    :param password: The password to use for encrypting the private key. Defaults to `None`.
    :param kga_cert_chain: The KGA certificate chain to use. Defaults to `None`.
    :param hash_alg: The hash algorithm to use. Defaults to "sha256".
    :param kga_key: The key generation authority key to use. Defaults to `None`.
    :param ec_priv_key: The ECDH private key to use for `KARI`. Defaults to `None`.
    :raises BadCertTemplate: If the key OID is not recognized.
    """
    pub_key = None
    if pki_message["extraCerts"].isValue:
        pub_key = keyutils.load_public_key_from_spki(
            pki_message["extraCerts"][0]["tbsCertificate"]["subjectPublicKeyInfo"]
        )

    cek = os.urandom(32)
    recip_info = _prepare_recip_info_for_kga(
        cek=cek,
        password=password,
        public_key=pub_key,
        cert=cert,
        ec_priv_key=ec_priv_key,
    )

    signed_data = envdatautils.prepare_signed_data(
        signing_key=kga_key,
        sig_hash_name=hash_alg,
        cert=kga_cert_chain[0],
        private_keys=[new_private_key],
        cert_chain=kga_cert_chain,
    )
    signed_data_der = encoder.encode(signed_data)
    enveloped_data = envdatautils.prepare_enveloped_data(
        recipient_infos=[recip_info],
        data_to_protect=signed_data_der,
        cek=cek,
    )
    return enveloped_data


@not_keyword
def prepare_cert_and_private_key_for_kga(
    cert_template: rfc4211.CertTemplate,
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: PrivateKeySig,
    kga_cert_chain: Optional[List[rfc9480.CMPCertificate]],
    kga_key: Optional[PrivateKeySig],
    password: Optional[Union[bytes, str]] = None,
    ec_priv_key: Optional[ECDHPrivateKey] = None,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, rfc9480.EnvelopedData]:
    """Prepare a certified key pair for the key generation action.

    :param cert_template: The certificate template to get the key from.
    :param request: The PKIMessage to prepare the private key for.
    :param ca_cert: The CA certificate to matching the private key.
    :param ca_key:  The CA key to sign the certificate with.
    :param password: The password to use for encrypting the private key. Defaults to `None`.
    :param kga_cert_chain: The KGA certificate chain to use. Defaults to `None`.
    :param kga_key: The key generation authority key to sign the signed data with. Defaults to `None`.
    :param ec_priv_key: The ECDH private key to use for `KARI`. Defaults to `None`.
    :param cmp_protection_cert: The CMP protection certificate to use for `KARI`, `KTRI`
    or the recipient cert for `KEMRI`. Defaults to `None`.
    :return: The populated `CertifiedKeyPair` structure.
    """
    if protectionutils.get_protection_type_from_pkimessage(request) == "mac" and password is None:
        raise ValueError("The password must be provided for KGA `PWRI`.")

    if kga_cert_chain is None:
        raise ValueError("`kga_cert_chain` must be provided.")

    private_key = _get_kga_key_from_cert_template(cert_template)
    spki = subjectPublicKeyInfo_from_pubkey(private_key.public_key())
    cert_template["publicKey"]["subjectPublicKey"] = spki["subjectPublicKey"]
    if not cert_template["publicKey"]["algorithm"].isValue:
        cert_template["publicKey"]["algorithm"] = spki["algorithm"]

    cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_template,
        ca_cert=ca_cert,
        ca_key=ca_key,
        extensions=kwargs.get("extensions"),
        hash_alg=kwargs.get("hash_alg", "sha256"),
        use_rsa_pss=kwargs.get("use_rsa_pss", False),
    )

    if is_kem_public_key(private_key.public_key()):
        cmp_protection_cert = cert

    enveloped_data = _prepare_private_key_for_kga(
        new_private_key=private_key,
        pki_message=request,
        password=password,
        kga_cert_chain=kga_cert_chain,
        hash_alg=kwargs.get("hash_alg", "sha256"),
        kga_key=kga_key,
        ec_priv_key=ec_priv_key,
        cert=cmp_protection_cert,
    )
    return cert, enveloped_data


def check_if_request_is_for_kga(pki_message: PKIMessageTMP, index: int = 0) -> bool:
    """Check if the request is for key generation action.

    :param pki_message: The PKIMessage to check.
    :param index: The index of the certificate request to check. Defaults to `0`.
    :return: True if the request is for key generation action, False otherwise.
    :raises ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
    :raises BadCertTemplate: If the key OID is not recognized, or if the public key value is set,
    but not the OID.
    """
    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message, index)
    if not cert_req_msg["popo"].isValue:
        _get_kga_key_from_cert_template(cert_req_msg["certReq"]["certTemplate"])
        return True
    return False


def _verify_pop_signature(
    pki_message: PKIMessageTMP,
    request_index: int = 0,
) -> None:
    """Verify the POP signature in the PKIMessage.

    :param pki_message: The PKIMessage to verify the POP signature for.
    :param request_index: The index of the certificate request to verify the POP for. Defaults to `0`.
    :raises BadAsn1Data: If the CertRequest encoding fails.
    :raises BadPOP: If the POP verification fails.
    :raises InvalidSignature: If the signature verification fails.
    """
    body_name = pki_message["body"].getName()

    try:
        cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message, index=request_index)
        popo: rfc4211.ProofOfPossession = cert_req_msg["popo"]
        if not popo["signature"].isValue:
            raise BadPOP("POP signature is missing in the PKIMessage.")

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
        raise BadPOP(f"Signature POP verification for `{body_name}` failed.") from err


def _verify_ra_verified(
    pki_message: PKIMessageTMP,
    allowed_ra_dir: str = "data/trusted_ras",
    strict_eku: bool = True,
    strict_ku: bool = True,
    verify_ra_verified: bool = True,
    verify_cert_chain: bool = True,
) -> None:
    """Verify the raVerified in the PKIMessage.

    :param pki_message: The PKIMessage to verify the raVerified for.
    :param allowed_ra_dir: The allowed RA directory. Defaults to `None`.
    :param strict_eku: Whether the RA certificate must have the `cmcRA` EKU bit set. Defaults to `True`.
    :param strict_ku: Whether the RA certificate must have the `digitalSignature` KeyUsage bit set. Defaults to `True`.
    :param verify_ra_verified: Whether to verify the `raVerified` or let it pass. Defaults to `True`.
    :param verify_cert_chain: Whether to verify the certificate chain. Defaults to `True`.
    """
    if not verify_ra_verified:
        logging.info("Skipping `raVerified` verification.")
        return

    ra_certs = certutils.load_certificates_from_dir(allowed_ra_dir)

    if len(ra_certs) is None:
        raise ValueError("No RA certificates found in the allowed RA directory.")

    logging.debug("Loaded RA certificates: %d", len(ra_certs))

    if not pki_message["extraCerts"].isValue:
        raise NotAuthorized("RA certificate is missing in the PKIMessage (no `extraCerts`).")

    may_ra_cert = pki_message["extraCerts"][0]
    result = certutils.cert_in_list(may_ra_cert, ra_certs)

    if not result:
        raise NotAuthorized("RA certificate not in allowed RA directory.")

    try:
        certutils.validate_cmp_extended_key_usage(
            cert=may_ra_cert, ext_key_usages="cmcRA", strictness="STRICT" if strict_eku else "LAX"
        )
    except ValueError as err:
        raise NotAuthorized("RA certificate does not have the `cmcRA` EKU bit set.") from err

    try:
        certutils.validate_key_usage(
            cert=may_ra_cert, key_usages="digitalSignature", strictness="STRICT" if strict_ku else "LAX"
        )
    except ValueError as err:
        raise NotAuthorized("RA certificate does not have the `digitalSignature` KeyUsage bit set.") from err

    cert_chain = certutils.build_cmp_chain_from_pkimessage(
        pki_message,
        ee_cert=may_ra_cert,
    )

    if len(cert_chain) == 1 and not certutils.check_is_cert_signer(cert_chain[0], cert_chain[0]):
        raise NotAuthorized("RA certificate is not self-signed, but the certificate chain could not be build.")

    logging.debug("RA certificate chain length: %d", len(cert_chain))
    print("RA certificate chain length:", len(cert_chain))

    if verify_cert_chain:
        try:
            certutils.verify_cert_chain_openssl(
                cert_chain=cert_chain,
                crl_check=False,
                verbose=True,
                timeout=60,
            )
        except SignerNotTrusted as err:
            error_details = [err.message] + err.get_error_details()
            raise NotAuthorized(
                "RA certificate is not trusted, verification with OpenSSL failed.", error_details=error_details
            ) from err


def verify_popo_for_cert_request(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: PKIMessageTMP,
    allowed_ra_dir: str = "data/trusted_ras",
    cert_req_index: Union[int, str] = 0,
    must_have_ra_eku_set: bool = True,
    verify_ra_verified: bool = True,
    verify_cert_chain: bool = True,
) -> None:
    """Verify the Proof-of-Possession (POP) for a certificate request.

    Arguments:
    ---------
       - `pki_message`: The pki message to verify the POP for.
       - `allowed_ra_dir`: The allowed RA directory, filed with trusted RA certificates.
         Defaults to `data/trusted_ras`.
       - `allow_os_store`: Whether to allow the OS store. Defaults to `False`.
       - `cert_req_index`: The index of the certificate request to verify the POP for. Defaults to `0`.
       - `must_have_ra_eku_set`: Whether Extended Key Usage (EKU) CMP-RA bit must be set. Defaults to `True`.
       - `verify_ra_verified`: Whether to verify the `raVerified` or let it pass. Defaults to `True`.
       - `verify_cert_chain`: Whether to verify the certificate chain. Defaults to `True`.

    Raises:
    ------
        - ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
        - ValueError: If the POP structure is invalid
        - ValueError: If the public key type is invalid.
        - NotImplementedError: If the request is for key agreement.
        - BadPOP: If the POP verification fails.
        - NotAuthorized: If the RA certificate is not trusted.

    Examples:
    --------
    | Verify POP Signature For PKI Request | ${pki_message} | ${allowed_ra_dir} | ./data/trustanchors | True |
    | Verify POP Signature For PKI Request | ${pki_message} | verify_ra_verified=False |

    """
    body_name = pki_message["body"].getName()
    if body_name not in {"ir", "cr", "kur", "crr"}:
        raise ValueError(f"Invalid PKIMessage body: {pki_message['body'].getName()} Expected: ir, cr, kur, crr")

    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message, index=cert_req_index)

    if check_if_request_is_for_kga(pki_message=pki_message, index=cert_req_index):
        return

    if not cert_req_msg["popo"].isValue:
        raise BadPOP(f"POP structure is missing in the PKIMessage, for {body_name}")

    name = cert_req_msg["popo"].getName()

    if name == "raVerified":
        _verify_ra_verified(
            pki_message,
            allowed_ra_dir=allowed_ra_dir,
            verify_cert_chain=verify_cert_chain,
            strict_eku=must_have_ra_eku_set,
            verify_ra_verified=verify_ra_verified,
        )

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


def _validate_cert_template(
    cert_template: rfc9480.CertTemplate,
    pop_alg_id: Optional[rfc9480.AlgorithmIdentifier] = None,
    max_key_size: Optional[int] = None,
):
    """Validate that the certificate template has set the correct fields."""
    if not cert_template["subject"].isValue:
        raise BadCertTemplate("The `subject` field is not set inside the certificate template.")

    public_key = keyutils.load_public_key_from_cert_template(cert_template=cert_template, must_be_present=False)
    if isinstance(public_key, DHPublicKey):
        raise BadCertTemplate("The `publicKey` inside the certificate template was a `DH` key, which is not allowed.")

    if isinstance(public_key, DSAPublicKey):
        raise BadCertTemplate("The `publicKey` inside the certificate template was a `DSA` key, which is not allowed.")

    if isinstance(public_key, RSAPublicKey):
        if public_key.key_size < 2048:
            raise BadCertTemplate("The RSA public key was shorter then 2048 bits")

        if max_key_size is not None and public_key.key_size > max_key_size:
            raise BadCertTemplate(f"The RSA public key was longer then {max_key_size} bits")


def respond_to_key_agreement(  # noqa: D417 Missing argument descriptions in the docstring
    cert_req_msg: rfc4211.CertReqMsg,
    ca_key: PrivateKeySig,
    ca_cert: rfc9480.CMPCertificate,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    ca_ecc_key: Optional[EllipticCurvePublicKey] = None,
    ca_x25519: Optional[X25519PrivateKey] = None,
    ca_x448: Optional[X448PrivateKey] = None,
    use_ephemeral: bool = False,
    extensions: Optional[rfc9480.Extensions] = None,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, rfc9480.EnvelopedData]:
    """Respond to a certificate request using key agreement.

    Note:
    ----
       - Assumes that the request includes a public key compatible with key agreement.
       - Requires the CA to have a corresponding private key for key agreement.

    Arguments:
    ---------
       - `cert_req_msg`: The certificate request message containing the key agreement parameters.
       - `ca_key`: The CA private key used to sign the certificate.
       - `ca_cert`: The CA certificate corresponding to the signing key.
       - `cmp_protection_cert`: The CMP protection certificate used in the key agreement. Defaults to `None`.
       - `ca_ecc_key`: The CA’s Elliptic Curve public key for ECDH key agreement. Defaults to `None`.
       - `ca_x25519`: The CA’s X25519 private key for key agreement. Defaults to `None`.
       - `ca_x448`: The CA’s X448 private key for key agreement. Defaults to `None`.
       - `use_ephemeral`: Whether to use an ephemeral key for key agreement. Defaults to `False`.
       - `extensions`: Additional certificate extensions (e.g., OCSP, CRL). Defaults to `None`.

    Returns:
    -------
       - The newly issued certificate and an `EnvelopedData` structure for secure transport.

    Raises:
    ------
       - `ValueError`: If the request contains an invalid public key type.
       - `ValueError`: If no matching CA key is provided for key agreement.

    Examples:
    --------
    | ${cert} | ${env_data} = | Respond To Key Agreement | ${cert_req_msg} | ${ca_key} | ${ca_cert} |
    | ${cert} | ${env_data} = | Respond To Key Agreement | ${cert_req_msg} | ${ca_key} | ${ca_cert} \
    | ${cmp_protection_cert} | ${ca_x25519} | ${use_ephemeral} |

    """
    cert_template = cert_req_msg["certReq"]["certTemplate"]
    public_key = keyutils.load_public_key_from_cert_template(cert_template=cert_template)

    if not isinstance(public_key, ECDHPublicKey):
        raise ValueError(
            f"Invalid public key type, for `keyAgreement`.Expected: ECDHPublicKey, Got: {type(public_key)}"
        )

    if isinstance(public_key, X25519PublicKey):
        server_key = ca_x25519
    elif isinstance(public_key, X448PublicKey):
        server_key = ca_x448
    elif use_ephemeral:
        server_key = keyutils.generate_key("ec", curve=public_key.curve.name)
    else:
        server_key = ca_ecc_key

    if server_key is None:
        raise ValueError(f"The CA key for the matching public key was not provided: Expectedtype: {type(public_key)}")

    cek = os.urandom(32)
    kari = envdatautils.prepare_kari(
        public_key=public_key,
        recip_private_key=server_key,  # type: ignore
        recip_cert=cmp_protection_cert,
        oid=None,
        cek=cek,
        use_ephemeral=use_ephemeral,
    )
    new_ee_cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_template,
        ca_key=ca_key,
        ca_cert=ca_cert,
        extensions=extensions,
    )
    data = encoder.encode(new_ee_cert)
    kari = envdatautils.parse_recip_info(kari)
    env_data = envdatautils.prepare_enveloped_data(
        recipient_infos=[kari],
        cek=cek,
        target=None,
        data_to_protect=data,
        enc_oid=rfc5652.id_data,
    )
    return new_ee_cert, env_data


@keyword(name="Respond To CertReqMsg")
def respond_to_cert_req_msg(  # noqa: D417 Missing argument descriptions in the docstring
    cert_req_msg: rfc4211.CertReqMsg,
    ca_key: PrivateKey,
    ca_cert: rfc9480.CMPCertificate,
    hybrid_kem_key: Optional[ECDHPrivateKey] = None,
    hash_alg: str = "sha256",
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
    **kwargs,
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
    cert_template = cert_req_msg["certReq"]["certTemplate"]

    _validate_cert_template(
        cert_template,
        max_key_size=4096 * 2,
    )

    if not cert_req_msg["popo"].isValue:
        public_key = load_public_key_from_cert_template(cert_template=cert_template, must_be_present=False)

        if public_key:
            raise BadPOP("The public key value is set, but the POPO is missing in the certificate request.")

    if not cert_req_msg["popo"].isValue:
        request = kwargs.get("request")
        body_name = request["body"].getName()
        cert_index = int(kwargs.get("cert_index", 0))
        cert, private_key = prepare_cert_and_private_key_for_kga(
            cert_template=request["body"][body_name][cert_index]["certReq"]["certTemplate"],
            request=request,
            ca_cert=ca_cert,
            ca_key=ca_key,
            kga_cert_chain=kwargs.get("kga_cert_chain"),
            kga_key=kwargs.get("kga_key"),
            password=kwargs.get("password"),
            hash_alg=kwargs.get("hash_alg", "sha256"),
            ec_priv_key=kwargs.get("ec_priv_key"),
            cmp_protection_cert=kwargs.get("cmp_protection_cert"),
            extensions=kwargs.get("extensions"),
        )
        return cert, None, private_key

    name = cert_req_msg["popo"].getName()

    if name in ["raVerified", "signature"]:
        cert = certbuildutils.build_cert_from_cert_template(
            cert_template=cert_template,
            ca_key=ca_key,
            ca_cert=ca_cert,
            extensions=extensions,
        )
        return cert, None, None

    elif name == "keyEncipherment":
        cert = certbuildutils.build_cert_from_cert_template(
            cert_template=cert_template,
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

        return cert, enc_cert, None

    elif name == "keyAgreement":
        cert, enc_cert = respond_to_key_agreement(
            ca_key=ca_key, ca_cert=ca_cert, hash_alg=hash_alg, extensions=extensions, **kwargs
        )
        return cert, enc_cert, None

    else:
        name = cert_req_msg["popo"].getName()
        raise ValueError(f"Invalid POP structure: {name}.")


@keyword(name="Verify POP Signature For PKI Request")
def verify_sig_pop_for_pki_request(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: PKIMessageTMP, cert_index: Union[int, str] = 0
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
            raise BadPOP("POP signature is missing in the PKIMessage.")

        _verify_pop_signature(pki_message, request_index=cert_index)

    elif pki_message["p10cr"]:
        csr = pki_message["p10cr"]
        try:
            pq_compute_utils.verify_csr_signature(csr)
        except InvalidSignature:
            raise BadPOP("POP verification for `p10cr` failed.")

    else:
        raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, crr or p10cr")


@not_keyword
def prepare_ca_body(
    body_name: str,
    responses: Union[Sequence[CertResponseTMP], CertResponseTMP],
    ca_pubs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
) -> PKIBodyTMP:
    """Prepare the body for a CA `CertResponse` message.

    :return: The prepared body.
    """
    types_to_id = {"ip": 1, "cp": 3, "kup": 8, "ccp": 14}
    if body_name not in types_to_id:
        raise ValueError(f"Unsupported body_type: '{body_name}'. Expected one of {list(types_to_id.keys())}.")

    body = PKIBodyTMP()
    if ca_pubs is not None:
        body[body_name]["caPubs"].extend(ca_pubs)

    if isinstance(responses, CertResponseTMP):
        responses = [responses]

    if responses is None:
        raise ValueError("No responses provided to build the body.")

    body[body_name]["response"].extend(responses)
    return body


@not_keyword
def set_ca_header_fields(request: PKIMessageTMP, kwargs: dict) -> dict:
    """Set header fields for a new PKIMessage, by extracting them from the request.

    Includes the setting of the `recipNonce`, `recipKID`, `senderNonce`, `transactionID`, and
    `recipient`, `pvno` fields.

    :param request: The PKIMessage to extract the header fields from.
    :param kwargs: The additional values to set for the header, values if are
    included in the request will not be overwritten.
    """
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
    kwargs["recipient"] = kwargs.get("recipient") or request["header"]["sender"]
    kwargs["pvno"] = kwargs.get("pvno") or int(request["header"]["pvno"])
    return kwargs


def build_cp_from_p10cr(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
    cert: Optional[rfc9480.CMPCertificate] = None,
    set_header_fields: bool = True,
    cert_req_id: Union[int, str] = -1,
    ca_pubs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
    ca_key: Optional[PrivateKey] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    **kwargs,
) -> Tuple[PKIMessageTMP, rfc9480.CMPCertificate]:
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

    Examples:
    --------
    | ${pki_message} | ${cert} = | Build CP From P10CR | ${request} | ${cert} | ${ca_key} | ${ca_cert} |
    | ${pki_message} | ${cert} = | Build CP From P10CR | ${request} | ${cert} | ${ca_key} | ${ca_cert} | cert_req_id=2 |

    """
    if request["body"].getName() != "p10cr":
        raise ValueError("Request must be a p10cr to build a CP message for it.")

    if request and set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

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
    body = prepare_ca_body(body_name="cp", responses=responses, ca_pubs=ca_pubs)
    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, cert


def _process_one_cert_request(
    ca_key: PrivateKey,
    ca_cert: rfc9480.CMPCertificate,
    request: PKIMessageTMP,
    cert_index: int,
    eku_strict: bool,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, Optional[rfc5652.EnvelopedData], Optional[rfc9480.EnvelopedData]]:
    """Process a single certificate response.

    :param ca_key: The CA private key to sign the certificate with.
    :param ca_cert: The CA certificate matching the CA key.
    :param request: The PKIMessage containing the certificate request.
    :param cert_index: The index of the certificate to respond to.
    :param eku_strict: The strictness of the EKU bits.
    :param kwargs: The additional values to set for the header.
    :return: The certificate and the optional encrypted certificate.
    """
    logging.info("Processing certificate request: %d", cert_index)
    logging.debug("Verify RA verified in _process_one_cert: %s", kwargs.get("verify_ra_verified", True))

    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message=request, index=cert_index)

    if cert_req_msg["popo"].isValue:
        if cert_req_msg["popo"].getName() == "signature":
            public_key = get_public_key_from_cert_req_msg(cert_req_msg)
            try:
                keyutils.check_consistency_alg_id_and_key(
                    cert_req_msg["popo"]["signature"]["algorithmIdentifier"], public_key
                )
            except BadAlg:
                raise BadCertTemplate("The `signature` POP alg id and the public key are of different types.")

    elif not cert_req_msg["popo"].isValue:
        if not check_if_request_is_for_kga(request):
            raise BadCertTemplate(
                "The `popo` structure is missing in the PKIMessage."
                "But the request is not for KGA (key generation authority)."
            )

    _validate_cert_template(cert_req_msg["certReq"]["certTemplate"], max_key_size=4096 * 2)

    verify_popo_for_cert_request(
        pki_message=request,
        allowed_ra_dir=kwargs.get("allowed_ra_dir", "./data/trusted_ras"),
        cert_req_index=cert_index,
        must_have_ra_eku_set=eku_strict,
        verify_ra_verified=kwargs.get("verify_ra_verified", True),
    )

    cert, enc_cert, private_key = respond_to_cert_req_msg(
        cert_req_msg=cert_req_msg, request=request, ca_key=ca_key, ca_cert=ca_cert, **kwargs
    )
    return cert, enc_cert, private_key


def _process_cert_requests(
    ca_key: PrivateKey,
    ca_cert: rfc9480.CMPCertificate,
    request: PKIMessageTMP,
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

    logging.warning("Verify RA verified in _process_cert_requests: %s", kwargs.get("verify_ra_verified", True))

    body_name = request["body"].getName()

    for i in range(len(request["body"][body_name])):
        cert, enc_cert, private_key = _process_one_cert_request(
            ca_key=ca_key,
            ca_cert=ca_cert,
            request=request,
            cert_index=i,
            eku_strict=eku_strict,
            **kwargs,
        )
        certs.append(cert)
        cert_req_id = int(request["body"][body_name][i]["certReq"]["certReqId"])
        response = prepare_cert_response(cert=cert, enc_cert=enc_cert, private_key=private_key, cert_req_id=cert_req_id)

        responses.append(response)

    return responses, certs


def build_cp_cmp_message(  # noqa: D417 Missing argument descriptions in the docstring
    request: Optional[PKIMessageTMP] = None,
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
            cert, enc_cert, private_key = _process_one_cert_request(
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

            responses = prepare_cert_response(
                cert=cert, enc_cert=enc_cert, private_key=private_key, cert_req_id=cert_req_id
            )

        else:
            responses, certs = _process_cert_requests(
                ca_key=ca_key,
                ca_cert=ca_cert,
                request=request,
                eku_strict=eku_strict,
                **kwargs,
            )

    if request and set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    kwargs["sender_nonce"] = kwargs.get("sender_nonce") or os.urandom(16)
    body = prepare_ca_body("cp", responses=responses, ca_pubs=kwargs.get("ca_pubs"))
    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, certs


@keyword(name="Enforce LwCMP For CA")
def enforce_lwcmp_for_ca(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
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
    request: Optional[PKIMessageTMP] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc5652.EnvelopedData] = None,
    ca_pubs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
    responses: Optional[Union[Sequence[CertResponseTMP], CertResponseTMP]] = None,
    exclude_fields: Optional[str] = None,
    set_header_fields: bool = True,
    verify_ra_verified: bool = True,
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
        (as an example for OCSP, CRL, etc.)

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
        kwargs = set_ca_header_fields(request, kwargs)

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
                verify_ra_verified=verify_ra_verified,
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

    body = prepare_ca_body("ip", responses=responses, ca_pubs=ca_pubs)
    kwargs["sender_nonce"] = kwargs.get("sender_nonce") or os.urandom(16)
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
    text: Union[List[str], str] = None,
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
                enc_key["identifier"]["generalName"], prepareutils.prepare_name(expected_name)
            )
            if not result:
                logging.debug(enc_key["identifier"].prettyPrint())
                raise ValueError("EncKeyWithID identifier name mismatch.")

    data = encoder.encode(enc_key["privateKeyInfo"])

    private_key = CombinedKeyFactory.load_key_from_one_asym_key(data, must_be_version_2=False)

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
    public_key: KEMPublicKey,
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

    Examples:
    --------
    | ${enc_cert} | Prepare Encr Cert For Request | ${cert_req_msg} | ${signing_key} | ${hash_alg} | ${ca_cert} |

    """
    new_ee_cert = new_ee_cert or certbuildutils.build_cert_from_cert_template(
        cert_template=cert_req_msg["certReq"]["certTemplate"],
        ca_key=signing_key,
        ca_cert=ca_cert,
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


def _validate_cert_status(
    status: rfc9480.PKIStatusInfo,
) -> None:
    """Validate the certificate status.

    :param status: The certificate status to validate.
    :raises BadRequest: If the certificate status is not `accepted` or `rejection`.
    :raises BadRequest: If the certificate status is `accepted`, but a `failInfo` is present.
    """
    if not status.isValue:
        return

    if str(status["status"]) not in {"accepted", "rejection"}:
        raise BadRequest(
            "Invalid certificate status in CertConf message."
            f"Expected 'accepted' or 'rejection', got {status['status'].getName()}"
        )

    if str(status["status"]) == "accepted" and status["failInfo"].isValue:
        raise BadRequest("Certificate status is accepted, but a fail info is present.")


@keyword(name="Build pkiconf from CertConf")
def build_pki_conf_from_cert_conf(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
    issued_certs: List[rfc9480.CMPCertificate],
    exclude_fields: Optional[str] = None,
    enforce_lwcmp: bool = True,
    set_header_fields: bool = True,
    **kwargs,
) -> PKIMessageTMP:
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

        _validate_cert_status(entry["statusInfo"])
        if entry["statusInfo"].isValue:
            if str(entry["statusInfo"]["status"]) == "rejection":
                logging.debug("Certificate status was rejection.")
                continue

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
            raise BadCertId("Invalid certificate hash in CertConf message.")

    if request and set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    pki_message = cmputils.prepare_pki_message(exclude_fields=exclude_fields, **kwargs)
    pki_message["body"]["pkiconf"] = rfc9480.PKIConfirmContent("").subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 19)
    )

    return pki_message


@not_keyword
def get_correct_ca_body_name(request: PKIMessageTMP) -> str:
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
    request: Optional[PKIMessageTMP] = None,
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
        pki_header_fields = set_ca_header_fields(request, pki_header_fields)

    pki_message = cmputils.prepare_pki_message(**pki_header_fields)
    pki_message["body"] = prepare_ca_body(body_name, responses=responses)
    return pki_message


def _contains_cert(cert_template, certs: Sequence[rfc9480.CMPCertificate]) -> Optional[rfc9480.CMPCertificate]:
    """Check if the certificate template is in the list of certificates.

    :param cert_template: The certificate template to check.
    :param certs: The list of certificates to check.
    :return: The certificate if it is in the list, `None` otherwise.
    :raises BadCertId: If the certificate template does not match the certificate or
    If the certificate template does not match any known certificates
    """
    found = False
    for cert in certs:
        found = compareutils.compare_cert_template_and_cert(cert_template, cert, include_fields="serialNumber, issuer")

        if compareutils.compare_cert_template_and_cert(cert_template, cert, strict_subject_validation=True):
            return cert

    if found:
        raise BadCertId("The certificate template did not match the certificate.")

    raise BadCertId("The certificate template did not match any known certificates.")


@keyword(name="Validate RR crlEntryDetails Reason")
def validate_rr_crl_entry_details_reason(  # noqa: D417 Missing argument descriptions in the docstring
    crl_entry_details: rfc9480.Extensions, must_be: Optional[str] = None
) -> str:
    """Validate the extension containing the CRL entry details.

    Arguments:
    ---------
        - `crl_entry_details`: The `Extensions` object containing the CRL entry details.
        - `must_be`: The revocation reason that the CRL entry details must have. Defaults to `None`.

    Returns:
    -------
        - The revocation reason.

    Raises:
    ------
        - `BadRequest`: If the CRL entry details are missing or invalid.
        - `ValueError`: If the revocation reason does not match the expected value.
        - `BadAsn1Data`: If the CRL entry details extension cannot be decoded.

    Examples:
    --------
    | ${reason} | Validate RR crlEntryDetails Reason | ${crl_entry_details} |

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
            raise BadAsn1Data("Invalid CRL reason value.")

        _reason = decoded.prettyPrint()
        if must_be is not None and _reason != must_be:
            raise ValueError(f"Invalid CRL reason. Expected: `{must_be}`. Got: `{_reason}`")
        return _reason

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


def _verify_pkimessage_protection_rp(
    request: PKIMessageTMP,
    shared_secret: Optional[bytes],
) -> Tuple[Optional[str], Optional[str]]:
    """Verify the protection of the PKIMessage for the response.

    :param request: The PKIMessage to verify the protection for.
    :param shared_secret: The shared secret to use for the response. Defaults to `None`.
    :return: The failure information and text if the protection is invalid, `None`, `None` otherwise.
    """
    try:
        py_verify_logic.verify_hybrid_pkimessage_protection(
            request,
        )
    except (InvalidSignature, InvalidAltSignature):
        try:
            protectionutils.verify_pkimessage_protection(request, shared_secret=shared_secret)
        except (ValueError, InvalidSignature):
            logging.debug("Failed to verify the PKIMessage protection.")
            return "badMessageCheck", "Failed to verify the PKIMessage protection."

    return None, None


def _check_rev_details_mandatory_fields(cert_details: rfc9480.CertTemplate) -> None:
    """Check the mandatory fields for a Revocation Request.

    :param cert_details: The certificate details to check.
    :raises AddInfoNotAvailable: If the mandatory fields are missing.
    """
    if not cert_details["issuer"].isValue:
        raise AddInfoNotAvailable("Issuer field is missing in the certificate details.")

    if not cert_details["serialNumber"].isValue:
        raise AddInfoNotAvailable("Serial number field is missing in the certificate details.")

    if cert_details["version"].isValue:
        if int(cert_details["version"]) != int(rfc5280.Version("v2")):
            raise BadRequest("Invalid version inside the `RevDetails` `CertTemplate`.")


def _check_cert_for_revoked(
    cert: rfc9480.CMPCertificate, revoked_certs: Optional[List[rfc9480.CMPCertificate]] = None
) -> None:
    """Check if a certificate is revoked.

    :param cert: The certificate to check.
    :param revoked_certs: The list of revoked certificates. Defaults to `None`.
    :raises BadRequest: If the certificate is not revoked.
    """
    if revoked_certs is not None:
        for revoked_cert in revoked_certs:
            if encoder.encode(cert) == encoder.encode(revoked_cert):
                raise CertRevoked("Certificate is already revoked.")


def _check_cert_for_revive(
    cert: rfc9480.CMPCertificate, revoked_certs: Optional[List[rfc9480.CMPCertificate]] = None
) -> None:
    """Check if a certificate can be revived. Only check if the revoked certificate is not `None`.

    :param cert: The certificate to check.
    :param revoked_certs: The list of revoked certificates. Defaults to `None`.
    :raises BadCertId: If the certificate cannot be revived, because it was not revoked.
    """
    if revoked_certs is not None:
        for revoked_cert in revoked_certs:
            if encoder.encode(cert) == encoder.encode(revoked_cert):
                return
    else:
        return

    raise BadCertId("Certificate can not be revived it was not revoked.")


@keyword(name="Validate Revocation Details")
def validate_rev_details(  # noqa D417 undocumented-param
    rev_details: rfc9480.RevDetails,
    issued_certs: Sequence[rfc9480.CMPCertificate],
    revoked_certs: Optional[List[rfc9480.CMPCertificate]] = None,
) -> Tuple[rfc9480.PKIStatusInfo, Dict]:
    """Process a single Revocation Request entry.

    Arguments:
    ---------
       - `entry`: The RevDetails entry to process.
       - `issued_certs`: The list of certificates to check.
       - `revoked_certs`: The list of revoked certificates. Defaults to `None`.

    Returns:
    -------
        - The PKIStatusInfo for the response.
        - A dictionary containing the reason and the certificate if it was found.
        ({"reason": "removeFromCRL", "cert": `CMPCertificate`})

    Raises:
    ------
        - `AddInfoNotAvailable`: If the mandatory fields are missing (issuer, serial number).
        - `BadRequest`: If the version is set and not 2.
        - `BadCertId`: If the RevDetails entry does not match any of the known certificates.
        - `BadCertID`: If the certificate details are invalid.
        - `BadAsn1Data`: If the CRL entry details extension cannot be decoded or the reason contains
        trailing data or is invalid.
        - `CertRevoked`: If the certificate is already revoked.
        - `BadCertId`: If the certificate cannot be revived, because it was not revoked.

    Examples:
    --------
    | ${response} | Validate Revocation Details | ${entry} | ${issued_certs} |
    | ${response} | Validate Revocation Details | ${entry} | ${issued_certs} | ${revoked_certs} |

    """
    _check_rev_details_mandatory_fields(rev_details["certDetails"])

    cert = _contains_cert(
        cert_template=rev_details["certDetails"],
        certs=issued_certs,
    )
    reason = validate_rr_crl_entry_details_reason(rev_details["crlEntryDetails"])
    if cert is not None:
        if reason == "removeFromCRL":
            msg = f"Revive certificate with serial number: {int(cert['tbsCertificate']['serialNumber'])}"
            _check_cert_for_revive(cert, revoked_certs)
        else:
            _check_cert_for_revoked(cert, revoked_certs)
            msg = f"Revoked certificate with reason: {reason}"
        return cmputils.prepare_pkistatusinfo(status="accepted", texts=msg), {"reason": reason, "cert": cert}

    raise BadCertId("The RevDetails entry does not match any of the known certificates.")


# TODO fix for bad order od CertID


def build_rp_from_rr(  # noqa: D417 missing argument descriptions in the docstring
    request: PKIMessageTMP,
    shared_secret: Optional[bytes] = None,
    set_header_fields: bool = True,
    certs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
    add_another_details: bool = False,
    crls: Optional[Union[rfc5280.CertificateList, Sequence[rfc5280.CertificateList]]] = None,
    verify: bool = True,
    **kwargs,
) -> Tuple[PKIMessageTMP, List[Dict[str, Union[str, rfc9480.CMPCertificate]]]]:
    """Build a PKIMessage for a revocation request.

    Arguments:
    ---------
        - `request`: The Revocation Request message.
        - `shared_secret`: The shared secret to use for the response. Defaults to `None`.
        (experimental used for KEM keys and EC keys)
        - `set_header_fields`: Whether to set the header fields. Defaults to `True`.
        - `certs`: The certificates to use for the response. Defaults to `None`.
        - `add_another_details`: Whether to add another status details. Defaults to `False`.
        - `crls`: The CRLs to include in the response. Defaults to `None`.
        - `verify`: Whether to verify the PKIMessage protection. Defaults to `True`.

    **kwargs:
    --------
        - `enforce_lwcmp` (bool): Whether to enforce LwCMP rules. Defaults to `True`.
        - `cert_id` (CertId): The certificate ID to use for the response. Defaults to `None`.
        - `revoked_certs` (List[rfc9480.CMPCertificate]): The list of revoked certificates. Defaults to `None`.

    Returns:
    -------
        - The built PKIMessage for the revocation response.
        - The data for the revocation response. (reason and certificate) as dict.

    Raises:
    ------
        - `ValueError`: If the request is not a `rr` message.
        - `BadRequest`: If `enforce_lwcmp` is set to `True` and the request size is not 1.
        - `BadRequest`: If the `extraCerts` field is empty in the revocation request message.
        - `BadMessageCheck`: If the PKIMessage protection is invalid.
        - `BadCertTemplate`: If the certificate details are invalid.

    Examples:
    --------
    | ${response} | Build RP from RR | ${request} | ${shared_secret} | ${set_header_fields} | ${certs} |
    | ${response} | Build RP from RR | ${request} | ${certs} | add_another_details=True |

    """
    if kwargs.get("enforce_lwcmp", True):
        enforce_lwcmp_for_ca(request)

    body = rfc9480.PKIBody()
    if set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    fail_info = None

    if verify:
        if not request["extraCerts"].isValue:
            fail_info = "addInfoNotAvailable"
            text = "The `extraCerts` field was empty in the revocation request message."
        else:
            fail_info, text = _verify_pkimessage_protection_rp(
                request=request,
                shared_secret=shared_secret,
            )

    if fail_info is not None:
        status_info = cmputils.prepare_pkistatusinfo(
            status="rejection",
            failinfo=fail_info,
            texts=text,  # pylint: disable=undefined-variable
        )
        body["rp"]["status"].append(status_info)
        pki_message = cmputils.prepare_pki_message(**kwargs)
        pki_message["body"] = body
        return pki_message, []

    data = []

    for entry in request["body"]["rr"]:
        try:
            status_info, entry = validate_rev_details(
                rev_details=entry,
                issued_certs=certs,
                revoked_certs=kwargs.get("revoked_certs"),
            )
        except CMPTestSuiteError as e:
            status_info = cmputils.prepare_pkistatusinfo(
                status="rejection",
                failinfo=e.failinfo,
                texts=e.message,
            )
            entry = {}

        if entry:
            data.append(entry)

        body["rp"]["status"].append(status_info)

        if not kwargs.get("enforce_lwcmp", True):
            cert = _contains_cert(
                cert_template=entry["certDetails"],
                certs=certs,
            )
            body["rp"]["revCerts"].append(kwargs.get("cert_id") or _prepare_cert_id(cert))

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
    request: PKIMessageTMP,
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
) -> Tuple[PKIMessageTMP, int]:
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
        - `cmp_protection_cert`: for KARI to populate the RID. Defaults to `None`.

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
        kwargs = set_ca_header_fields(request, kwargs)

    kwargs["pvno"] = kwargs.get("pvno") or for_pvno
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
            ca_cert=kwargs.get("cmp_protection_cert"),
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


def _validate_old_cert_id(
    control: rfc4211.AttributeTypeAndValue, cert: rfc9480.CMPCertificate, ca_cert: rfc9480.CMPCertificate
) -> None:
    """Validate the old certificate ID inside the KUR message.

    :param control: The control to validate.
    :param cert: The certificate to use for validation.
    :param ca_cert: The CA certificate to use for validation.
    :raises BadRequest: If the old certificate ID is missing.
    :raises BadAsn1Data: If the old certificate ID cannot be decoded or has a remaining part.
    :raises BadCertId: If the old certificate ID does not match the CA certificate.
    """
    if not control["value"].isValue:
        raise BadRequest("Old certificate ID is missing in the KUR message.")

    old_cert_id, rest = try_decode_pyasn1(
        control["value"].asOctets(),
        rfc4211.OldCertId(),
    )
    old_cert_id: rfc4211.OldCertId

    if rest:
        raise BadAsn1Data("OldCertId")

    if not old_cert_id["serialNumber"].isValue:
        raise BadRequest("Serial number is missing in the old certificate ID.")

    if not old_cert_id["issuer"].isValue:
        raise BadRequest("Issuer is missing in the old certificate ID.")

    if not compareutils.compare_general_name_and_name(
        old_cert_id["issuer"],
        ca_cert["tbsCertificate"]["subject"],
    ):
        name_issuer = get_openssl_name_notation(
            old_cert_id["issuer"]["directoryName"],
        )
        cert_name = get_openssl_name_notation(
            ca_cert["tbsCertificate"]["subject"],
        )
        msg = "Expected: " + cert_name + " Got: " + name_issuer
        raise BadCertId(f"Issuer in the old certificate ID does not match the CA certificate.{msg}")

    if int(old_cert_id["serialNumber"]) != int(cert["tbsCertificate"]["serialNumber"]):
        raise BadCertId("Serial number in the old certificate ID does not match the CA certificate.")


def validate_kur_controls(  # noqa D417 undocumented-param
    request: PKIMessageTMP,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    request_index: int = 0,
    must_be_present: bool = False,
) -> None:
    """Validate the KUR controls.

    Arguments:
    ---------
        - `request`: The KUR message to validate.
        - `ca_cert`: The CA certificate to use for validation (will be extracted from the \
        `extraCerts` field at position 1) Defaults to `None`.
        - `request_index`: The index of the request. Defaults to `0`.
        - `must_be_present`: Whether the controls must be present. Defaults to `False`.

    Raises:
    ------
        - `BadRequest`: If the controls are missing in the KUR message.
        - `BadMessageCheck`: If the extraCerts are missing in the KUR message.
        - `BadCertId`: If the old certificate ID is invalid.

    Examples:
    --------
    | Validate KUR Controls | ${request} | ${ca_cert} |
    | Validate KUR Controls | ${request} | ${ca_cert} | must_be_present=True |
    | Validate KUR Controls | ${request} | ${ca_cert} | request_index=1 |

    """
    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message=request, index=request_index)

    controls: rfc4211.Controls = cert_req_msg["certReq"]["controls"]
    if not controls.isValue and must_be_present:
        raise BadRequest("Controls are missing in the KUR message.")
    if not controls.isValue:
        return

    if not request["extraCerts"].isValue:
        raise BadMessageCheck("ExtraCerts are missing in the KUR message.")

    if ca_cert is None:
        ca_cert = request["extraCerts"][1]

    cert = request["extraCerts"][0]

    control: rfc4211.AttributeTypeAndValue

    for control in controls:
        if control["type"] == rfc4211.id_regCtrl_oldCertID:
            _validate_old_cert_id(control, cert=cert, ca_cert=ca_cert)
        else:
            logging.debug(f"Unknown control type: {str(control['type'])}")


def _validate_popo_kur(request: PKIMessageTMP, index: int = 0) -> None:
    """Validate the Proof-of-Possession structure for the KUR message.

    :param request: The request message.
    :param index: The index of the request.
    """
    popo = get_popo_from_pkimessage(request=request, index=index)
    if not popo.isValue:
        raise BadRequest("POP structure is missing in the KUR message.")

    if popo["signature"].isValue:
        _verify_pop_signature(pki_message=request, request_index=index)
        return

    if popo["keyAgreement"].isValue:
        raise NotImplementedError("`keyAgreement` is not supported for KUR messages.")

    if popo["keyEncipherment"].isValue:
        raise NotImplementedError("`keyEncipherment` is not supported for KUR messages.")

    if popo.getName() == "raVerified":
        raise BadPOP("`raVerified` is not supported for KUR messages.")

    raise BadPOP(f"Did got a unknown POP: {popo.getName()}")


def build_kup_from_kur(
    request: PKIMessageTMP,
    ca_key: PrivateKeySig,
    ca_cert: rfc9480.CMPCertificate,
    must_have_controls: bool = False,
    allow_same_key: bool = True,
    **kwargs,
) -> CA_RESPONSE:
    """Build a KUP message from a KUR message.

    :param request: The request message.
    :param ca_key: The CA key used for signing the new certificate.
    :param ca_cert: The CA certificate matching the CA key.
    :param kwargs: Optional parameters to set.
    :param allow_same_key: Whether to allow the same key for the new certificate. Defaults to `False`.
    :return: The KUP message and the new certificate.
    """
    if request["body"].getName() != "kur":
        raise ValueError("Request must be a `kur` message.")

    if len(request["body"]["kur"]) != 1:
        raise BadRequest("Invalid number of entries in KUR message. Expected 1.")

    _validate_popo_kur(
        request=request,
        index=0,
    )

    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message=request)
    if not allow_same_key:
        cert = request["extraCerts"][0]
        pub_key = get_public_key_from_cert_req_msg(cert_req_msg)
        pub_key_cert = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
        if pub_key == pub_key_cert:
            raise BadCertTemplate("The new certificate must not have the same key as the old certificate.")

    validate_kur_controls(request, must_be_present=must_have_controls)

    if cert_req_msg:
        _num = int(cert_req_msg["certReq"]["certReqId"])
        if _num != 0:
            raise BadRequest(f"Invalid CertReqId in KUR message. Expected 0. Got: {_num}")

    cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_req_msg["certReq"]["certTemplate"],
        ca_key=ca_key,
        ca_cert=ca_cert,
    )

    responses = prepare_cert_response(cert=cert, cert_req_id=kwargs.get("cert_req_id", 0))
    body = prepare_ca_body(body_name="kup", responses=responses, ca_pubs=kwargs.get("ca_pubs"))

    kwargs["recip_nonce"] = kwargs.get("recip_nonce") or os.urandom(16)
    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, [cert]


def get_popo_from_pkimessage(request: PKIMessageTMP, index: int = 0) -> rfc4211.ProofOfPossession:
    """Extract the POPO from a PKIMessage.

    :param request: The PKIMessage to extract the Proof-of-Possession from.
    :param index: The `CertMsgReq` index to extract the Proof-of-Possession from.
    """
    body_name = request["body"].getName()
    if body_name not in ["ir", "cr", "kur", "ccr"]:
        raise ValueError(f"The PKIMessage was not a certification request. Got body name: {body_name}")

    return request["body"][body_name][index]["popo"]


@keyword(name="Prepare New CA Certificate")
def prepare_new_ca_certificate(  # noqa D417 undocumented-param
    old_cert: rfc9480.CMPCertificate,
    new_priv_key: PrivateKeySig,
    hash_alg: Optional[str] = "sha256",
    use_rsa_pss: bool = True,
    use_pre_hash: bool = False,
    bad_sig: bool = False,
) -> rfc9480.CMPCertificate:
    """Prepare a new CA certificate.

    Arguments:
    ---------
        - `old_cert`: The old CA certificate.
        - `new_priv_key`: The private key of the new CA certificate.
        - `hash_alg`: The hash algorithm to use for the signature. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature. Defaults to `True`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite signature key. \
        Defaults to `False`.
        - `bad_sig`: Whether to generate a bad signature. Defaults to `False`.

    Returns:
    -------
        - The new CA certificate.

    Raises:
    ------
        - ValueError: If the private key cannot be used for signing.

    Examples:
    --------
    | ${new_ca_cert} | Prepare New CA Certificate | ${old_ca_cert} | ${new_priv_key} |
    | ${new_ca_cert} | Prepare New CA Certificate | ${old_ca_cert} | ${new_priv_key} | sha256 |

    """
    new_cert = rfc9480.CMPCertificate()

    new_cert = copy_asn1_certificate(old_cert, new_cert)

    # Prepare the new certificate
    new_cert["tbsCertificate"]["validity"] = certbuildutils.default_validity()
    new_cert["tbsCertificate"]["serialNumber"] = x509.random_serial_number()
    new_cert["tbsCertificate"]["extensions"] = rfc9480.Extensions().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
    )

    extn = certbuildutils.prepare_extensions(
        key=new_priv_key.public_key(),
        ca_key=new_priv_key.public_key(),
        critical=False,
    )
    new_cert["tbsCertificate"]["extensions"].extend(extn)

    new_cert["tbsCertificate"]["subjectPublicKeyInfo"] = subjectPublicKeyInfo_from_pubkey(new_priv_key.public_key())

    sig_alg = certbuildutils.prepare_sig_alg_id(
        new_priv_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss, use_pre_hash=use_pre_hash
    )

    new_cert["tbsCertificate"]["signature"] = sig_alg
    new_cert["signatureAlgorithm"] = sig_alg
    der_data = encoder.encode(new_cert["tbsCertificate"])

    sig = sign_data_with_alg_id(
        data=der_data,
        key=new_priv_key,
        alg_id=sig_alg,
    )
    if bad_sig:
        sig = utils.manipulate_bytes_based_on_key(sig, key=new_priv_key)

    new_cert["signature"] = univ.BitString.fromOctetString(sig)

    return new_cert


def prepare_old_with_new_cert(  # noqa D417 undocumented-param
    old_cert: rfc9480.CMPCertificate,
    new_cert: rfc9480.CMPCertificate,
    new_priv_key: PrivateKeySig,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    use_pre_hash: bool = True,
    bad_sig: bool = False,
) -> rfc9480.CMPCertificate:
    """Prepare the old certificate signed by the new one.

    Sign the old certificate with the new private key.

    Arguments:
    ---------
        - `old_cert`: The old certificate.
        - `new_cert`: The new certificate.
        - `new_priv_key`: The private key of the new certificate.
        - `hash_alg`: The hash algorithm to use for the signature. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature. Defaults to `True`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite signature key. \
        Defaults to `False`.
        - `bad_sig`: Whether to generate a bad signature. Defaults to `False`.

    Returns:
    -------
        - The old certificate signed by the new one.

    Examples:
    --------
    | ${old_with_new_cert} | Prepare Old With New Cert | ${old_cert} | ${new_cert} | ${new_priv_key} |
    | ${old_with_new_cert} | Prepare Old With New Cert | ${old_cert} | ${new_cert} | ${new_priv_key} | sha256 |

    """
    old_with_new_cert = copy_asn1_certificate(old_cert, rfc9480.CMPCertificate())
    old_with_new_cert["tbsCertificate"]["issuer"] = new_cert["tbsCertificate"]["subject"]
    return certbuildutils.sign_cert(
        cert=old_with_new_cert,
        signing_key=new_priv_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
        bad_sig=bad_sig,
    )


def prepare_new_root_ca_certificate(  # noqa D417 undocumented-param
    old_cert: rfc9480.CMPCertificate,
    old_priv_key: PrivateKeySig,
    new_priv_key: PrivateKeySig,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    use_pre_hash: bool = True,
    bad_sig: bool = False,
    bad_sig_old: bool = False,
    bad_sig_new: bool = False,
    new_cert: Optional[rfc9480.CMPCertificate] = None,
    include_old_with_new: bool = True,
) -> rfc9480.RootCaKeyUpdateValue:
    """Prepare a new `RootCaKeyUpdateValue` structure containing the new root CA certificate.

    Used to simulate a root CA key update message.

    Arguments:
    ---------
        - `old_cert`: The old root CA certificate.
        - `old_priv_key`: The private key of the old root CA certificate.
        - `new_priv_key`: The private key of the new root CA certificate.
        - `hash_alg`: The hash algorithm to use for the signature. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature. Defaults to `True`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite signature key. \
        Defaults to `False`.
        - `bad_sig`: Whether to generate a bad signature for the new CA certificate. Defaults to `False`.
        - `bad_sig_old`: Whether to generate a bad signature for the old certificate signed by the new one. \
        Defaults to `False`.
        - `bad_sig_new`: Whether to generate a bad signature for the new certificate signed by the old one. \
        Defaults to `False`.
        - `new_cert`: The new root CA certificate. Defaults to `None`.
        - `include_old_with_new`: Whether to include the old certificate signed by the new one. Defaults to `True`.

    Returns:
    -------
        - The populated `RootCaKeyUpdateValue` structure.

    Raises:
    ------
        - ValueError: If the signature algorithm is not supported or the private key is not supported.

    Examples:
    --------
    | ${root_ca}= | Prepare New Root CA Certificate | ${old_cert} | ${old_priv_key} | ${new_priv_key} |
    | ${root_ca}= | Prepare New Root CA Certificate | ${old_cert} | ${old_priv_key} | ${new_priv_key} | sha256 | \
    use_rsa_pss=True |
    | ${root_ca}= | Prepare New Root CA Certificate | ${old_cert} | ${old_priv_key} | ${new_priv_key} | \
    new_cert=${new_cert} |

    """
    new_cert = new_cert or prepare_new_ca_certificate(
        old_cert=old_cert,
        new_priv_key=new_priv_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
        bad_sig=bad_sig,
    )

    new_with_old_cert = prepare_old_with_new_cert(
        old_cert=new_cert,
        new_cert=old_cert,
        new_priv_key=old_priv_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
        bad_sig=bad_sig_new,
    )
    old_with_new_cert = None
    if include_old_with_new:
        old_with_new_cert = prepare_old_with_new_cert(
            old_cert=old_cert,
            new_cert=new_cert,
            new_priv_key=new_priv_key,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
            use_pre_hash=use_pre_hash,
            bad_sig=bad_sig_old,
        )

    return prepare_root_ca_key_update(
        new_with_new_cert=new_cert,
        new_with_old_cert=new_with_old_cert,
        old_with_new_cert=old_with_new_cert,
    )


@keyword(name="Prepare RootCAKeyUpdateValue")
def prepare_root_ca_key_update(  # noqa D417 undocumented-param
    new_with_new_cert: Optional[rfc9480.CMPCertificate] = None,
    new_with_old_cert: Optional[rfc9480.CMPCertificate] = None,
    old_with_new_cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc9480.RootCaKeyUpdateValue:
    """Build and return a `RootCaKeyUpdateContent` structure containing the provided certificates.

    Arguments:
    ---------
       - `new_with_new_cert`: The new Root certificate.
       - `new_with_old_cert`: The new CA certificate signed by the old one.
       - `old_with_new_cert`: The old CA certificate signed by the new one.

    Returns:
    -------
        - The populated `RootCaKeyUpdateContent` structure.

    Raises:
    ------
        - `ValueError`: If the provided certificates are not valid.

    Examples:
    --------
    | ${root_ca}= | Build Root CA Key Update Content | ${new_with_new_cert} | ${new_with_old_cert} | \
    ${old_with_new_cert} |

    """
    root_ca_update = rfc9480.RootCaKeyUpdateValue()

    if new_with_new_cert is not None:
        root_ca_update.setComponentByName("newWithNew", new_with_new_cert)

    if new_with_old_cert is not None:
        new_with_old = rfc9480.CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )

        new_with_old_cert = copy_asn1_certificate(new_with_old_cert, new_with_old)
        root_ca_update.setComponentByName("newWithOld", new_with_old_cert)

    if old_with_new_cert is not None:
        old_with_new = rfc9480.CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )

        old_with_new = copy_asn1_certificate(old_with_new_cert, old_with_new)
        root_ca_update.setComponentByName("oldWithNew", old_with_new)

    return root_ca_update


CertsType = Union[rfc9480.CMPCertificate, Sequence[rfc9480.CMPCertificate]]


def _validate_ccr_cert_template(cert_template: rfc9480.CertTemplate) -> rfc9480.CertTemplate:
    """Validate the certificate template for the CCR message.

    :param cert_template: The certificate template to validate.
    :raises BadCertTemplate: If the certificate template is invalid.
    """
    if cert_template["version"].isValue:
        # For now is absent treated as version 3.
        if int(cert_template["version"]) != int(rfc5280.Version("v3")):
            logging.warning("The certificate template version is not v3. But is strongly advised to use v3.")

        if int(cert_template["version"]) == int(rfc5280.Version("v2")):
            raise BadCertTemplate("The certificate template version is allowed to be `v2`.")

    if not cert_template["validity"]["notBefore"].isValue:
        raise BadCertTemplate("For the CA cross certificate request, the `notBefore` field must be set.")

    if not cert_template["validity"]["notAfter"].isValue:
        raise BadCertTemplate("For the CA cross certificate request, the `notAfter` field must be set.")

    if not cert_template["issuer"].isValue:
        raise BadCertTemplate("For the CA cross certificate request, must the `issuer` be set.")

    if is_null_dn(cert_template["issuer"]):
        if get_extension(cert_template["extensions"], rfc5280.id_ce_issuerAltName) is None:
            raise BadCertTemplate("The certificate template must contain an `issuer` or an `issuerAltName`.")

    if not cert_template["subject"].isValue:
        raise BadCertTemplate("For the CA cross certificate request, must the `subject` be set.")

    if not cert_template["subject"].isValue:
        raise BadCertTemplate("The certificate template must contain a subject.")

    if not cert_template["validity"].isValue:
        raise BadCertTemplate("The certificate template must contain a validity period.")

    if cert_template["signingAlg"].isValue:
        logging.debug("The signature algorithm is set in the certificate template.But currently not supported.")

    return cert_template


def _process_crr_single(
    request,
    ca_key,
    ca_cert,
    index: int = 0,
    expected_id: Optional[int] = 0,
) -> rfc9480.CMPCertificate:
    """Process a single CRR message."""
    popo = get_popo_from_pkimessage(request=request, index=index)

    if not popo.isValue:
        raise BadRequest("The CA cross certificate request message must contain a POP structure.")

    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message=request, index=index)
    public_key = keyutils.load_public_key_from_cert_template(cert_req_msg["certReq"]["certTemplate"])
    try:
        _ = ensure_is_verify_key(public_key)
    except ValueError as e:
        raise BadCertTemplate(
            f"The public key in the cross Certificate request is not a signing key.Got: {type(public_key)}",
            error_details=str(e),
        )

    if popo.getName() == "raVerified":
        raise BadRequest("The `raVerified` POP structure is not supported for CA cross certification request.")

    if popo["signature"].isValue:
        _verify_pop_signature(pki_message=request, request_index=index)

    else:
        raise BadPOP("The POP structure must contain a signature, for a CA cross certification request.")

    if expected_id is not None:
        if int(request["body"]["ccr"][index]["certReq"]["certReqId"]) != expected_id:
            raise BadRequest("The `CCR` message `certReqId` must not 0.")

    cert_template = request["body"]["ccr"][index]["certReq"]["certTemplate"]
    result = check_if_request_is_for_kga(pki_message=request, index=index)
    if result:
        raise BadRequest(
            "The `CCR` message can not be for a `KGA` request.The private key must be securely generated by the client."
        )

    _validate_ccr_cert_template(cert_template)

    cert_template = _ensure_key_usage(cert_template)
    cert_template = _ensure_basic_constraints(cert_template)
    cert = certbuildutils.build_cert_from_cert_template(cert_template=cert_template, ca_key=ca_key, ca_cert=ca_cert)
    return cert


def build_ccp_from_ccr(  # noqa D417 undocumented-param
    request: PKIMessageTMP,
    ca_key: Optional[PrivateKeySig] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    **kwargs,
) -> CA_RESPONSE:
    """Build a CCP message from a CCR message.

    Build a CA certificate response message from a CA certificate request.
    Validates the `KeyUsage` bits and the `BasicConstraints` extension.

    Arguments:
    ---------
        - `request`: The CCR message.
        - `ca_key`: The CA key used for signing the new certificate.
        - `ca_cert`: The CA certificate matching the CA key.
        - `certs`: The certificates to use for the response. Defaults to `None`.

    """
    if request["body"].getName() != "ccr":
        raise ValueError("Request must be a `ccr` message.")

    if len(request["body"]["ccr"]) != 1:
        raise BadRequest("Invalid number of entries in CCR message. Expected 1.")

    if not cert:
        # ONLY 1 is allowed, please refer to RFC4210bis-18!
        cert = _process_crr_single(request, ca_key, ca_cert, index=0, expected_id=0)

    responses = prepare_cert_response(
        cert=cert,
        cert_req_id=kwargs.get("cert_req_id", 0),
        text=kwargs.get("text", "Certificate issued"),
        status=kwargs.get("status", "accepted"),
        rspInfo=kwargs.get("rspInfo", None),
    )

    body = prepare_ca_body(body_name="ccp", responses=responses)

    if kwargs.get("set_header_fields", True):
        kwargs = set_ca_header_fields(request, kwargs)

    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, [cert]


def _ensure_key_usage(cert_template: rfc9480.CertTemplate) -> rfc9480.CertTemplate:
    """Ensure that the KeyUsage extension is present in the certificate template."""
    extn = get_extension(cert_template["extensions"], rfc5280.id_ce_keyUsage)
    if extn:
        try:
            decoded_extn, _ = decoder.decode(extn["extnValue"], asn1Spec=rfc5280.KeyUsage())
        except pyasn1.error.PyAsn1Error:
            raise BadDataFormat("The `KeyUsage` extension could not be decoded.")

        required_usages = {"keyCertSign"}
        present_usages = set(get_set_bitstring_names(decoded_extn).split(", "))
        if not required_usages.issubset(present_usages):
            raise BadCertTemplate(
                "KeyUsage extension is present but does not include required key usages."
                f" Got: {present_usages}. Required: {required_usages}."
            )

        if not {"digitalSignature"}.issubset(present_usages):
            logging.warning("Only `keyCertSign` is set not `digitalSignature`")

    else:
        extn = certbuildutils.prepare_key_usage_extension("keyCertSign,digitalSignature", critical=True)
        cert_template["extensions"].append(extn)

    return cert_template


def _ensure_basic_constraints(cert_template: rfc9480.CertTemplate) -> rfc9480.CertTemplate:
    """Ensure that the BasicConstraints extension is present in the certificate template."""
    extn = get_extension(cert_template["extensions"], rfc5280.id_ce_basicConstraints)
    if extn is None:
        extn = certbuildutils.prepare_basic_constraints_extension(ca=True, critical=True)
        cert_template["extensions"].append(extn)
    return cert_template


@not_keyword
def build_kga_cmp_response(
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: PrivateKeySig,
    kga_cert_chain: Optional[List[rfc9480.CMPCertificate]],
    kga_key: Optional[PrivateKeySig] = None,
    password: Optional[Union[bytes, str]] = None,
    hash_alg: str = "sha256",
    set_header_fields: bool = True,
    **kwargs,
) -> CA_RESPONSE:
    """Build a CMP message that responds to a KGA request and returns the newly generated private key to the end entity.

    :param request:        The PKIMessage (e.g., an ir/cr/p10cr) that includes a KGA request
                           (no POP, i.e. no signature). We'll generate the key for it.
    :param ca_cert:        The CA certificate used to sign the newly issued certificate.
    :param ca_key:         The CA's private key.
    :param kga_cert_chain: The full chain for the KGA (including the KGA cert and possibly others).
                           Typically [kga_cert, ca_cert].
    :param kga_key:        The KGA private key if the KGA must sign the "SignedData" that wraps
                           the newly generated private key (optional).
    :param password:       The password used if the KGA uses PWRI instead of KARI/KTRI.
                           (i.e. the client used MAC-based protection on the KGA request.)
    :param hash_alg:       The signature/hash algorithm to use for the newly issued certificate.
    :param set_header_fields: Whether to set common header fields (transactionID, senderNonce, etc.).
    :param kwargs:         Additional fields to pass into the final CMP-building function,
                           such as 'recipient', 'sender', or 'exclude_fields'.

    :return: A tuple (pki_message, [certs]) where pki_message is the newly built CMP message
             with the new certificate & private key in the CertifiedKeyPair. 'certs' is a
             list of the newly issued certificate(s).
    :raises BadRequest: If the request is not recognized or does not represent a valid KGA request.
    """
    body_name = request["body"].getName()

    if len(request["body"][body_name]) != 1:
        raise BadRequest("Invalid number of entries in KGA request. Expected 1.")

    body_name = request["body"].getName()
    if not check_if_request_is_for_kga(request):
        raise BadRequest("This PKIMessage is not a KGA request (the 'popo' is not empty).")

    if body_name not in ("ir", "cr", "p10cr"):
        raise BadRequest(f"Invalid message body for KGA: {body_name}. Must be one of ir, cr, p10cr, or kur.")
    cert_req_msg = get_cert_req_msg_from_pkimessage(request)

    # Actually generate a new key & build the certificate, plus EnvelopedData for the private key
    # (with PWRI, KARI, or KTRI) using existing KGA logic:
    cert, enveloped_data = prepare_cert_and_private_key_for_kga(
        cert_template=cert_req_msg["certReq"]["certTemplate"],
        request=request,
        ca_cert=ca_cert,
        ca_key=ca_key,
        kga_cert_chain=kga_cert_chain,
        kga_key=kga_key,
        password=password,
        hash_alg=hash_alg,
        # For KARI with ephemeral ECDH or KEM:
        ec_priv_key=kwargs.get("ec_priv_key"),
        cmp_protection_cert=kwargs.get("cmp_protection_cert"),
        extensions=kwargs.get("extensions"),
    )

    cert_req_id = int(cert_req_msg["certReq"]["certReqId"])
    cert_response = prepare_cert_response(
        cert_req_id=cert_req_id,
        cert=cert,
        private_key=enveloped_data,  # Goes in 'CertifiedKeyPair.privateKey'
        status="accepted",
        text="New Key Generation completed.",
    )

    if body_name == "ir":
        pki_message, certs = build_ip_cmp_message(
            request=request, responses=cert_response, ca_pubs=None, set_header_fields=set_header_fields, **kwargs
        )
    else:
        pki_message, certs = build_cp_cmp_message(
            request=request, responses=cert_response, set_header_fields=set_header_fields, **kwargs
        )

    return pki_message, certs


def _compare_comp_template(cert_template: rfc9480.CertTemplate, certs: list[rfc9480.CMPCertificate]) -> bool:
    """Check if a `CertTemplate` is already present in a list of certificates.

    :param cert_template: The template to check.
    :param certs: A list of `CMPCertificate` objects to check against.
    """
    for cert in certs:
        if compareutils.compare_cert_template_and_cert(cert_template, cert, strict_subject_validation=True):
            return True
    return False


@not_keyword
def cert_template_exists(
    cert_template: rfc9480.CertTemplate,
    certs: list[rfc9480.CMPCertificate],
    check_only_subject_and_pub_key: bool = True,
) -> bool:
    """Check if a `CertTemplate` is already present in a list of certificates.

    The subject and the public key of the certificate are used for comparison.

    :param cert_template: A CMPCertificate object serving as the reference (template).
    :param certs: A list of CMPCertificate objects to check against.
    :param check_only_subject_and_pub_key: If True, only the subject and public key are compared.
    Defaults to `True`.
    :return: True if a certificate with the same subject and public key
             is found in 'cert_list'. Otherwise, False.
    """
    template_subject = cert_template["subject"]
    pub_key = keyutils.load_public_key_from_cert_template(cert_template)
    if not pub_key:
        return False

    if not check_only_subject_and_pub_key:
        return _compare_comp_template(cert_template, certs)

    for cert in certs:
        cert_subject = cert["tbsCertificate"]["subject"]
        cert_spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
        result = compareutils.compare_pyasn1_names(cert_subject, template_subject, "without_tag")
        result2 = pub_key == keyutils.load_public_key_from_spki(cert_spki)
        if result and result2:
            return True

    return False
