# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains the logic, which allows a Client to have more flexibility in issuing a key.

Because some keys like ML-KEM are not signing keys and need a different Proof-of-Possession mechanism.

"""

import logging

# TODO update for better explanation, if time or after thesis.
from typing import Optional, Union

import pyasn1.error
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey
from pq_logic.migration_typing import HybridKEMPrivateKey, KEMPrivateKey, KEMPublicKey
from pq_logic.pq_utils import is_kem_private_key, is_kem_public_key
from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1.type.base import Asn1Type
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5652, rfc6955, rfc9480, rfc9629
from robot.api.deco import keyword, not_keyword

from resources import asn1utils, cmputils, compareutils, keyutils, utils
from resources.asn1_structures import ChallengeASN1, PKIMessageTMP
from resources.ca_kga_logic import validate_enveloped_data
from resources.certutils import load_public_key_from_cert
from resources.convertutils import str_to_bytes
from resources.cryptoutils import compute_aes_cbc, compute_hmac, perform_ecdh
from resources.envdatautils import (
    build_env_data_for_exchange,
    prepare_issuer_and_serial_number,
    prepare_one_asymmetric_key,
    prepare_recipient_identifier,
)
from resources.exceptions import BadAsn1Data, BadRequest, InvalidKeyCombination
from resources.oid_mapping import compute_hash
from resources.prepareutils import prepare_name
from resources.protectionutils import compute_and_prepare_mac
from resources.typingutils import ECDHPrivKeyTypes, EnvDataPrivateKey, PrivateKey, Strint
from resources.utils import get_openssl_name_notation


@keyword(name="Prepare PKMAC POPO")
def prepare_pkmac_popo(  # noqa D417 undocumented-param
    cert_request: rfc4211.CertRequest,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    private_key: Optional[PrivateKey] = None,
    shared_secret: Optional[Union[bytes, str]] = None,
    mac_alg: str = "password_based_mac",
    salt: Optional[Union[bytes, str]] = None,
    hash_alg: str = "sha256",
    iterations: Strint = 100000,
) -> rfc4211.ProofOfPossession:
    """Prepare the Proof-of-Possession structure for the PKMAC value.

    Arguments:
    ---------
        - `cert_request`: The certificate request to prepare the PoP structure.
        - `ca_cert`: The CA certificate to use for `DH` key exchange. Defaults to `None`.
        - `private_key`: The private key to use `DH` key exchange. Defaults to `None`.
        - `shared_secret`: The shared secret to use for the `ProofOfPossession` structure. Defaults to `None`.
        - `mac_alg`: The MAC algorithm to use for the `ProofOfPossession` structure. Defaults to `password_based_mac`.
        - `salt`: The salt to use for the MAC algorithm. Defaults to `None`.
        - `hash_alg`: The hash algorithm to use for the MAC algorithm. Defaults to `sha256`.
        - `iterations`: The number of iterations to use for the KDF algorithm. Defaults to `100.000`.


    Returns:
    -------
        - The populated `ProofOfPossession` structure.

    Raises:
    ------
        - `ValueError`: If the shared secret or the private key and CA certificate are not provided.

    Examples:
    --------
    | ${popo} = | Prepare PKMAC POPO | ${cert_request} | ${shared_secret} |
    | ${popo} = | Prepare PKMAC POPO | ${cert_request} | ${ca_cert} |

    """
    if shared_secret is None:
        if private_key is None or ca_cert is None:
            raise ValueError("The shared secret or the private key and CA certificate are required.")
        shared_secret = _compute_ss(client_key=private_key, ca_cert=ca_cert)

    shared_secret = str_to_bytes(shared_secret)
    data = encoder.encode(cert_request)
    return _prepare_pkmac_val(
        shared_secret=shared_secret,
        data=data,
        mac_alg=mac_alg,
        for_agreement=False,
        hash_alg=hash_alg,
        iterations=int(iterations),
        salt=salt,
    )


@keyword(name="Prepare EncKeyWithID")
def prepare_enc_key_with_id(  # noqa D417 undocumented-param
    private_key: PrivateKey, sender: Optional[str] = None, use_string: bool = False
) -> rfc4211.EncKeyWithID:
    """Prepare the private key for the Proof-of-Possession structure.

    Arguments:
    ---------
        - `private_key`: A private key to prepare for the PoP structure. Should be a non-signing key.
        - `sender`: The sender name to include in the PoP structure (e.g., `CN=CMP-Test-Suite`).
         Defaults to `None` (must be present if PoP).
        - `use_string`: Whether to use a string for the sender name. Defaults to `False`.
        Otherwise, a `GeneralName` structure is used, which sets the distinguished name.

    Returns:
    -------
      - The populated `EncKeyWithID` structure.

    Examples:
    --------
    | ${enc_key} = | Prepare EncKeyWithID | ${private_key} | ${sender} | use_string=${True} |

    """
    one_asym_key = prepare_one_asymmetric_key(private_key)

    data = rfc4211.EncKeyWithID()

    tmp = rfc4211.PrivateKeyInfo()
    tmp["privateKeyAlgorithm"]["algorithm"] = one_asym_key["privateKeyAlgorithm"]["algorithm"]
    tmp["privateKey"] = one_asym_key["privateKey"]
    tmp["version"] = 0

    data["privateKey"] = tmp
    if sender is not None:
        # MUST be present, if pop.
        if use_string:
            data["identifier"]["string"] = sender
        else:
            data["identifier"]["generalName"] = cmputils.prepare_general_name("directoryName", sender)

    logging.debug("Private key for PoP:  %s", data.prettyPrint())
    return data


@keyword(name="Prepare KEM EnvelopedData For POPO")
def prepare_kem_env_data_for_popo(  # noqa D417 undocumented-param
    ca_cert: rfc9480.CMPCertificate,
    data: Optional[Union[Asn1Type, bytes, str]] = None,
    client_key: Optional[PrivateKey] = None,
    rid_sender: str = "Null-DN",
    cert_req_id: Strint = 0,
    enc_key_sender: str = "CN=CMP-Test-Suite",
    cek: Optional[Union[bytes, str]] = None,
    key_encipherment: bool = True,
    hybrid_key_recip: Optional[HybridKEMPrivateKey] = None,
) -> rfc4211.ProofOfPossession:
    """Prepare a `ProofOfPossession` structure with a CA KEM certificate.

    Built the `EnvelopedData` structure to present the new client key to the CA/RA.

    Arguments:
    ---------
        - `ca_cert`: The CA certificate to use for the KEM-based key exchange.
        - `data`: The data to encrypt with the KEM-based key exchange.
        - `client_key`: The client's private key to send to the CA/RA.
        - `rid_sender`: The sender name to use for the `RecipientIdentifier` structure. Defaults to `Null-DN`.
        - `cert_req_id`: The certificate request ID to use for the `RecipientIdentifier` structure. Defaults to `0`.
        - `enc_key_sender`: The sender name to use for the `EncKeyWithID` structure. Defaults to `CN=CMP-Test-Suite`.
        - `cek`: The Content Encryption Key (CEK) to use for the KEM-based key exchange. Defaults to `None`.
        - `key_encipherment`: Whether to use the `keyEncipherment` or `keyAgreement` option for the `ProofOfPossession`
        structure. Defaults to `True`.
        - `hybrid_key_recip`: The hybrid key recipient to use for the KEM-based key exchange. Defaults to `None`.

    Returns:
    -------
        - The `ProofOfPossession` structure for the KEM-based key exchange.

    Examples:
    --------
    | ${popo} = | Prepare KEM EnvelopedData For POPO | ${ca_cert} | ${data} |
    | ${popo} = | Prepare KEM EnvelopedData For POPO | ${ca_cert} | ${data} | rid_sender=${rid} |

    """
    if data is not None:
        if isinstance(data, Asn1Type):
            data = encoder.encode(data)

        data = str_to_bytes(data)

    elif data is None and client_key is None:
        raise ValueError("Either the data to encrypt is required, or the client key.")

    else:
        data = prepare_enc_key_with_id(private_key=client_key, sender=enc_key_sender)
        data = encoder.encode(data)

    issuer_and_ser = prepare_issuer_and_serial_number(serial_number=int(cert_req_id), issuer=rid_sender)

    env_data = rfc5652.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))

    ca_public_key = keyutils.load_public_key_from_spki(ca_cert["tbsCertificate"]["subjectPublicKeyInfo"])

    if not is_kem_public_key(ca_public_key):
        raise InvalidKeyCombination(f"The KEM env data got an invalid key: {type(ca_public_key).__name__}")

    env_data = build_env_data_for_exchange(
        public_key_recip=ca_public_key,
        cert_sender=ca_cert,
        cek=cek,
        target=env_data,
        data=data,
        issuer_and_ser=issuer_and_ser,
        hybrid_key_recip=hybrid_key_recip,
    )

    if key_encipherment:
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
def is_null_dn(name: rfc5280.Name) -> bool:
    """Check if the given Name is a NULL-DN, meaning it has no RDNs."""
    return encoder.encode(name) == b"\x30\x00"


# TODO verify with Alex, if this functions does too much,
# otherwise add new arg to the `validate_enveloped_data` function.
def _extract_rid(recipient_info: rfc5652.RecipientInfo, kari_index: int = 0) -> rfc5652.IssuerAndSerialNumber:
    """Extract and return the 'rid' field as an IssuerAndSerialNumber or RecipientKeyIdentifier.

    :param recipient_info:
    :param kari_index: The index inside the `RecipientEncryptedKeys` structure to extract the rid of.
    :return: The `IssuerAndSerialNumber` structure if not pwri.
    :raises ValueError: If the 'rid' field type is invalid or not `issuerAndSerialNumber`.
    """
    if recipient_info.getName() == "ktri":
        rid = recipient_info["ktri"]["rid"]
        if rid.getName() != "issuerAndSerialNumber":
            raise ValueError(
                "Invalid 'rid' type found in KeyTransRecipientInfo."
                f"Expected `issuerAndSerialNumber`. Got: {rid.getName()}"
            )

        return rid["issuerAndSerialNumber"]

    if recipient_info.getName() == "ori":
        if recipient_info["ori"]["oriType"] != rfc9629.id_ori_kem:
            raise NotImplementedError("Unsupported `oriType` in OriginatorRecipientInfo. Expected `id_ori_kem`.")

        kemri, _ = decoder.decode(recipient_info["ori"]["oriValue"], rfc9629.KEMRecipientInfo())
        rid = kemri["rid"]
        if rid.getName() != "issuerAndSerialNumber":
            raise ValueError("Invalid 'rid' type found in KEMRecipientInfo. Expected `issuerAndSerialNumber`.")

        return rid["issuerAndSerialNumber"]

    if recipient_info.getName() == "kari":
        recipient_encrypted_key = recipient_info["kari"]["recipientEncryptedKeys"][kari_index]
        rid = recipient_encrypted_key["rid"]
        if rid.getName() != "issuerAndSerialNumber":
            raise ValueError("Invalid 'rid' type in KeyAgreeRecipientIdentifier.")

        return rid["issuerAndSerialNumber"]

    raise ValueError("Unsupported recipient information type.")


def validate_kemri_rid_for_encrypted_cert(  # noqa D417 undocumented-param
    pki_message: PKIMessageTMP,
    key: Optional[Union[KEMPublicKey, KEMPrivateKey]] = None,
    issuer: Optional[str] = None,
    serial_number: Optional[int] = None,
    cert_number: Strint = 0,
) -> None:
    """Validate the RecipientIdentifier inside the KEMRecipientInfo structure for the encrypted certificate.

    Arguments:
    ---------
       - `pki_message`: The PKIMessage containing the KEMRecipientInfo structure.
       - `key`: The KEM key to prepare the expected SubjectKeyIdentifier value. Defaults to `None`.
       - `issuer`: The issuer name to validate against in openssl notation (e.g. `CN=Test-CA`). Defaults to `None`.
       - `serial_number`: The serial number to validate against. Defaults to `None`.
       - `cert_number`: The certificate number to validate against. Defaults to `0`.

    Raises:
    ------
        - `ValueError`: If the RecipientIdentifier is not correctly populated with the expected values.
        - `BadAsn1Data`: If the KEMRecipientInfo decoding has a remainder.
        - `ValueError`: If the `oriType` is not `id_ori_kem`.
        - `ValueError`: If neither the key or issuer and serial number are provided.

    Examples:
    --------
    | Validate KEMRI Rid For Encrypted Cert | ${pki_message} | ${key} | ${issuer} | ${serial_number} |
    | Validate KEMRI Rid For Encrypted Cert | ${pki_message} | ${key} | cert_number=1 |

    """
    body_name = pki_message["body"].getName()
    cert_key_pair: rfc9480.CertifiedKeyPair = asn1utils.get_asn1_value(
        pki_message, query=f"body.{body_name}.response/{cert_number}.certifiedKeyPair"
    )

    recip_info = cert_key_pair["certOrEncCert"]["encryptedCert"]["envelopedData"]["recipientInfos"][0]
    if recip_info.getName() != "ori":
        raise ValueError("Unsupported recipient information type.")

    ori = recip_info["ori"]
    if ori["oriType"] != rfc9629.id_ori_kem:
        raise ValueError("Unsupported `oriType` in OriginatorRecipientInfo. Expected `id_ori_kem`.")

    if not isinstance(ori["oriValue"], rfc9629.KEMRecipientInfo):
        kemri, rest = decoder.decode(ori["oriValue"], rfc9629.KEMRecipientInfo())
        if rest:
            raise BadAsn1Data("KEMRecipientInfo")
    else:
        kemri = ori["oriValue"]

    rid = kemri["rid"]

    rid_name = rid.getName()

    expected_rid = prepare_recipient_identifier(key=key, issuer=issuer, serial_number=serial_number)

    if encoder.encode(rid) != encoder.encode(expected_rid):
        raise ValueError(
            f"Expected RecipientIdentifier: {expected_rid.prettyPrint()}. Got: {rid_name}"
            f" with value: {rid.prettyPrint()}"
        )


@keyword(name="Validate Rid For encryptedRand")
def validate_rid_for_encrypted_rand(  # noqa D417 undocumented-param
    env_data: rfc5652.EnvelopedData,
    cert_req_id: Strint,
    recip_index: Strint = 0,
    kari_index: Strint = 0,
) -> None:
    """Validate the `issuerAndSerialNumber` field inside the encryptRand EnvelopedData structure.

    For the `encryptedRand` field, the sender MUST populate the rid field in the
    EnvelopedData structure using the issuerAndSerialNumber choice. The issuer field
    MUST be the NULL-DN and the serialNumber MUST be the certReqId.

    Arguments:
    ---------
       - `env_data`: The EnvelopedData structure containing the encryptedRand.
       - `cert_req_id`: The certificate request ID to validate against the serialNumber.
       - `recip_index`: The index of the recipientInfo to extract the `rid` field from. Defaults to `0`.
       - `kari_index`: The index of the recipientEncryptedKeys to extract the `rid` field from. Defaults to `0`.

    Raises:
    ------
        - `ValueError`: If the `rid` field is not correctly populated with `NULL-DN` and `certReqId` as `serialNumber`.

    """
    recipient_infos: rfc9480 = env_data["recipientInfos"]
    recipient_info: rfc5652.RecipientInfo = recipient_infos[int(recip_index)]

    rid = _extract_rid(recipient_info=recipient_info, kari_index=int(kari_index))

    # The sender MUST populate the rid field in the EnvelopedData sequence using the
    # issuerAndSerialNumber choice containing a NULL-DN as issuer and the certReqId
    # as serialNumber. The client MAY ignore the rid field

    issuer = rid["issuer"]
    if not is_null_dn(issuer):
        raise ValueError("`rid` field is not correctly populated with `NULL-DN`")

    if int(rid["serialNumber"]) != int(cert_req_id):
        raise ValueError("`rid` field serialNumber is not equal to the `certReqId`")


def _parse_pkimessage_from_der(raw_bytes: bytes) -> PKIMessageTMP:
    """Decode the `PKIMessage` and `POPODecKeyChallContent` from the DER-encoded bytes.

    :param raw_bytes: The DER-encoded `PKIMessage` as bytes.
    :return: The parsed `PKIMessage`.
    :raises BadAsn1Data: If the PKIMessage decoding has a remainder.
    """
    # TODO fix if pyasn1-alt-modules is updated.
    # this was newly added in the draft4210bis-*.
    msg, rest = decoder.decode(raw_bytes, PKIMessageTMP())

    if rest:
        raise BadAsn1Data("PKIMessage")

    return msg


@keyword(name="Process PKIMessage With Popdecc")
def process_pkimessage_with_popdecc(  # noqa D417 undocumented-param
    pki_message: bytes,
    ee_key: Optional[EnvDataPrivateKey] = None,
    password: Optional[Union[str, bytes]] = None,
    challenge_size: Strint = 1,
    challenge_index: Strint = 0,
    cert_req_id: Strint = 0,
    recip_index: Strint = 0,
    expected_size: Strint = 1,
    expected_sender: Optional[str] = None,
    iv: Union[str, bytes] = "A" * 16,
    **kwargs,
) -> rfc9480.PKIMessage:
    """Process the POPODecKeyChallContent structure by decrypting the encryptedRand field or decapsulating the challenge

     When the end-entity wants to issue a key, which is not allowed to sign data, it can indicate to
     use a challenge-response mechanism as Proof-of-Possession. The CA/RA sends a PKIMessage with the
     POPODecKeyChallContent structure containing the encryptedRand field or a challenge.

    The end-entity must process the challenge and return the decrypted challenge as a `Rand` object.
    To prove that the private key is in possession of the end-entity.

    Note:
    ----
       - For the deprecated `challenge` field is AES-CBC-256 used.

    Arguments:
    ---------
        - `pki_message`: The DER-encoded PKIMessage as bytes.
        - `ee_key`: The private key of the end-entity to process the challenge.
        - `password`: Optional password for compute the PKIMessage protection.
        - `challenge_size`: The number of expected challenges inside the `POPODecKeyChallContent` structure.
        Defaults to `1`.
        - `index`: The index of the POPODecKeyChallContent to process the challenge. Defaults to `0`.
        - `cert_req_id`: The certificate request ID to validate against the serialNumber.
        - `recip_index`: The index of the recipientInfo to extract the `rid` field from. Defaults to `0`.
        - `expected_size`: The expected size inside the `EnvelopedData` structure.
        - `expected_sender`: The expected sender name to validate in the `Rand` structure.
        - `**kwargs`: Additional values for the `PKIHeader`.

    Returns:
    -------
        - The PKIMessage with the `popdecr` body set.

    Raises:
    ------
        - `ValueError`: If the PKIMessage decoding has a remainder.
        - `BadRequest`: If the PKIMessage version is invalid.
        - `BadAsn1Data`: If the `PKIMessage` decoding has a remainder.
        - `BadAsn1Data`: If the `Rand` decoding has a remainder.
        - `ValueError`: If the `rid` field is not correctly populated with NULL-DN and `cert_req_id` as `serialNumber`.

    Examples:
    --------
    | ${response} = | Process PKIMessage With Popdecc | ${pki_message} | ${ee_key} |
    | ${response} = | Process PKIMessage With Popdecc | ${pki_message} | password=${password} |

    """
    pki_message = _parse_pkimessage_from_der(pki_message)  # type: ignore

    if len(pki_message["body"]["popdecc"]) != int(challenge_size):
        raise BadRequest(f"Expected {challenge_size} challenges, got {len(pki_message['body']['popdecc'])}")

    popdecc = pki_message["body"]["popdecc"]
    challenge = popdecc[int(challenge_index)]
    validate_popdecc_version(pki_message)  # type: ignore

    if challenge["encryptedRand"].isValue:
        rand = _process_encrypted_rand(
            env_data=challenge["encryptedRand"],
            pki_message=pki_message,  # type: ignore
            password=password,
            ee_key=ee_key,
            recip_index=int(recip_index),
            cert_req_id=int(cert_req_id),
            expected_size=int(expected_size),
        )

    else:
        rand = process_simple_challenge(challenge=challenge, ee_key=ee_key, iv=iv)

    num = rand["int"]
    if expected_sender is not None:
        sender = prepare_name(expected_sender)
        if not compareutils.compare_general_name_and_name(rand["sender"], sender):
            rand_name = get_openssl_name_notation(rand["sender"]["directoryName"])
            raise ValueError(f"Expected sender name: {expected_sender}. Got: {rand_name}")

    response = cmputils._prepare_pki_message(
        **kwargs,
    )

    response["body"]["popdecr"].append(num)

    return response


@not_keyword
def validate_popdecc_version(pki_message: PKIMessageTMP) -> None:
    """Validate the PKIMessage version against the presence of the encryptedRand and challenge fields.

    :param pki_message: The PKIMessage to validate.
    """
    is_enc_present = any(c["encryptedRand"].isValue for c in pki_message["body"]["popdecc"])

    if int(pki_message["header"]["pvno"]) != 3 and is_enc_present:
        raise BadRequest("Invalid PKIMessage version for encryptedRand. Expected version 3.")

    if int(pki_message["header"]["pvno"]) != 2 and not is_enc_present:
        raise BadRequest("Invalid PKIMessage version for challenge. Expected version 2.")


def _process_encrypted_rand(
    env_data: rfc9480.EnvelopedData,
    pki_message: PKIMessageTMP,
    password: Optional[Union[str, bytes]],
    ee_key: Optional[Union[PQKEMPrivateKey, ECDHPrivateKey, RSAPrivateKey, HybridKEMPrivateKey]],
    recip_index: int,
    cert_req_id: int,
    expected_size: int,
) -> rfc9480.Rand:
    """Process the encryptedRand field by decrypting it with the end-entity private key.

    :param env_data: The `EnvelopedData` structure containing the encryptedRand.
    :param pki_message: The PKIMessage containing the encryptedRand.
    :param password: The password to decrypt the encryptedRand.
    :param ee_key: The private key to decrypt the encryptedRand or perform the decapsulation.
    :param recip_index: The index of the recipientInfo to extract the `rid` field from. Defaults to `0`.
    :param cert_req_id: The certificate request ID to validate against the serialNumber.
    the challenge. Defaults to `False`.
    :param expected_size: The expected size inside the `EnvelopedData` structure.
    :return: The decrypted challenge as a `Rand` object.
    :raises BadAsn1Data: If the `Rand` decoding has a remainder.
    :raises ValueError: If the `rid` field is not correctly populated with NULL-DN and `cert_req_id` as `serialNumber`.
    """
    validate_rid_for_encrypted_rand(
        env_data=env_data,
        recip_index=recip_index,
        cert_req_id=cert_req_id,
    )
    raw_bytes = validate_enveloped_data(
        env_data=env_data,
        pki_message=pki_message,
        password=password,
        ee_key=ee_key,
        expected_raw_data=True,
        expected_size=expected_size,
        for_pop=True,
    )

    obj, rest = decoder.decode(raw_bytes, asn1Spec=rfc9480.Rand())
    if rest:
        raise BadAsn1Data("Rand")

    return obj


@not_keyword
def process_simple_challenge(
    challenge: ChallengeASN1,
    iv: Union[str, bytes],
    ee_key: PrivateKey,
    ca_pub_key: Optional[ECDHPublicKey] = None,
    kemct: Optional[bytes] = None,
) -> rfc9480.Rand:
    """Process the challenge value by decrypting or decapuslation it with the end-entity private key.

    :param challenge: The `Challenge` to process.
    :param iv: The initialization vector to use for the AES decryption.
    :param ee_key: The private key to decrypt the challenge.
    :param ca_pub_key: The CA's public key to use for the ECDH key exchange.
    :param kemct: The KEM ciphertext.
    :return: The shared secret as the password field in the PKIMessage.
    :raises ValueError: If the private key type is not supported.
    :raises BadAsn1Data: If the `Rand` decoding has a remainder.
    """
    challenge_val = challenge["challenge"].asOctets()

    if isinstance(ee_key, rsa.RSAPrivateKey):
        rand_data = ee_key.decrypt(challenge_val, padding=padding.PKCS1v15())
        rand_obj, rest = decoder.decode(rand_data, asn1Spec=rfc9480.Rand())
        if rest:
            raise BadAsn1Data("Rand")
        return rand_obj

    if isinstance(ee_key, ECDHPrivateKey):
        ss = perform_ecdh(ee_key, ca_pub_key)
    elif is_kem_private_key(ee_key):
        ss = ee_key.decaps(kemct)
    else:
        raise ValueError(
            f"The private key type is not supported, for processing the challenge.: {type(ee_key).__name__}"
        )

    rand_data = compute_aes_cbc(key=ss, data=challenge_val, iv=str_to_bytes(iv), decrypt=True)
    rand_obj, rest = decoder.decode(rand_data, asn1Spec=rfc9480.Rand())
    if rest:
        raise BadAsn1Data("Rand")
    return rand_obj


def _compute_ss(client_key: ECDHPrivateKey, ca_cert: rfc9480.CMPCertificate) -> bytes:
    """Compute the shared secret (SS) between the client's private key and the CA's public key.

    :param client_key: The client's private key.
    :param ca_cert: The CA's certificate used to obtain the CA's public key.

    :return: The computed shared secret.
    :raises ValueError: If the client key is of an unsupported type.
    """
    pub_key = load_public_key_from_cert(ca_cert)
    if isinstance(client_key, ECDHPrivKeyTypes):
        return perform_ecdh(client_key, pub_key)

    raise ValueError(f"The provided public key type is not expected: {type(client_key).__name__}")


def _prepare_pkmac_val(
    shared_secret: bytes, data: bytes, mac_alg: str, for_agreement: bool = True, bad_pop: bool = False, **mac_params
) -> rfc4211.ProofOfPossession:
    """Prepare the PKMAC value for the Proof-of-Possession structure.

    :param shared_secret: The shared secret to use for the MAC.
    :param data: The data to authenticate with the MAC.
    :param mac_alg: The MAC algorithm to use for the PKMAC value.
    :param for_agreement: The flag to indicate whether the PKMAC value is for key agreement. Defaults to `True`.
    :param mac_params: The additional parameters to use for the MAC algorithm.
    :param bad_pop: Whether to manipulate the first byte of the MAC value. Defaults to `False`.
    :return: The populated Proof-of-Possession structure with the `agreeMAC` field set.
    """
    pkmac_value = rfc4211.PKMACValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
    alg_id, mac_value = compute_and_prepare_mac(key=shared_secret, data=data, mac_alg=mac_alg, **mac_params)

    if bad_pop:
        mac_value = utils.manipulate_first_byte(mac_value)

    pkmac_value["algId"]["algorithm"] = alg_id["algorithm"]
    pkmac_value["algId"]["parameters"] = alg_id["parameters"]
    pkmac_value["value"] = univ.BitString.fromOctetString(mac_value)

    if for_agreement:
        index = 3
        option = "keyAgreement"
    else:
        index = 2
        option = "keyEncipherment"

    popo_priv_key = rfc4211.POPOPrivKey().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, index)
    )
    popo_priv_key["agreeMAC"] = pkmac_value
    popo_structure = rfc4211.ProofOfPossession()
    popo_structure[option] = popo_priv_key
    return popo_structure


@keyword(name="Prepare keyAgreement POPO")
def prepare_key_agreement_popo(  # noqa D417 undocumented-param
    use_encr_cert: bool = True,
    env_data: Optional[rfc9480.EnvelopedData] = None,
    client_key: Optional[ECDHPrivKeyTypes] = None,
    shared_secret: Optional[bytes] = None,
    cert_request: Optional[Union[bytes, rfc4211.CertRequest]] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    mac_alg: str = "password_based_mac",
    bad_pop: bool = False,
    **mac_params,
) -> rfc4211.ProofOfPossession:
    """Prepare a Proof-of-Possession (PoP) structure for a Key Agreement (KA) key.

    This function creates a `ProofOfPossession` structure for key agreement, which may include:
    - An HMAC-based PoP using the client's private key and CA's public key.
    - An encrypted key or subsequent message depending on the `use_encr_cert` flag.

    Arguments:
    ---------
        - `use_encr_cert`: A flag indicating whether to use an encrypted certificate (`True`) or a
        challenge-based message (`False`). Defaults to `True`.
        - `env_data`: `EnvelopedData` object containing encrypted key material.
        - `client_key`: client-side private key for key agreement.
        - `ca_cert`: CA certificate containing the public key for key agreement.
        - `shared_secret`: shared secret for key agreement.
        - `cert_request`: certificate request to authenticate with the MAC.
        - `mac_alg`: The MAC algorithm to use for the POP structure. Defaults to `password_based_mac`.
        - `bad_pop`: A flag indicating whether to manipulate the first byte of the MAC value. Defaults to `False`.

    Returns:
    -------
        - The populated Proof-of-Possession structure for key agreement.

    Raises:
    ------
        - `ValueError`: If the certificate request id not provided for the `agreeMAC` PoP.

    Examples:
    --------
    | ${popo_structure} = | Prepare keyAgreement POPO | use_encr_cert=${True} |
    | ${popo_structure} = | Prepare keyAgreement POPO | use_encr_cert=${False} | client_key=${client_key} \
    | ca_cert=${ca_cert} |

    """
    if client_key is not None and ca_cert is not None:
        shared_secret = _compute_ss(client_key, ca_cert=ca_cert)

    popo_priv_key = rfc4211.POPOPrivKey().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
    if env_data is None and shared_secret is None:
        option = "encrCert" if use_encr_cert else "challenge"
        popo_priv_key["subsequentMessage"] = rfc4211.SubsequentMessage(option).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
    elif shared_secret is not None:
        if cert_request is None:
            raise ValueError("The certificate request is required for `agreeMAC` PoP.")

        if not isinstance(cert_request, bytes):
            cert_request = encoder.encode(cert_request)

        return _prepare_pkmac_val(
            shared_secret=shared_secret,
            data=cert_request,
            for_agreement=True,
            mac_alg=mac_alg,
            bad_pop=bad_pop,
            **mac_params,
        )
    else:
        popo_priv_key["encryptedKey"] = env_data

    popo_structure = rfc4211.ProofOfPossession()
    popo_structure["keyAgreement"] = popo_priv_key
    return popo_structure


@not_keyword
def compute_dh_static_pop(
    ca_cert: rfc9480.CMPCertificate,
    cert_request: rfc4211.CertRequest,
    ss: Optional[bytes] = None,
    private_key: Optional[ECDHPrivateKey] = None,
    use_pkmac: bool = False,
):
    """Compute a static Diffie-Hellman Proof-of-Possession (PoP) value for certificate requests.

    :param ss: The shared secret used for generating the MAC (if not provided, it's computed).
    :param ca_cert: The CA's certificate containing the issuer's public key.
    :param cert_request: The certificate request to be authenticated with the MAC.
    :param private_key: Optionally, the private key used for Diffie-Hellman.
    :param use_pkmac: A flag indicating whether to use the PKMAC value in the PoP structure.

    :return: A populated Proof-of-Possession structure, including either a DH MAC or PKMAC value.
    :raises ValueError: If neither the shared secret nor the private key is provided.
    """
    if not ss and not private_key:
        raise ValueError("Both the shared secret and private key cannot be None")

    if not ss:
        public_key = load_public_key_from_cert(ca_cert)
        ss = perform_ecdh(private_key=private_key, public_key=public_key)

    # as of RFC 2875
    # If either the subject or
    # issuer name in the CA certificate is empty, then the alternative name
    # should be used in its place.

    subject_dn_bytes = encoder.encode(ca_cert["tbsCertificate"]["subject"])
    issuer_dn_bytes = encoder.encode(ca_cert["tbsCertificate"]["issuer"])
    concatenated_data = subject_dn_bytes + ss + issuer_dn_bytes
    key = compute_hash(alg_name="sha1", data=concatenated_data)
    mac = compute_hmac(hash_alg="sha1", key=key, data=encoder.encode(cert_request))

    alg_id = rfc9480.AlgorithmIdentifier()
    alg_id["algorithm"] = rfc6955.id_dhPop_static_sha1_hmac_sha1
    # names differs, but same structure.
    dh_pop_static = rfc6955.DhSigStatic()
    dh_pop_static["hashValue"] = rfc6955.MessageDigest(mac)
    dh_pop_static["issuerAndSerial"] = prepare_issuer_and_serial_number(ca_cert)
    alg_id["algorithm"]["parameters"] = rfc6955.DhSigStatic()

    popo_priv_key = rfc4211.POPOPrivKey().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))

    if use_pkmac:
        pk_mac_val = rfc4211.PKMACValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))

        pk_mac_val["algId"] = alg_id
        pk_mac_val["value"] = univ.BitString().fromOctetString(mac)
        popo_priv_key["agreeMAC"] = pk_mac_val
    else:
        popo_priv_key["dhMAC"] = popo_priv_key["dhMAC"].fromOctetString(mac)

    return popo_priv_key


@keyword(name="Get EncCert From PKIMessage")
def get_enc_cert_from_pkimessage(  # noqa D417 undocumented-param
    pki_message: rfc9480.PKIMessage,
    cert_number: Strint = 0,
    ee_private_key: Optional[PrivateKey] = None,
    server_cert: Optional[rfc9480.CMPCertificate] = None,
    password: Optional[Union[str, bytes]] = None,
    expected_recip_type: Optional[str] = None,
    exclude_rid_check: bool = False,
) -> rfc9480.CMPCertificate:
    """Decrypt an encrypted certificate.

    Extract the decrypted certificate and then decrypts the certificate by processing the recipient info type.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage containing the EncCert to be extracted.
        - `cert_number`: The index of the certified key pair in the response to extract. Defaults to `0`.
        - `ee_private_key`: The end-entity private key to decrypt the EncCert if it is encrypted. Defaults to `None`.
        - `server_cert`: The server's CMPCertificate used for validating the EncCert. Defaults to `None`.
        - `password`: A password for decryption if required by the enveloped data. Defaults to `None`.
        - `expected_recip_type`: Expected recipient type to validate the encrypted data. Defaults to `None`.
        - `exclude_rid_check`: A flag indicating whether to exclude the RecipientIdentifier check. Defaults to `False`.
        (should only be used for KEMRecipientInfo, because the rid should be the recipient cert)

    Returns:
    -------
       - The decrypted certificate.

    Raises:
    ------
       - ValueError: If the envelopedData structure is incorrectly populated.
       - InvalidUnwrap: If the encrypted data cannot be unwrapped.

    Examples:
    --------
    | ${enc_cert}= | Get EncCert From PKIMessage | pki_message=${pki_message} | cert_number=0 | ee_private_key=${key} |
    | ${enc_cert}= | Get EncCert From PKIMessage | pki_message=${pki_message} | cert_number=0 | password=${password} |

    """
    body_name = pki_message["body"].getName()
    cert_key_pair: rfc9480.CertifiedKeyPair = asn1utils.get_asn1_value(
        pki_message, query=f"body.{body_name}.response/{cert_number}.certifiedKeyPair"
    )
    if cert_key_pair["certOrEncCert"]["encryptedCert"].getName() != "envelopedData":
        raise ValueError("The enc certificate field MUST be an `envelopedData` structure")

    env_data = cert_key_pair["certOrEncCert"]["encryptedCert"]["envelopedData"]

    data = validate_enveloped_data(
        env_data=env_data,
        pki_message=pki_message,
        password=password,
        ee_key=ee_private_key,
        cmp_protection_cert=server_cert,
        expected_raw_data=True,
        expected_type=expected_recip_type,
        for_pop=exclude_rid_check,
    )

    try:
        cert, rest = decoder.decode(data, asn1Spec=rfc9480.CMPCertificate())

        if rest != b"":
            raise ValueError(f"Unexpected data after decoding the encrypted certificate: {rest.hex()}")

    except pyasn1.error.PyAsn1Error:
        raise ValueError(f"The decrypted certificate was not decoded-able: {data.hex()}")  # type: ignore

    return cert
