# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Chempat key encapsulation mechanism and corresponding key classes."""

import logging
from typing import List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x448, x25519
from pyasn1.type import univ
from resources.exceptions import InvalidKeyCombination
from robot.api.deco import not_keyword

from pq_logic.kem_mechanism import DHKEMRFC9180
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from pq_logic.keys.abstract_wrapper_keys import (
    AbstractHybridRawPrivateKey,
    AbstractHybridRawPublicKey,
)
from pq_logic.keys.kem_keys import (
    FrodoKEMPrivateKey,
    FrodoKEMPublicKey,
    McEliecePrivateKey,
    McEliecePublicKey,
    MLKEMPrivateKey,
    MLKEMPublicKey,
    Sntrup761PrivateKey,
    Sntrup761PublicKey,
)
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.tmp_oids import CHEMPAT_NAME_2_OID
from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey

CURVE_NAME_2_CONTEXT_NAME = {
    "secp256r1": "P256",
    "brainpoolP256r1": "brainpoolP256",
    "secp384r1": "P384",
    "brainpoolP384r1": "brainpoolP384",
}


@not_keyword
def get_oid_for_chemnpat(
    pq_key: Union[PQKEMPrivateKey, PQKEMPublicKey],
    trad_key: Union[ECDHPrivateKey, ECDHPublicKey],
    curve_name: Optional[str] = None,
) -> univ.ObjectIdentifier:
    """Return the OID for a Chempat key combination.

    :param pq_key: The post-quantum key object.
    :param trad_key: The traditional key object.
    :param curve_name: The name of the elliptic curve.
    :return: The Object Identifier.
    :raises InvalidKeyCombination: If the traditional key type or the post-quantum key type is not supported,
    or if the Chempat key combination is not supported.

    """
    if pq_key.name == "sntrup761":
        pq_name = "sntrup761"

    elif isinstance(pq_key, (McEliecePrivateKey, McEliecePublicKey)):
        pq_name = pq_key.name.replace("-", "").lower()
    elif isinstance(pq_key, (MLKEMPrivateKey, MLKEMPublicKey)):
        pq_name = pq_key.name.upper()

    elif isinstance(pq_key, (FrodoKEMPublicKey, FrodoKEMPrivateKey)):
        pq_name = pq_key.name

    else:
        raise InvalidKeyCombination(f"Unsupported post-quantum key type for Chempat.: {pq_key.name}")

    if isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        curve_name = curve_name or trad_key.curve.name
        trad_name = CURVE_NAME_2_CONTEXT_NAME[curve_name]

    elif isinstance(trad_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        trad_name = "X25519"

    elif isinstance(trad_key, (x448.X448PrivateKey, x448.X448PublicKey)):
        trad_name = "X448"
    else:
        raise InvalidKeyCombination(f"Unsupported traditional key type.: {type(trad_key).__name__}")

    try:
        return CHEMPAT_NAME_2_OID[f"Chempat-{trad_name}-{pq_name}"]
    except KeyError as e:
        raise InvalidKeyCombination(f"Unsupported Chempat key combination: Chempat-{trad_name}-{pq_name}") from e


def _get_trad_name(trad_key: Union[ECDHPrivateKey, ECDHPrivateKey]) -> str:
    """Return the traditional name to generate the context string"""
    if isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        name = CURVE_NAME_2_CONTEXT_NAME[trad_key.curve.name]
    elif isinstance(trad_key, (x448.X448PrivateKey, x448.X448PublicKey)):
        name = "X448"
    elif isinstance(trad_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        name = "X25519"
    else:
        raise ValueError("Unsupported key type.")
    return name


class ChempatKEM:
    """Class implementing a hybrid key encapsulation mechanism (Chempat).

    Combining a traditional KEM (TKEM) with a post-quantum KEM (PQKEM).
    """

    def __init__(self, pq_key: Optional[PQKEMPrivateKey], trad_key: Optional[ECDHPrivateKey] = None):
        """Initialize the ChempatKEM instance with keys.

        :param trad_key: Traditional private.
        :param pq_key: Post-quantum private.
        """
        self.pq_key = pq_key
        self.trad_key = trad_key
        self.context = None
        if pq_key is not None and trad_key is not None:
            self.context = self.get_context()

    def get_context(self) -> bytes:
        """Generate the context string based on the traditional and post-quantum keys.

        The context string uniquely identifies the hybrid KEM configuration, including
        the types of keys in use.

        :return: The context string as bytes.
        :raises InvalidKeyCombination: If the key combination is not supported.
        """
        if self.pq_key.name == "sntrup761":
            pq_name = "sntrup761"

        elif isinstance(self.pq_key, (McEliecePrivateKey, McEliecePublicKey)):
            pq_name = self.pq_key.name.replace("-", "").lower()
        elif isinstance(self.pq_key, (MLKEMPrivateKey, MLKEMPublicKey)):
            pq_name = self.pq_key.name.upper()

        elif isinstance(self.pq_key, (FrodoKEMPrivateKey, FrodoKEMPublicKey)):
            pq_name = self.pq_key.name

        else:
            raise InvalidKeyCombination(f"Unsupported post-quantum key type for Chempat.: {self.pq_key.name}")

        name = bytes(get_ec_trad_name(self.trad_key), "utf-8")

        return b"Chempat-" + name + b"-" + bytes(pq_name, "utf-8")

    @staticmethod
    def _hash_sha3_256(data: bytes) -> bytes:
        """Compute the SHA3-256 hash of the given data.

        :param data: Input data as bytes.
        :return: Hash digest as bytes.
        """
        digest = hashes.Hash(hashes.SHA3_256())
        digest.update(data)
        return digest.finalize()

    @staticmethod
    def trad_public_bytes_raw(trad_key: ECDHPublicKey) -> bytes:
        """Return the raw bytes of the traditional public key.

        :param trad_key: The traditional public key.
        :return: The raw bytes of the traditional public key.
        """
        return DHKEMRFC9180.encode_public_key(trad_key)

    def encaps(self, peer_pq_key: PQKEMPublicKey, trad_pk: ECDHPublicKey) -> Tuple[bytes, bytes]:
        """Perform hybrid key encapsulation with a peer's public key.

        :param peer_pq_key: The peer's post-quantum public key.
        :param trad_pk: The peer's traditional public key.
        :return: A tuple containing the kem combined shared secret and combined ciphertext
        """
        dhkem = DHKEMRFC9180(private_key=self.trad_key)

        ss_T, ct_T = dhkem.encaps(trad_pk)
        self.trad_key = dhkem.private_key
        ss_PQ, ct_PQ = peer_pq_key.encaps()

        pk_trad = DHKEMRFC9180.encode_public_key(trad_pk)
        pk_pq = peer_pq_key.public_bytes_raw()

        if self.context is None:
            self.pq_key = peer_pq_key
            self.context = self.get_context()
            self.pq_key = None

        ss = self.kem_combiner(ss_T, ss_PQ, ct_T, ct_PQ, pk_trad, pk_pq)
        return ss, b"".join([ct_T, ct_PQ])

    def decaps(self, ct: bytes) -> bytes:
        """Perform hybrid key decapsulation using the provided ciphertext.

        :param ct: Concatenated ciphertext of the traditional and post-quantum keys.
        :return: The combined shared secret as bytes.
        :raises ValueError: If the input ciphertext length does not match the expected value.
        """
        nenc = TRAD_ALG_2_NENC[get_ec_trad_name(self.trad_key)]

        if len(ct) != nenc + self.pq_key.ct_length:
            raise ValueError(f"Invalid ciphertext length. Expected: {nenc + self.pq_key.ct_length}, got: {len(ct)}")

        ct_T = ct[0:nenc]
        ct_PQ = ct[nenc:]
        dhkem = DHKEMRFC9180(private_key=self.trad_key)

        ss_T = dhkem.decaps(ct_T)
        ss_PQ = self.pq_key.decaps(ct_PQ)

        pk_trad = DHKEMRFC9180.encode_public_key(self.trad_key.public_key())
        pk_pq = self.pq_key.public_key().public_bytes_raw()

        ss = self.kem_combiner(ss_T, ss_PQ, ct_T, ct_PQ, pk_trad, pk_pq)
        logging.info("Chempat ss: %s", ss)
        return ss

    def kem_combiner(
        self,
        receiver_pk_TKEM: bytes,
        receiver_pk_PQKEM: bytes,
        sender_ct_TKEM: bytes,
        sender_ct_PQKEM: bytes,
        ss_TKEM: bytes,
        ss_PQKEM: bytes,
    ) -> bytes:
        """Generate a hybrid shared secret using traditional-KEM and PQ-KEM.

        :param receiver_pk_TKEM: Public key for the traditional KEM (TKEM) as bytes.
        :param receiver_pk_PQKEM: Public key for the post-quantum KEM (PQKEM) as bytes.
        :param sender_ct_TKEM: Ciphertext from the sender for TKEM as bytes.
        :param sender_ct_PQKEM: Ciphertext from the sender for PQKEM as bytes.
        :param ss_TKEM: Shared secret derived from TKEM as bytes.
        :param ss_PQKEM: Shared secret derived from PQKEM as bytes.
        :return: The hybrid shared secret as bytes.
        """
        hybrid_pk = receiver_pk_TKEM + receiver_pk_PQKEM
        hybrid_ct = sender_ct_TKEM + sender_ct_PQKEM

        h_hybrid_ct = self._hash_sha3_256(hybrid_ct)
        h_hybrid_pk = self._hash_sha3_256(hybrid_pk)

        concatenated_data = ss_TKEM + ss_PQKEM + h_hybrid_ct + h_hybrid_pk + self.context

        hybrid_ss = self._hash_sha3_256(concatenated_data)

        return hybrid_ss


class ChempatPublicKey(AbstractHybridRawPublicKey):
    """Public key class for the Chempat hybrid key encapsulation mechanism."""

    _trad_key: Optional[ECDHPublicKey]
    _pq_key: PQKEMPublicKey

    def __eq__(self, other):
        """Compare the ChempatPublicKey with another object."""
        if isinstance(other, ChempatPublicKey):
            return self.pq_key == other.pq_key and self._trad_key == other.trad_key
        raise ValueError(f"Cannot compare ChempatPublicKey with other types: {type(other)}.")

    def __init__(self, pq_key: PQKEMPublicKey, trad_key: Optional[ECDHPublicKey] = None):
        """Initialize the ChempatPublicKey instance with keys.

        :param pq_key: The post-quantum public key.
        :param trad_key: The traditional public key.
        :raises ValueError: If the trad_key is not None and not an ECDHPublicKey.
        :raises InvalidKeyCombination: If the key combination is not supported.
        """
        super().__init__(pq_key, trad_key)
        if trad_key and not isinstance(trad_key, ECDHPublicKey):
            raise ValueError("Unsupported key type for Chempat the trad_key must be `None` or `ECDHPublicKey`")

        self.chempat_kem = get_oid_for_chemnpat(pq_key, trad_key)

    def public_bytes_raw(self) -> bytes:
        """Return the raw bytes of the public key as concatenation of the post-quantum and traditional keys."""
        return self._pq_key.public_bytes_raw() + ChempatKEM.trad_public_bytes_raw(self._trad_key)

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID for the Chempat key."""
        return get_oid_for_chemnpat(self._pq_key, self.trad_key)

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "ChempatPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :param name: The key name.
        :return: The public key.
        """
        name = name.lower()
        if "sntrup761" in name:
            return ChempatSntrup761PublicKey.from_public_bytes(data, name=name)
        if "mceliece" in name:
            return ChempatMcEliecePublicKey.from_public_bytes(data, name=name)
        if "ml-kem" in name:
            return ChempatMLKEMPublicKey.from_public_bytes(data, name=name)
        if "frodokem" in name:
            return ChempatFrodoKEMPublicKey.from_public_bytes(data, name=name)

        raise NotImplementedError(f"The ChempatPublicKey class does not support key generation. Got name: {name}")

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        nenc = TRAD_ALG_2_NENC[get_ec_trad_name(self.trad_key)]
        return self._pq_key.ct_length + nenc

    @property
    def key_size(self) -> int:
        """Return the key size of the Chempat key."""
        trad_size = TRAD_ALG_2_NENC[get_ec_trad_name(self.trad_key)]
        return self.pq_key.key_size + trad_size

    def _get_trad_name(self) -> str:
        """Return the traditional name"""
        if isinstance(self.trad_key, ec.EllipticCurvePublicKey):
            name = "ecdh-" + self.trad_key.curve.name
        elif isinstance(self.trad_key, x448.X448PublicKey):
            name = "x448"
        elif isinstance(self.trad_key, x25519.X25519PublicKey):
            name = "x25519"
        else:
            raise ValueError(f"Unsupported trad_key type. Got: {type(self.trad_key)}")
        return name

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return "chempat-" + self.pq_key.name + "-" + self._get_trad_name()

    def encaps(self, private_key: Optional[ECDHPrivateKey] = None) -> Tuple[bytes, bytes]:
        """Perform key encapsulation with a peer's private key.

        :param private_key: The peer's private key.
        :return: The encapsulated shared secret and ciphertext.
        """
        self.chempat_kem = ChempatKEM(self.pq_key, private_key)  # type: ignore
        ss, ct = self.chempat_kem.encaps(self.pq_key, self.trad_key)  # type: ignore
        logging.info("Chempat: ss: %s, ct: %s", ss.hex(), ct.hex())
        return ss, ct

    def kem_combiner(self, **kwargs) -> bytes:
        """Generate a hybrid shared secret using traditional-KEM and PQ-KEM."""
        raise NotImplementedError("The kem_combiner is directly implemented in the ChempatKEM class.")

    def _export_public_key(self) -> bytes:
        """Export the public key as bytes."""
        return self.public_bytes_raw()


class ChempatPrivateKey(AbstractHybridRawPrivateKey):
    """Chempat private key class."""

    _pq_key: PQKEMPrivateKey
    _trad_key: ECDHPrivateKey

    def __init__(self, pq_key: PQKEMPrivateKey, trad_key: ECDHPrivateKey):
        """Initialize the ChempatPrivateKey instance with keys.

        :param pq_key: The post-quantum private key.
        :param trad_key: The traditional private key.
        :raises ValueError: If the trad_key is not None and not an ECDHPrivateKey.
        :raises InvalidKeyCombination: If the key combination is not supported.
        """
        super().__init__(pq_key, trad_key)
        self.chempat_kem = ChempatKEM(self._pq_key, self.trad_key)

    def public_key(self) -> ChempatPublicKey:
        """Return the corresponding public key class."""
        return ChempatPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    @classmethod
    def _load_pq_key(cls, data: bytes, name: str) -> Tuple[PQKEMPrivateKey, bytes]:
        raise NotImplementedError("The ChempatPrivateKey class does not support key loading.")

    @classmethod
    def _from_private_bytes(cls, data: bytes, name: str) -> "ChempatPrivateKey":
        """Create a ChempatPrivateKey instance from the provided private bytes.

        :param data: The private key bytes, which are the pq-part and the trad-part concatenated.
        :param name: The pq-algorithm name.
        :return: The created `ChempatPrivateKey` instance.
        """
        pq_key, rest = cls._load_pq_key(data, name)
        trad_key = _load_private_key(rest, name)
        return cls(pq_key, trad_key)

    @classmethod
    def from_private_bytes(cls, data: bytes, name: Optional[str] = None) -> "ChempatPrivateKey":
        """Create a ChempatPrivateKey instance from the provided private bytes.

        :param data: The private key bytes, which are the pq-part and the trad-part concatenated.
        :param name: The pq-algorithm name.
        :return: The created `ChempatPrivateKey` instance.
        """
        if name is None:
            raise ValueError("The key name must be provided to create a ChempatPrivateKey instance.")

        name = name.lower()
        if "sntrup761" in name:
            return ChempatSntrup761PrivateKey.from_private_bytes(data, name=name)

        if "mceliece" in name:
            return ChempatMcEliecePrivateKey.from_private_bytes(data, name=name)

        if "ml-kem" in name:
            return ChempatMLKEMPrivateKey.from_private_bytes(data, name=name)

        if "frodokem" in name:
            return ChempatFrodoKEMPrivateKey.from_private_bytes(data, name=name)

        raise ValueError(f"Unsupported key type for Chempat. Got: {name}")

    def _get_header_name(self) -> bytes:
        """Return the PEM header name."""
        return b"CHEMPAT"

    def kem_combiner(self, **kwargs) -> bytes:
        """Generate a hybrid shared secret using traditional-KEM and PQ-KEM."""
        raise NotImplementedError("The kem_combiner is directly implemented in the ChempatKEM class.")

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID for the Chempat key."""
        return get_oid_for_chemnpat(self.pq_key, self.trad_key)

    def _export_private_key(self) -> bytes:
        """Export the private key as bytes."""
        return self.private_bytes_raw()

    @staticmethod
    def parse_keys(pq_key, trad_key) -> "ChempatPrivateKey":
        """Parse and create a ChempatPrivateKey instance based on the provided keys.

        :param pq_key: The post-quantum private key.
        :param trad_key: The traditional private key.
        :return: The corresponding `ChempatPrivateKey` instance.
        :raises InvalidKeyCombination: If the key combination is not supported.
        """
        if isinstance(pq_key, MLKEMPrivateKey):
            return ChempatMLKEMPrivateKey(pq_key, trad_key)

        if isinstance(pq_key, McEliecePrivateKey):
            return ChempatMcEliecePrivateKey(pq_key, trad_key)

        if isinstance(pq_key, Sntrup761PrivateKey):
            return ChempatSntrup761PrivateKey(pq_key, trad_key)

        if isinstance(pq_key, FrodoKEMPrivateKey):
            return ChempatFrodoKEMPrivateKey(pq_key, trad_key)

        raise InvalidKeyCombination(f"Unsupported key type for ChempatPrivateKey: {pq_key.name}")

    def decaps(self, ct: bytes) -> bytes:
        """Perform key decapsulation using the provided ciphertext.

        :param ct: The ciphertext to be decrypted.
        :return: The decapsulated shared secret.
        """
        return self.chempat_kem.decaps(ct)

    @property
    def key_size(self) -> int:
        """Return the key size of the Chempat key."""
        trad_size = TRAD_ALG_2_NENC[get_ec_trad_name(self.trad_key)]
        return self.pq_key.key_size + trad_size

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        nenc = TRAD_ALG_2_NENC[get_ec_trad_name(self.trad_key)]
        return self.pq_key.ct_length + nenc

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return self.public_key().name

    @property
    def trad_key(self) -> "ECDHPrivateKey":
        """Return the traditional key."""
        return self._trad_key

    @property
    def pq_key(self) -> "PQKEMPrivateKey":
        """Return the pq key."""
        return self._pq_key


class ChempatSntrup761PublicKey(ChempatPublicKey):
    """Public key class for the Chempat hybrid key encapsulation mechanism."""

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "ChempatPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :param name: The key name.
        :return: The public key.
        :raises InvalidKeyCombination: If the key combination is not supported or incorrect.
        """
        key = PQKeyFactory.generate_pq_key("sntrup761").public_key()
        key_size = key.key_size
        pq_key = Sntrup761PublicKey.from_public_bytes(data=data[:key_size], name="sntrup761")
        trad_key = x25519.X25519PublicKey.from_public_bytes(data[key_size:])

        if len(data) != key_size + 32:
            raise InvalidKeyCombination(f"Invalid key length for ChempatSntrup761PublicKey: {len(data)}")

        return cls(pq_key, trad_key)


class ChempatSntrup761PrivateKey(ChempatPrivateKey):
    """Chempat Sntrup761 private key class."""

    @classmethod
    def generate(cls):
        """Generate a ChempatSntrup761PrivateKey instance."""
        return cls(PQKeyFactory.generate_pq_key("sntrup761"), x25519.X25519PrivateKey.generate())

    def public_key(self) -> ChempatSntrup761PublicKey:
        """Return the corresponding public key class."""
        return ChempatSntrup761PublicKey(self._pq_key.public_key(), self.trad_key.public_key())

    @classmethod
    def _load_pq_key(cls, data: bytes, name: str) -> Tuple[Sntrup761PrivateKey, bytes]:
        """Load a post-quantum private key from the given data.

        :param data: The private key data.
        :param name: The key name.
        :return: The loaded private key.
        """
        key = PQKeyFactory.generate_pq_key("sntrup761")
        key_size = key.key_size
        key = Sntrup761PrivateKey.from_private_bytes(data[:key_size], name="sntrup761")
        return key, data[key_size:]

    @classmethod
    def from_private_bytes(cls, data: bytes, name: Optional[str] = None) -> "ChempatSntrup761PrivateKey":
        """Create a ChempatSntrup761PrivateKey instance from the provided private bytes.

        :param data: The private key bytes, which are the pq-part and the trad-part concatenated.
        :param name: The pq-algorithm name.
        :return: The created `ChempatSntrup761PrivateKey` instance.
        """
        key = PQKeyFactory.generate_pq_key("sntrup761")
        key_size = key.key_size
        pq_key = Sntrup761PrivateKey.from_private_bytes(data=data[:key_size], name="sntrup761")
        trad_key = x25519.X25519PrivateKey.from_private_bytes(data=data[key_size:])
        return ChempatSntrup761PrivateKey(pq_key, trad_key)


class ChempatMcEliecePublicKey(ChempatPublicKey):
    """Public key class for the Chempat hybrid key encapsulation mechanism."""

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "ChempatPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :param name: The key name.
        :return: The public key.
        :raises InvalidKeyCombination: If the key combination is not supported or incorrect.
        """
        name = name.lower()

        if "mceliece" not in name:
            raise InvalidKeyCombination(f"Unsupported key type for ChempatMcEliecePublicKey: {name}")

        tmp = name.replace("chempat-x25519-", "")
        tmp = tmp.replace("chempat-x448-", "")

        tmp = "mceliece" + "-" + tmp.replace("mceliece", "")

        key = PQKeyFactory.generate_pq_key(tmp).public_key()
        key_size = key.key_size

        pq_key = McEliecePublicKey.from_public_bytes(data[:key_size], name=tmp)

        if "x25519" in name:
            trad_key = x25519.X25519PublicKey.from_public_bytes(data[key_size:])
            trad_size = 32
        elif "x448" in name:
            trad_key = x448.X448PublicKey.from_public_bytes(data[key_size:])
            trad_size = 56
        else:
            raise InvalidKeyCombination(f"Unsupported key type for ChempatMcEliecePublicKey: {name}")

        size = key.key_size + trad_size
        if len(data) != size:
            raise ValueError(f"Invalid key length for ChempatMcEliecePublicKey. Expected: {size}, got: {len(data)}")

        return cls(pq_key, trad_key)


class ChempatMcEliecePrivateKey(ChempatPrivateKey):
    """Chempat McEliece private key class."""

    def public_key(self) -> ChempatMcEliecePublicKey:
        """Return the corresponding public key class."""
        return ChempatMcEliecePublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    @classmethod
    def _load_pq_key(cls, data: bytes, name: str) -> Tuple[McEliecePrivateKey, bytes]:
        """Load a post-quantum private key from the given data.

        :param data: The private key data.
        :param name: The key name.
        :return: The loaded private key.
        """
        tmp = name.replace("chempat-x25519-", "")
        tmp = tmp.replace("chempat-x448-", "")
        tmp = "mceliece" + "-" + tmp.replace("mceliece", "")

        key = PQKeyFactory.generate_pq_key(tmp)
        key_size = key.key_size
        key = McEliecePrivateKey.from_private_bytes(data[:key_size], name=tmp)

        return key, data[key_size:]


class ChempatMLKEMPublicKey(ChempatPublicKey):
    """Public key class for the Chempat hybrid key encapsulation mechanism."""

    def __init__(self, pq_key: MLKEMPublicKey, trad_key: ECDHPublicKey):
        """Initialize the ChempatMLKEMPublicKey instance with keys.

        :param pq_key: The post-quantum public key.
        :param trad_key: The traditional public key.
        """
        super().__init__(pq_key, trad_key)

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "ChempatPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :param name: The key name.
        :return: The public key.
        :raises InvalidKeyCombination: If the key combination is not supported or incorrect.
        """
        if name is None:
            raise ValueError("The key name must be provided to create a ChempatMLKEMPublicKey instance.")

        name = name.lower()

        if "ml-kem-768" in name:
            key = PQKeyFactory.generate_pq_key("ml-kem-768").public_key()
            key_size = key.key_size
            pq_name = "ml-kem-768"
        elif "ml-kem-1024" in name:
            key = PQKeyFactory.generate_pq_key("ml-kem-1024").public_key()
            key_size = key.key_size
            pq_name = "ml-kem-1024"
        else:
            raise InvalidKeyCombination(f"Unsupported key type for ChempatMLKEMPublicKey: {name}")

        trad_key = _load_public_key(data[key_size:], name)

        pq_key = MLKEMPublicKey.from_public_bytes(data=data[:key_size], name=pq_name)

        key = cls(pq_key, trad_key)
        # checks if the public key is allowed to be created.

        if len(data) != key.key_size:
            raise ValueError(
                f"Invalid key length for ChempatMLKEMPublicKey. Expected: {key.key_size}, got: {len(data)}"
            )

        key.get_oid()
        return key


class ChempatMLKEMPrivateKey(ChempatPrivateKey):
    """Chempat ML-KEM 768 private key class."""

    _pq_key: MLKEMPrivateKey

    def public_key(self) -> ChempatMLKEMPublicKey:
        """Return the corresponding public key class."""
        return ChempatMLKEMPublicKey(self._pq_key.public_key(), self.trad_key.public_key())

    @classmethod
    def _load_pq_key(cls, data: bytes, name: str) -> [MLKEMPrivateKey, bytes]:
        """Load a post-quantum private key from the given data.

        :param data: The private key data.
        :param name: The key name.
        :return: The loaded private key and the remaining data for the traditional key.
        """
        pq_name = _get_may_name(name, ["ml-kem-768", "ml-kem-1024"])
        key_size = MLKEMPrivateKey(pq_name).key_size
        key = MLKEMPrivateKey.from_private_bytes(data=data[:key_size], name=pq_name)
        return key, data[key_size:]


def _get_may_name(name: str, options: List[str]) -> Optional[str]:
    """Return the first option from the list that is in the name."""
    for option in options:
        if option in name:
            return option
    return None


def _ec_key_from_der(der_data: bytes, curve: ec.EllipticCurve) -> ec.EllipticCurvePrivateKey:
    """Reconstruct an EllipticCurvePrivateKey from DER data.

    :param der_data: The DER encoded private key.
    :param curve: The elliptic curve.
    :return: The reconstructed private key.
    """
    private_value = int.from_bytes(der_data, byteorder="big")
    return ec.derive_private_key(private_value, curve)


def _load_private_key(data: bytes, name: str) -> ECDHPrivateKey:
    """Load an ECDH private key from the given data.

    :param data: The private key data.
    :param name: The key name.
    :return: The loaded private key.
    """
    if "x25519" in name:
        return x25519.X25519PrivateKey.from_private_bytes(data)
    if "x448" in name:
        return x448.X448PrivateKey.from_private_bytes(data)

    if "p256" in name:
        curve = ec.SECP256R1()
        return _ec_key_from_der(data, curve)

    if "p384" in name:
        curve = ec.SECP384R1()
        return _ec_key_from_der(data, curve)

    if "brainpoolp256" in name:
        curve = ec.BrainpoolP256R1()
        return _ec_key_from_der(data, curve)

    if "brainpoolp384" in name:
        curve = ec.BrainpoolP384R1()
        return _ec_key_from_der(data, curve)

    raise InvalidKeyCombination(f"Unsupported key type for Chempat: {name}")


def _load_public_key(data: bytes, name: str) -> ECDHPublicKey:
    """Load an ECDH public key from the given data."""
    if "x25519" in name:
        return x25519.X25519PublicKey.from_public_bytes(data)
    if "x448" in name:
        return x448.X448PublicKey.from_public_bytes(data)
    if "p256" in name:
        curve = ec.SECP256R1()
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)
    if "p384" in name:
        curve = ec.SECP384R1()
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)
    if "brainpoolp256" in name:
        curve = ec.BrainpoolP256R1()
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)
    if "brainpoolp384" in name:
        curve = ec.BrainpoolP384R1()
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)

    raise InvalidKeyCombination(f"Unsupported key type for Chempat: {name}")


class ChempatFrodoKEMPublicKey(ChempatPublicKey):
    """Chempat FrodoKEM public key class."""

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "ChempatPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :param name: The key name.
        :return: The public key.
        :raises InvalidKeyCombination: If the key combination is not supported or incorrect.
        """
        name = name.lower()

        pq_name = _get_may_name(
            name, ["frodokem-976-aes", "frodokem-1344-aes", "frodokem-976-shake", "frodokem-1344-shake"]
        )

        if not name or not pq_name:
            raise InvalidKeyCombination(f"Unsupported key type for ChempatFrodoKEMPublicKey: {name}")

        key = PQKeyFactory.generate_pq_key(algorithm=pq_name).public_key()
        key_size = key.key_size
        pq_key = FrodoKEMPublicKey.from_public_bytes(data=data[:key_size], name=pq_name)

        trad_key = _load_public_key(data[key_size:], name)

        key = cls(pq_key, trad_key)
        # checks if the public key is allowed to be created.

        if len(data) != key.key_size:
            raise ValueError(
                f"Invalid key length for ChempatFrodoKEMPublicKey. Expected: {key.key_size}, got: {len(data)}"
            )

        key.get_oid()
        return key


class ChempatFrodoKEMPrivateKey(ChempatPrivateKey):
    """Chempat FrodoKEM private key class."""

    def public_key(self) -> ChempatFrodoKEMPublicKey:
        """Return the corresponding public key class."""
        return ChempatFrodoKEMPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    @classmethod
    def generate(cls, trad_name: str = None, curve: str = None):
        """Generate a ChempatFrodoKEMPrivateKey instance.

        :param trad_name: The traditional key name.
        :param curve: The curve name.
        :return: The generated `ChempatFrodoKEMPrivateKey` instance.
        """
        raise NotImplementedError("Not implemented yet.")

    @classmethod
    def _load_pq_key(cls, data: bytes, name: str) -> [FrodoKEMPrivateKey, bytes]:
        """Load a post-quantum private key from the given data.

        :param data: The private key data.
        :param name: The key name.
        :return: The loaded private key and the remaining data for the traditional key.
        """
        pq_name = _get_may_name(
            name, ["frodokem-976-aes", "frodokem-1344-aes", "frodokem-976-shake", "frodokem-1344-shake"]
        )
        key_size = FrodoKEMPrivateKey(pq_name).key_size
        key = FrodoKEMPrivateKey.from_private_bytes(data[:key_size], name=pq_name)
        return key, data[key_size:]


def get_ec_trad_name(trad_key: Union[ECDHPrivateKey, ECDHPublicKey]) -> str:
    """Return the traditional name to generate the context string"""
    if isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        name = CURVE_NAME_2_CONTEXT_NAME[trad_key.curve.name]
    elif isinstance(trad_key, (x448.X448PrivateKey, x448.X448PublicKey)):
        name = "X448"
    elif isinstance(trad_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        name = "X25519"
    else:
        raise ValueError(f"Unsupported key type. Got: {type(trad_key).__name__}")
    return name


def get_trad_key_length(key: Union[ECDHPrivateKey, ECDHPrivateKey, rsa.RSAPrivateKey, rsa.RSAPublicKey]) -> int:
    """Return the key size of the traditional key.

    :param key: The traditional key for which to get the key size.
    :return: The key size of the specified key.
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return key.key_size
    return TRAD_ALG_2_NENC[get_ec_trad_name(key)]


TRAD_ALG_2_NENC = {"brainpoolP384": 97, "P256": 65, "brainpoolP256": 65, "X448": 56, "X25519": 32, "P384": 97}
