"""Abstract classes for public and private keys.

These classes define the abstract methods that must be implemented by the concrete
public and private key classes. The abstract classes provide a common interface for
working with public and private keys, and they define the methods for exporting the
keys in different formats.

The abstract classes follow the API functions defined in the `cryptography` library.

- The `public_bytes` and `private_bytes` methods are used to serialize the keys into
different formats, such as DER, PEM, or raw bytes.

- The `public_key` method is used to get the public key from a private key.

- The `from_public_bytes` and `from_private_bytes` methods are used to create public
and private keys from bytes (only for raw keys).

- The `public_bytes_raw` and `private_bytes_raw` methods are used to get the public
and private keys as raw bytes.

- The `get_oid` method is used to get the Object Identifier of the key.

- The `get_subject_public_key` method is used to get the public key for the
`SubjectPublicKeyInfo` structure.

"""

import base64
import textwrap
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5958

from resources.oidutils import PQ_NAME_2_OID

from pq_logic.hybrid_structures import CompositeSignaturePrivateKeyAsn1, CompositeSignaturePublicKeyAsn1
from pq_logic.keys.serialize_utils import prepare_enc_key_pem
from pq_logic.trad_typing import ECDHPrivateKey, ECDHPublicKey

# TODO fix and add into the Test-Suite.

HYBRID_TRAD_PUB_COMP = Union["TradKEMPublicKey", ECDHPublicKey, rsa.RSAPublicKey]
HYBRID_TRAD_PRIV_COMP = Union["TradKEMPrivateKey", ECDHPrivateKey, rsa.RSAPrivateKey]


class WrapperPublicKey(ABC):
    """Abstract class for public keys."""

    _name: str
    _public_key_bytes: bytes

    def __eq__(self, other: "WrapperPublicKey") -> bool:
        """Compare two public keys.

        :param other: The other public key to compare with.
        :return: The result of the comparison.
        """
        if type(other) is not type(self):
            return False
        return self._public_key_bytes == other._public_key_bytes

    @classmethod
    def _get_header_name(self) -> bytes:
        """Return the algorithm name, used in the header of the PEM file."""
        return b"WRAPPER"

    @property
    def name(self):
        """Get the name of the key."""
        return self._name.lower()

    @abstractmethod
    def _export_public_key(self) -> bytes:
        """Export the public key as bytes."""
        pass

    @abstractmethod
    def get_oid(self, **kwargs) -> univ.ObjectIdentifier:
        """Get the Object Identifier of the key."""

    @abstractmethod
    def _get_subject_public_key(self) -> bytes:
        """Get the public key for the `SubjectPublicKeyInfo` structure.

        Will be included in the SubjectPublicKeyInfo structure,
        MUST not include the BIT STRING encoding.
        """

    def _to_spki(self) -> bytes:
        """Encode the public key into the `SubjectPublicKeyInfo` (spki) format.

        :return: The public key in DER-encoded spki format as bytes.
        """
        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid()
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(self._get_subject_public_key())
        return encoder.encode(spki)

    def public_bytes(
        self, encoding: Encoding = Encoding.Raw, format: PublicFormat = PublicFormat.SubjectPublicKeyInfo
    ) -> Union[bytes, str]:
        """Get the serialized public key in bytes format.

        Serialize the public key into the specified encoding (`Raw`, `DER`, or `PEM`) and
        format (`Raw` or `SubjectPublicKeyInfo`).

        :param encoding: The encoding format. Can be `Encoding.Raw`, `Encoding.DER`, or `Encoding.PEM`.
                        Defaults to `Raw`.
        :param format: The public key format. Can be `PublicFormat.Raw` or `PublicFormat.SubjectPublicKeyInfo`.
                      Defaults to `SubjectPublicKeyInfo`.
        :return: The serialized public key as bytes (or string for PEM).
        :raises ValueError: If the combination of encoding and format is unsupported.
        """
        if encoding == Encoding.Raw and format.Raw == PublicFormat.Raw:
            return self._export_public_key()

        if encoding == Encoding.DER:
            if format == PublicFormat.SubjectPublicKeyInfo:
                return self._to_spki()
            raise ValueError(f"Unsupported format for DER encoding: {format}")

        if encoding == Encoding.PEM:
            if format == PublicFormat.SubjectPublicKeyInfo:
                data = self._to_spki()
            else:
                raise ValueError(f"Unsupported format for PEM encoding: {format}")

            b64_encoded = base64.b64encode(data).decode("utf-8")
            b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
            pem = "-----BEGIN PUBLIC KEY-----\n" + b64_encoded + "\n-----END PUBLIC KEY-----\n"
            return pem

        raise ValueError(f"Unsupported encoding: {encoding}")


class WrapperPrivateKey(ABC):
    """Abstract class for private keys."""

    _name: str

    @property
    def name(self):
        """Get the name of the key."""
        return self._name.lower()

    @abstractmethod
    def public_key(self) -> WrapperPublicKey:
        """Get the public key."""

    @classmethod
    def _get_header_name(self) -> bytes:
        """Return the algorithm name, used in the header of the PEM file."""
        return b"WRAPPER"

    @abstractmethod
    def get_oid(self, **kwargs) -> univ.ObjectIdentifier:
        """Get the Object Identifier of the key."""

    @abstractmethod
    def _export_private_key(self) -> bytes:
        """Export the private key as bytes, to put it inside a `OneAsymmetricKey` `v0` structure."""

    def _to_one_asym_key(self) -> bytes:
        """Convert the private key to a OneAsymmetricKey structure.

        :return: The DER-encoded OneAsymmetricKey structure.
        """
        data = rfc5958.OneAsymmetricKey()
        data["version"] = 0
        data["privateKeyAlgorithm"]["algorithm"] = self.get_oid()
        data["privateKey"] = univ.OctetString(self._export_private_key())
        return encoder.encode(data)

    def private_bytes(
        self,
        encoding: Encoding = Encoding.PEM,
        format: PrivateFormat = PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ) -> bytes:
        """Get the serialized private key in bytes format.

        :param encoding: The encoding format. Can be `Encoding.Raw`, `Encoding.DER`, or `Encoding.PEM`.
        :param format: The private key format. Can be `PrivateFormat.Raw` or `PrivateFormat.PKCS8`.
        :return: The serialized private key as bytes.
        """
        if format != PrivateFormat.PKCS8:
            raise ValueError("Only PKCS8 format is supported.")

        if not isinstance(encryption_algorithm, serialization.NoEncryption) and encoding == encoding.DER:
            raise ValueError("Encryption is not supported for DER encoding, only for PEM.")

        if encoding == Encoding.DER:
            return self._to_one_asym_key()

        if encoding == encoding.PEM and isinstance(encryption_algorithm, serialization.BestAvailableEncryption):
            password = encryption_algorithm.password.decode("utf-8")
            return prepare_enc_key_pem(password, self._to_one_asym_key(), self._get_header_name())

        if encoding == Encoding.PEM:
            data = self._to_one_asym_key()
            b64_encoded = base64.b64encode(data).decode("utf-8")
            b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
            pem = (
                f"-----BEGIN {self._get_header_name()} PRIVATE KEY-----\n"
                + b64_encoded
                + f"\n-----END {self._get_header_name()} PRIVATE KEY-----\n"
            )
            return pem.encode("utf-8")

        raise NotImplementedError(f"The encoding is not supported. Encoding: {encoding} .Format: {format}.")


class PQPublicKey(WrapperPublicKey, ABC):
    """Post-Quantum Public Key class."""

    def __init__(self, public_key: bytes, alg_name: str):
        """Initialize the PQPublicKey.

        :param public_key: The public key as bytes.
        :param alg_name: The name of the algorithm.
        """
        self._public_key_bytes = public_key
        self._name = alg_name

    def public_bytes_raw(self) -> bytes:
        """Return the public key as raw bytes."""
        return self._public_key_bytes

    def _export_public_key(self) -> bytes:
        """Export the public key as bytes."""
        return self._public_key_bytes

    def get_oid(self, **kwargs) -> univ.ObjectIdentifier:
        """Get the Object Identifier of the key."""
        return PQ_NAME_2_OID[self.name]

    @abstractmethod
    def _check_name(self, name: str):
        """Check if the parsed name is correct."""
        pass

    @classmethod
    def from_public_bytes(cls, name: str, data: bytes) -> "PQPublicKey":
        """Create a public key from bytes."""
        raise NotImplementedError("The method `from_public_bytes` is not implemented.")

    def _get_subject_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes


class PQPrivateKey(WrapperPrivateKey, ABC):
    """Post-Quantum Private Key class."""

    _seed: Optional[bytes]

    def __init__(
        self,
        alg_name: str,
        private_bytes: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
        seed: Optional[bytes] = None,
    ):
        """Initialize the PQPrivateKey.

        :param alg_name: The name of the algorithm.
        :param private_bytes: The private key as bytes.
        :param public_key: The public key as bytes.
        :param seed: The seed used to generate the key pair.
        """
        alg_name, name = self._check_name(alg_name)

        if private_bytes is None and public_key is None:
            private_bytes, public_key, seed = self._from_seed(alg_name, seed)
        elif private_bytes is None or public_key is None:
            raise ValueError("Both private and public key must be provided or none of them.")

        self._private_key_bytes = private_bytes
        self._public_key_bytes = public_key
        self._name = name
        self._seed = seed

    @classmethod
    def _from_seed(cls, alg_name: str, seed: Optional[bytes]) -> Tuple[bytes, bytes, Optional[bytes]]:
        """Generate a key pair from a seed.

        :param alg_name: The name of the algorithm.
        :param seed: The seed to generate the key pair.
        :return: The private key, the public key, and the seed.
        """
        raise NotImplementedError("The method `_from_seed` is not implemented.")

    @classmethod
    def from_seed(cls, alg_name: str, seed: bytes) -> "PQPrivateKey":
        """Generate a private key from a seed.

        :param alg_name: The name of the algorithm.
        :param seed: The seed to generate the key pair.
        :return: The generated private key.
        """
        private_key, public_key, seed = cls._from_seed(alg_name, seed)
        return cls(alg_name, private_key, public_key, seed)

    @abstractmethod
    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the parsed name is correct.

        :param name: The name to check.
        :return: The correct name and the name of the public key for OQS or other library.
        """
        pass

    def private_bytes_raw(self) -> bytes:
        """Return the private key as raw bytes."""
        return self._private_key_bytes

    def _export_private_key(self) -> bytes:
        """Export the private key as bytes."""
        return self._seed or self._private_key_bytes

    def get_oid(self, **kwargs) -> univ.ObjectIdentifier:
        """Get the Object Identifier of the key."""
        return PQ_NAME_2_OID[self.name]

    def public_key(self) -> PQPublicKey:
        """Get the public key."""
        return PQPublicKey(self._public_key_bytes, self._name)


class TradKEMPublicKey(WrapperPublicKey, ABC):
    """Abstract class for traditional KEM public keys."""

    _public_key: Union[ECDHPublicKey, rsa.RSAPublicKey]

    def __eq__(self, other: "TradKEMPublicKey") -> bool:
        """Compare two public keys.

        :param other: The other public key to compare with.
        :return: The result of the comparison.
        :raises ValueError: If the types of the keys are different.
        """
        if type(other) is not type(self):
            raise ValueError(f"Cannot compare {type(self)} with {type(other)}")
        return self._public_key == other._public_key

    @abstractmethod
    def encaps(self, **kwargs) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret and the ciphertext.

        :param kwargs: Additional arguments for encapsulation.
        :return: The shared secret and the ciphertext.
        """

    @property
    def ct_length(self) -> int:
        """Get the length of the ciphertext."""
        return len(self.encaps()[1])


class TradKEMPrivateKey(WrapperPrivateKey, ABC):
    """Abstract class for traditional KEM private keys."""

    @abstractmethod
    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a shared secret.

        :param ct: The ciphertext.
        :return: The shared secret.
        """

    @abstractmethod
    def public_key(self) -> TradKEMPublicKey:
        """Derive the public key from the private key."""

    @property
    def ct_length(self) -> int:
        """Get the length of the ciphertext."""
        return self.public_key().ct_length


class HybridPublicKey(WrapperPublicKey, ABC):
    """Abstract class for hybrid public keys."""

    _pq_key: PQPublicKey
    _trad_key: HYBRID_TRAD_PUB_COMP

    def __eq__(self, other):
        if type(other) is not type(self):
            return False
        return self._pq_key == other.pq_key and self._trad_key == other.trad_key  # type: ignore

    @property
    def pq_key(self) -> PQPublicKey:
        """Get the public key of the post-quantum algorithm."""
        return self._pq_key

    @property
    def trad_key(self) -> HYBRID_TRAD_PUB_COMP:
        """Get the public key of the traditional algorithm."""
        return self._trad_key


class HybridPrivateKey(WrapperPrivateKey, ABC):
    """Abstract class for hybrid private keys."""

    _pq_key: PQPrivateKey
    _trad_key: HYBRID_TRAD_PRIV_COMP

    @property
    def pq_key(self) -> WrapperPrivateKey:
        """Get the private key of the post-quantum algorithm."""
        return self._pq_key

    @property
    def trad_key(self) -> HYBRID_TRAD_PRIV_COMP:
        """Get the private key of the traditional algorithm."""
        return self._trad_key

    @abstractmethod
    def public_key(self) -> HybridPublicKey:
        """Get the public key."""


class HybridKEMPublicKey(HybridPublicKey, ABC):
    """Abstract class for KEM public keys."""

    @property
    def ct_length(self):
        """Get the length of the ciphertext."""
        return len(self.encaps()[1])

    @abstractmethod
    def kem_combiner(self, **kwargs) -> bytes:
        """Combine the traditional and post-quantum encapsulation outputs, accoring to the algorithm."""

    @abstractmethod
    def encaps(self, ec_key: Optional[ECDHPrivateKey] = None) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret and the ciphertext.

        :param ec_key: The ECDH private key to use for encapsulation. Defaults to `None`.
        :return: The shared secret and the ciphertext.
        """


class HybridKEMPrivateKey(HybridPrivateKey, ABC):
    """Abstract class for KEM private keys."""

    @abstractmethod
    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a shared secret.

        :param ct: The ciphertext.
        :return: The shared secret.
        """

    @abstractmethod
    def kem_combiner(self, **kwargs) -> bytes:
        """Combine the traditional and post-quantum decapsulation outputs, accoring to the algorithm."""

    @abstractmethod
    def public_key(self) -> HybridKEMPublicKey:
        """Derive the public key from the private key."""


class AbstractCompositePublicKey(HybridPublicKey, ABC):
    """Abstract class for Composite public keys."""


    def _prepare_old_spki(self) -> rfc5280.SubjectPublicKeyInfo:
        """Prepare the old SPKI structure.

        :return: The prepared SPKI structure.
        """
        tmp = univ.SequenceOf()

        pq_der_data = self._pq_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pq_tmp = decoder.decode(pq_der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]

        trad_der_data = self._trad_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        trad_tmp = decoder.decode(trad_der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]

        tmp.append(pq_tmp)
        tmp.append(trad_tmp)

        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid()
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(encoder.encode(tmp))
        return spki

    @abstractmethod
    def get_oid(self, use_pss: bool = False, pre_hash: bool = False) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the composite signature algorithm."""

    def _export_public_key(self) -> bytes:
        """Export the composite public key as bytes."""
        return self._self_to_raw_der()

    def _self_to_raw_der(self) -> bytes:
        """Convert the public key to a raw DER-encoded structure."""
        data = CompositeSignaturePublicKeyAsn1()
        data.append(univ.BitString.fromOctetString(self._pq_key.public_bytes_raw()))
        data.append(univ.BitString.fromOctetString(self._trad_key.public_bytes(Encoding.Raw, PublicFormat.Raw)))
        return encoder.encode(data)

    def to_spki(
        self, use_pss: bool = False, pre_hash: bool = False, use_2_spki: bool = False
    ) -> rfc5280.SubjectPublicKeyInfo:
        """Convert CompositePublicKey to a SubjectPublicKeyInfo structure.

        :param use_2_spki: Whether to use `SequenceOf` 2 SPKI structures.
        :param use_pss: Whether RSA-PSS padding was used (if RSA).
        :param pre_hash: Whether the prehashed version was used.
        :return: `SubjectPublicKeyInfo`.
        """
        if not use_2_spki:
            data = self._self_to_raw_der()
        else:
            data = encoder.encode(self._prepare_old_spki())

        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid(use_pss, pre_hash)
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(data)
        return spki


class AbstractCompositePrivateKey(HybridPrivateKey, ABC):
    """Abstract class for Composite private keys."""

    def __init__(self, pq_key: PQPrivateKey, trad_key: WrapperPrivateKey):
        """Initialize the CompositePrivateKey.

        :param pq_key: The post-quantum private key object.
        :param trad_key: The traditional private key object.
        """
        self._pq_key = pq_key
        self._trad_key = trad_key

    @abstractmethod
    def get_oid(self, **kwargs) -> univ.ObjectIdentifier:
        """Return the Object Identifier for the composite signature algorithm."""

    def public_key(self) -> "AbstractCompositePublicKey":
        """Return the corresponding public key class."""
        return AbstractCompositePublicKey(self._pq_key.public_key(), self._trad_key.public_key())

    def _export_private_key(self) -> bytes:
        """Export the private key bytes."""
        return self._to_der()

    def _to_der(self) -> bytes:
        """Convert the private key to a CompositeSignaturePrivateKeyAsn1 structure.

        :return: The DER-encoded CompositeSignaturePrivateKeyAsn1 structure.
        """
        data = CompositeSignaturePrivateKeyAsn1()

        pq_bytes = self.pq_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, serialization.NoEncryption())
        trad_bytes = self.trad_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, serialization.NoEncryption())

        obj, _ = decoder.decode(pq_bytes, asn1Spec=rfc5958.OneAsymmetricKey())
        obj2, _ = decoder.decode(trad_bytes, asn1Spec=rfc5958.OneAsymmetricKey())
        data.append(obj)
        data.append(obj2)

        return encoder.encode(data)


class AbstractCompositeKEMPublicKey(AbstractCompositePublicKey, ABC):
    """Abstract class for Composite KEM public keys."""


class AbstractHybridRawPublicKey(HybridKEMPublicKey, ABC):
    """Abstract class for a raw hybrid public key."""

    _pq_key: PQPublicKey
    _trad_key: ECDHPublicKey

    def __init__(self, pq_key: PQPublicKey, trad_key: ECDHPrivateKey):
        """Initialize the HybridRawPublicKey.

        :param pq_key: The post-quantum public key object.
        :param trad_key: The traditional public key object.
        """
        self._pq_key = pq_key
        self._trad_key = trad_key

    @abstractmethod
    def public_bytes_raw(self) -> bytes:
        """Return the public key as raw bytes."""

    @classmethod
    @abstractmethod
    def from_public_bytes(cls, data: bytes) -> "AbstractHybridRawPublicKey":
        """Create a public key from bytes."""

    def _get_subject_public_key(self) -> bytes:
        """Get the public key for the `SubjectPublicKeyInfo` structure.

        Will be included in the SubjectPublicKeyInfo structure,
        MUST not include the BIT STRING encoding.
        """
        return self.public_bytes_raw()


class AbstractHybridRawPrivateKey(HybridKEMPrivateKey, ABC):
    """Abstract class for a raw hybrid private key."""

    _pq_key: PQPrivateKey
    _trad_key: ECDHPrivateKey

    def __init__(self, pq_key: PQPrivateKey, trad_key: ECDHPrivateKey):
        """Initialize the HybridRawPrivateKey.

        :param pq_key: The post-quantum private key object.
        :param trad_key: The traditional private key object.
        """
        self._pq_key = pq_key
        self._trad_key = trad_key

    def _encode_trad_part(self) -> bytes:
        """Encode the traditional part of the private key.

        :return: The traditional part of the private key as bytes.
        """
        if isinstance(self._trad_key, (x25519.X25519PrivateKey, x448.X448PrivateKey)):
            return self._trad_key.private_bytes_raw()
        private_numbers = self._trad_key.private_numbers()
        return private_numbers.private_value.to_bytes(self._trad_key.key_size, byteorder="big")

    def private_bytes_raw(self) -> bytes:
        """Return the private key as raw bytes."""
        return self._pq_key.private_bytes_raw() + self._encode_trad_part()

    def _export_private_key(self) -> bytes:
        """Export the private key as bytes."""
        return self.private_bytes_raw()

    @classmethod
    @abstractmethod
    def from_private_bytes(cls, data: bytes) -> "AbstractHybridRawPrivateKey":
        """Create a private key from bytes."""
