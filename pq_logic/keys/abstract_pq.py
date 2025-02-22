# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility for preparing and generating post-quantum keys."""

import base64
import logging
import textwrap
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization

from pq_logic.keys.abstract_wrapper_keys import PQPublicKey
from pq_logic.keys.serialize_utils import prepare_enc_key_pem

try:
    import oqs
except ImportError:
    logging.info("PQ support is disabled.")

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from pyasn1.codec.der import encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5958
from resources.oidutils import PQ_NAME_2_OID


class PQPrivateKey(ABC):
    """Abstract base class for Post-Quantum Private Keys."""

    @abstractmethod
    def _check_name(self, name: str):
        """Check if the parsed name is correct."""
        pass

    @abstractmethod
    def _get_key_name(self) -> bytes:
        """Return the name for the PEM-Header."""

    def __init__(self, alg_name: str, private_bytes: Optional[bytes] = None, public_key: Optional[bytes] = None):
        """Initialize a Post-Quantum Private Key object.

        :param alg_name: The algorithm name.
        :param private_bytes: The private key as bytes.
        :param public_key: The public key as bytes.
        """
        self._check_name(name=alg_name)
        self._name = alg_name
        self._private_key = private_bytes
        self._public_key_bytes = public_key

    def _one_asym_key(self) -> rfc5958.OneAsymmetricKey:
        """Prepare a PyAsn1 OneAsymmetricKey structure."""
        one_asym_key = rfc5958.OneAsymmetricKey()
        # MUST be version 2 otherwise, liboqs will generate a wrong key.
        one_asym_key["version"] = 2
        one_asym_key["privateKeyAlgorithm"]["algorithm"] = PQ_NAME_2_OID[self.name]
        one_asym_key["privateKey"] = univ.OctetString(self.private_bytes_raw())
        public_key_asn1 = univ.BitString(hexValue=self.public_key().public_bytes_raw().hex()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
        one_asym_key["publicKey"] = public_key_asn1
        return one_asym_key

    def private_bytes_raw(self) -> bytes:
        """Return the private key as raw bytes."""
        return self._private_key

    def private_bytes(
        self,
        encoding: Encoding = Encoding.DER,
        format: PrivateFormat = PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ) -> bytes:
        """Serialize the private key as PEM string.

        Decode the ASN.1 structure and then add the PEM string around. The public key is included.

        :param encoding: The encoding format. Can be `Encoding.Raw` or `Encoding.PEM`.
                        Defaults to `Raw`.
        :param format: The private key format. Can be `PrivateFormat.PKCS8`.

        :return: The PEM string.
        """
        if not isinstance(encryption_algorithm, serialization.NoEncryption) and encoding == encoding.DER:
            raise ValueError("Encryption is not supported for DER encoding, only for PEM.")

        if encoding == Encoding.Raw and format == PublicFormat.Raw:
            return self.private_bytes_raw()

        if format == PrivateFormat.PKCS8:
            data = encoder.encode(self.to_one_asym_key())

            if encoding == encoding.DER:
                return data

            if encoding == encoding.PEM and isinstance(encryption_algorithm, serialization.BestAvailableEncryption):
                password = encryption_algorithm.password.decode("utf-8")
                return prepare_enc_key_pem(password, data, self._get_key_name())

            if encoding == encoding.PEM:
                key_name = self._get_key_name()
                b64_encoded = base64.b64encode(data).decode("utf-8")
                b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64)).encode("utf-8")
                pem_data = (
                    b"-----BEGIN "
                    + key_name
                    + b" PRIVATE KEY-----\n"
                    + b64_encoded
                    + b"\n-----END "
                    + key_name
                    + b" PRIVATE KEY-----\n"
                )
                return pem_data

            raise ValueError(f"Unsupported encoding: {encoding}")

        raise ValueError(f"Unsupported format: {format}")

    @property
    def name(self) -> str:
        """Return the name of the algorithm."""
        return self._name.lower()

    @abstractmethod
    def public_key(self) -> PQPublicKey:
        """Derive the corresponding public key."""

    def to_one_asym_key(self) -> rfc5958.OneAsymmetricKey:
        """Create a generic ASN.1 `OneAsymmetricKey` structure."""
        asn1_obj = rfc5958.OneAsymmetricKey()
        asn1_obj["version"] = 2
        algorithm_identifier = rfc5280.AlgorithmIdentifier()
        algorithm_identifier["algorithm"] = PQ_NAME_2_OID[self.name]
        asn1_obj["privateKeyAlgorithm"] = algorithm_identifier
        asn1_obj["privateKey"] = univ.OctetString(self._private_key)
        public_key_asn1 = univ.BitString(hexValue=self.public_key().public_bytes_raw().hex()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
        asn1_obj["publicKey"] = public_key_asn1
        return asn1_obj


class PQSignaturePublicKey(PQPublicKey, ABC):
    """Abstract base class for Post-Quantum Signature Public Keys."""

    _sig_method: Optional["oqs.Signature"]

    def __init__(self, sig_alg: str, public_key: bytes) -> None:  # noqa D107 Missing docstring
        self.sig_alg = None
        self._check_name(name=sig_alg)
        if self.sig_alg is None:
            self.sig_alg = sig_alg
        self._initialize(sig_alg=sig_alg, public_key=public_key)

    def _get_subject_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    def _initialize(self, sig_alg: str, public_key: bytes) -> None:
        """Initialize the `PQSignaturePublicKey` object.

        :param sig_alg: The signature algorithm name.
        :param public_key: The public key as bytes.
        :return:
        """
        self.sig_method = oqs.Signature(self.sig_alg)
        self._public_key_bytes = public_key

    @abstractmethod
    def check_hash_alg(
        self, hash_alg: Union[None, str, hashes.HashAlgorithm], allow_failure: bool = True
    ) -> Optional[str]:
        """Check if the hash algorithm is valid and return the name of the hash algorithm.

        If the name is invalid returns `None`.

        :return: The name of the hash algorithm.
        """

    def verify(
        self,
        signature: bytes,
        data: bytes,
        hash_alg: Optional[str] = None,
        is_prehashed: bool = False,
        ctx: bytes = b"",
    ) -> None:
        """Verify a signature of the provided data.

        :param signature: The signature of the provided data.
        :param data: The data to verify against the signature.
        :param hash_alg: The pre-hashed hash algorithm used for the pre-hashed data
        or supposed to be used.
        :param is_prehashed: Flag indicating if the pre-hashed data is to be verified
        (without the hash-oid.).
        :param ctx: The optional context to use.
        :raises InvalidSignature: If the signature is invalid.
        """
        self.check_hash_alg(hash_alg)

        if hash_alg is not None:
            raise NotImplementedError("Currently can the hash algorithm not parsed directly.")

        if is_prehashed:
            raise NotImplementedError("Currently can the pre-hashed data not parsed, in python-liboqs.")

        if not self.sig_method.verify(data, signature, self._public_key_bytes):
            raise InvalidSignature()


class PQSignaturePrivateKey(PQPrivateKey, ABC):
    """Abstract base class for Post-Quantum Signature Private Keys."""

    _sig_method: Optional["oqs.Signature"]

    def __init__(
        self,
        sig_alg: str,
        private_bytes: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
    ) -> None:
        """Initialize a Post-Quantum Signature Private Key object.

        :param sig_alg: The signature algorithm name.
        :param private_bytes: The private key as bytes.
        :param public_key: The public key as bytes.
        """
        self.sig_alg = None
        self._check_name(name=sig_alg)
        if self.sig_alg is None:
            self.sig_alg = sig_alg
        self._initialize(sig_alg=sig_alg, private_bytes=private_bytes, public_key=public_key)

    def _initialize(
        self, sig_alg: str, private_bytes: Optional[bytes] = None, public_key: Optional[bytes] = None
    ) -> None:
        """Initialize the private key and public key bytes.

        :param sig_alg: The signature algorithm name.
        :param private_bytes: The private key bytes.
        :param public_key: The public key bytes.
        :return:
        """
        self._sig_method = oqs.Signature(self.sig_alg, secret_key=private_bytes)
        self._public_key_bytes = public_key or self._sig_method.generate_keypair()
        self._private_key = private_bytes or self._sig_method.export_secret_key()

    @abstractmethod
    def public_key(self) -> PQSignaturePublicKey:
        """Derive the corresponding public key."""

    def check_hash_alg(
        self,
        hash_alg: Union[None, str, hashes.HashAlgorithm],
    ) -> Optional[str]:
        """Check if a specified or parsed hash algorithm is allowed."""
        return self.public_key().check_hash_alg(hash_alg)

    def sign(
        self,
        data: bytes,
        hash_alg: Union[None, str, hashes.HashAlgorithm] = None,
        ctx: bytes = b"",
        is_prehashed: bool = False,
    ) -> bytes:
        """Sign provided data.

        :param data: The data to sign.
        :param hash_alg: The pre-hashed hash algorithm used for the pre-hashed data
        or supposed to be used.
        :param ctx: The optional context to use.
        :param is_prehashed: Flag indicating if the pre-hashed data is to be verified.
        (without the hash-oid.)
        :return: The signature as bytes.
        """
        self.check_hash_alg(hash_alg)

        if ctx != b"":
            raise NotImplementedError("Currently is signed with context not possible with liboqs-python")

        if hash_alg is not None:
            raise NotImplementedError("Currently can the hash algorithm not parsed directly.")

        if is_prehashed:
            raise NotImplementedError("Currently can the pre-hashed data not parsed, in python-liboqs.")

        signature = self._sig_method.sign(data)
        return signature


class PQKEMPublicKey(PQPublicKey, ABC):
    """Abstract base class for Post-Quantum KEM Public Keys."""

    _kem_method: Optional["oqs.KeyEncapsulation"]

    def __init__(self, kem_alg: str, public_key: bytes):
        """Initialize a KEM public key object.

        :param kem_alg: The KEM algorithm name.
        :param public_key: The public key as raw bytes.

        :raises ValueError: If an invalid algorithm name is provided.
        """
        super().__init__(public_key=public_key, alg_name=kem_alg)
        self._initialize(public_key=public_key, kem_alg=kem_alg)

    def _initialize(self, kem_alg: str, public_key: bytes):
        """Initialize the KEM method, defaults to liboqs.

        :param kem_alg: The KEM algorithm name.
        :param public_key: The public key as raw bytes.
        """
        self._check_name(name=kem_alg)
        self._kem_method = oqs.KeyEncapsulation(self.kem_alg)
        self._public_key_bytes = public_key

    def _export_public_key(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes

    @property
    def name(self) -> str:
        """Return the name of the algorithm."""
        return self.kem_alg.lower()

    @property
    def ct_length(self) -> int:
        """Return the size of the ciphertext."""
        return self._kem_method.details["length_ciphertext"]

    @property
    def key_size(self) -> int:
        """Return the size of the public key."""
        return self._kem_method.details["length_public_key"]

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str):
        """Create a new public key object from the provided bytes."""
        return cls(kem_alg=name, public_key=data)

    def encaps(self) -> Tuple[bytes, bytes]:
        """Perform encapsulation to generate a shared secret.

        :return: The shared secret and the ciphertext as bytes.
        """
        ct, ss = self._kem_method.encap_secret(self._public_key_bytes)
        return ss, ct

    @property
    def nist_level(self) -> str:
        """Return the claimed NIST security level as string."""
        return self._kem_method.details["claimed_nist_level"]


class PQKEMPrivateKey(PQPrivateKey, ABC):
    """Concrete implementation of a Post-Quantum KEM Private Key.

    This class provides functionality to manage, serialize, and use KEM private keys.
    """

    _kem_method: Optional["oqs.KeyEncapsulation"]

    def __init__(self, kem_alg: str, private_bytes: Optional[bytes] = None, public_key: Optional[bytes] = None):
        """Initialize a KEM private key object.

        :param kem_alg: The KEM algorithm name.
        :param private_bytes: The private key as raw bytes.
        :param oid: The Object Identifier associated with the algorithm name.

        :raises ValueError: If an invalid algorithm name is provided.
        """
        super().__init__(alg_name=kem_alg, private_bytes=private_bytes, public_key=public_key)
        self._initialize(kem_alg, private_bytes, public_key)

    def _initialize(self, kem_alg: str, private_bytes: Optional[bytes] = None, public_key: Optional[bytes] = None):
        self.kem_method = oqs.KeyEncapsulation(self.kem_alg, secret_key=private_bytes)
        if private_bytes is None:
            self._public_key_bytes = self.kem_method.generate_keypair()
        else:
            self._public_key_bytes = public_key
        # MUST first generate a keypair, before the secret key can be exported.
        self._private_key = private_bytes or self.kem_method.export_secret_key()

    def decaps(self, ciphertext: bytes) -> bytes:
        """Perform decapsulation to retrieve a shared secret.

        Use the ciphertext to recover the shared secret corresponding to this private key.

        :param ciphertext: The ciphertext generated during encapsulation.
        :return: The shared secret as bytes.
        """
        return self.kem_method.decap_secret(ciphertext)

    @property
    def name(self) -> str:
        """Return the name of the algorithm."""
        return self.kem_alg.lower()

    @property
    def ct_length(self) -> int:
        """Return the size of the ciphertext."""
        return self.kem_method.details["length_ciphertext"]

    @property
    def key_size(self) -> int:
        """Return the size of the public key."""
        return self.kem_method.details["length_secret_key"]

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str):
        """Create a new private key object from the provided bytes.

        :param data: The private key as bytes.
        :param name: The algorithm name.
        :return: The private key object.
        :raises ValueError: If the key size does not match the expected size.
        """
        key = cls(kem_alg=name, private_bytes=data)
        if len(data) != key.key_size:
            raise ValueError(f"Invalid private key size for {cls.name}. Expected {key.key_size}, got {len(data)}")
        return key

    @property
    def nist_level(self) -> str:
        """Return the claimed NIST security level as string."""
        return self.public_key().nist_level
