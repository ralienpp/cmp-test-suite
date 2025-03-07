# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""
Provided Wrapper classes for Post-Quantum Key Encapsulation Mechanisms (KEM) Keys.

Classes in this file follow the `cryptography` library style. This ensures seamless integration
and allows the classes to be easily swapped out or extended in the future.

APIs are:

### Public Keys:
- `public_bytes(encoding: Encoding, format: PublicFormat)`: Serialize the public key into the specified encoding
and format.
- `_check_name(name: str)`: Validate the provided algorithm name.

### Private Keys:
- `public_key()`: Derive the corresponding public key from the private key.
- `generate(kem_alg: str)`: Generate a new private key for the specified algorithm.
- `_check_name(name: str)`: Validate the provided algorithm name.
"""

import importlib.util
import logging
import os
from typing import Optional, Tuple

from pq_logic.fips.fips203 import ML_KEM
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from pq_logic.tmp_oids import FRODOKEM_NAME_2_OID

if importlib.util.find_spec("oqs") is not None:
    import oqs  # pylint: disable=import-error
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None  # pylint: disable=invalid-name


VALID_MCELIECE_OPTIONS = {
    "mceliece-348864": "Classic-McEliece-348864",
    "mceliece-460896": "Classic-McEliece-460896",
    "mceliece-6688128": "Classic-McEliece-6688128",
    "mceliece-6960119": "Classic-McEliece-6960119",
    "mceliece-8192128": "Classic-McEliece-8192128",
}
ML_KEM_NAMES = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]

##########################
# ML-KEM
##########################


class MLKEMPublicKey(PQKEMPublicKey):
    """Represents an ML-KEM public key."""

    def _initialize_key(self):
        """Initialize the ML-KEM public key."""
        self.ml_class = ML_KEM(self.name)
        if oqs is not None:
            self._kem_method = oqs.KeyEncapsulation(self._other_name)

    def _check_name(self, name: str):
        """Validate the provided algorithm name.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not "ml-kem-512", "ml-kem-768", or "ml-kem-1024".
        """
        if name.lower() not in ML_KEM_NAMES:
            raise ValueError(f"Invalid ML-KEM algorithm name: {name}. Supported options: {ML_KEM_NAMES}")
        return name, name.upper()

    def encaps(self) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key."""
        if oqs is not None:
            return super().encaps()

        return self.ml_class.encaps_internal(ek=self._public_key_bytes, m=os.urandom(32))

    @property
    def ct_length(self) -> int:
        """Get the length of the ciphertext."""
        return {"ml-kem-768": 1088, "ml-kem-512": 768, "ml-kem-1024": 1568}[self.name]

    @property
    def key_size(self) -> int:
        """Get the size of the key."""
        return {"ml-kem-768": 1184, "ml-kem-512": 800, "ml-kem-1024": 1568}[self.name]

    @property
    def nist_level(self) -> int:
        """Get the claimed NIST level."""
        return {"ml-kem-768": 3, "ml-kem-512": 1, "ml-kem-1024": 5}[self.name]

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "MLKEMPublicKey":
        """Load an ML-KEM public key from raw bytes."""
        return super().from_public_bytes(data, name)  # type: ignore


class MLKEMPrivateKey(PQKEMPrivateKey):
    """Represents an ML-KEM private key.

    This class provides functionality for validating, managing, and using ML-KEM private keys.
    """

    def _initialize_key(self):
        """Initialize the ML-KEM private key."""
        self.ml_class = ML_KEM(self.name)

        if self._private_key_bytes is None and self._public_key_bytes is None:
            self._seed = self._seed or os.urandom(64)
            d, z = self._seed[:32], self._seed[32:]
            self._public_key_bytes, self._private_key_bytes = self.ml_class.keygen_internal(d=d, z=z)

        if oqs is not None:
            self._kem_method = oqs.KeyEncapsulation(self._other_name, secret_key=self._private_key_bytes)

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"ML-KEM"

    def _check_name(self, name: str):
        """Validate the provided algorithm name.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not "ml-kem-512", "ml-kem-768", or "ml-kem-1024".
        """
        if name not in ML_KEM_NAMES:
            raise ValueError(f"Invalid ML-KEM algorithm name: {name}. Supported options: {ML_KEM_NAMES}")
        return name, name.upper()

    def public_key(self) -> MLKEMPublicKey:
        """Derive the corresponding ML-KEM public key from this private key.

        :return: An instance of `MLKEMPublicKey`.
        """
        if self._public_key_bytes is None:
            # addresses a bug in the liboqs-python library,
            # if a private key is parsed, the public key is not set.
            k = {"ml-kem-768": 3, "ml-kem-512": 2, "ml-kem-1024": 4}[self.name]
            self._public_key_bytes = self.private_bytes_raw()[384 * k : 768 * k + 32]
        return MLKEMPublicKey(public_key=self._public_key_bytes, alg_name=self.name)

    @classmethod
    def generate(cls, kem_alg: str = "ml-kem-512") -> "MLKEMPrivateKey":
        """
        Generate a new ML-KEM private key.

        :param kem_alg: Algorithm name to use (default: "ml-kem-512").
        :return: An instance of `MLKEMPrivateKey`.
        """
        if kem_alg not in ML_KEM_NAMES:
            _name = ", ".join(ML_KEM_NAMES)
            raise ValueError(f"Invalid ML-KEM algorithm name: {kem_alg}.Supported options: {_name}")
        return MLKEMPrivateKey(alg_name=kem_alg)

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str) -> "MLKEMPrivateKey":
        """
        Create an ML-KEM public key from raw bytes.

        :param data: The public key as raw bytes.
        :param name: The algorithm name.
        :return: An instance of `MLKEMPublicKey`.
        """
        if len(data) == 64:
            return cls.from_seed(alg_name=name, seed=data)

        key = cls(alg_name=name, private_bytes=data)
        if key.key_size != len(data):
            raise ValueError(f"Invalid key size expected {key.key_size}, but got: {len(data)}")
        return key

    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a shared secret using the private key.

        :param ct: The ciphertext to decapsulate the shared secret from.
        :return: The shared secret.
        """
        if oqs is not None:
            return super().decaps(ct)

        try:
            return self.ml_class.decaps_internal(dk=self._private_key_bytes, c=ct)
        except IndexError as e:
            raise ValueError("Invalid ciphertext.") from e

    @property
    def ct_length(self) -> int:
        """Get the length of the ciphertext."""
        return {"ml-kem-768": 1088, "ml-kem-512": 768, "ml-kem-1024": 1568}[self.name]

    @property
    def key_size(self) -> int:
        """Get the size of the key."""
        return {"ml-kem-768": 2400, "ml-kem-512": 1632, "ml-kem-1024": 3168}[self.name]

    @property
    def nist_level(self) -> int:
        """Get the claimed NIST level."""
        return {"ml-kem-768": 3, "ml-kem-512": 1, "ml-kem-1024": 5}[self.name]

    @staticmethod
    def _from_seed(alg_name: str, seed: Optional[bytes]) -> Tuple[bytes, bytes, bytes]:
        """Generate a new ML-KEM private key from a seed.

        :param alg_name: The algorithm name (e.g., "ml-kem-512").
        :param seed: The seed to use for key generation.
        :return: The private key, public key, and seed.
        """
        if len(seed) != 64:
            raise ValueError(f"Invalid seed length. Expected 64 bytes. Got: {len(seed)}")

        ek, dk = ML_KEM(alg_name).keygen_internal(d=seed[:32], z=seed[32:])
        return dk, ek, seed


##########################
# McEliece
##########################


class McEliecePublicKey(PQKEMPublicKey):
    """Represents a McEliece public key.

    This class provides functionality for validating and managing McEliece public keys.
    """

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"McEliece"

    def _check_name(self, name: str):
        """Validate the provided algorithm name against supported McEliece options.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not supported.
        """
        for x, y in VALID_MCELIECE_OPTIONS.items():
            if name in [y, x]:
                return name, y
        raise ValueError(f"Invalid McEliece algorithm name: {name}. Supported options: {VALID_MCELIECE_OPTIONS}")

    @property
    def name(self) -> str:
        """Return the algorithm name."""
        for x, y in VALID_MCELIECE_OPTIONS.items():
            if y == self._other_name:
                return x

        raise ValueError(
            f"Invalid McEliece algorithm name: {self._other_name}. Supported options: {VALID_MCELIECE_OPTIONS}"
        )

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "McEliecePublicKey":
        """Load a McEliece public key from raw bytes."""
        return super().from_public_bytes(data, name)  # type: ignore


class McEliecePrivateKey(PQKEMPrivateKey):
    """Represents a McEliece private key.

    This class provides functionality for validating, managing, and using McEliece private keys.
    """

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"McEliece"

    def _check_name(self, name: str):
        """Validate the provided algorithm name against supported McEliece options.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not supported.
        """
        if name not in VALID_MCELIECE_OPTIONS:
            raise ValueError(f"Invalid McEliece algorithm name: {name}. Supported options: {VALID_MCELIECE_OPTIONS}")

        _other = VALID_MCELIECE_OPTIONS[name]
        return name, _other

    def public_key(self) -> McEliecePublicKey:
        """
        Derive the corresponding McEliece public key from this private key.

        :return: An instance of `McEliecePublicKey`.
        """
        return McEliecePublicKey(public_key=self._public_key_bytes, alg_name=self.name)


##########################
# SNTRUP761
##########################


class Sntrup761PublicKey(PQKEMPublicKey):
    """
    Represents an SNTRUP761 public key.

    This class provides functionality for validating and managing SNTRUP761 public keys.
    """

    def _check_name(self, name: str):
        """
        Validate the provided algorithm name.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not "sntrup761".
        """
        if name != "sntrup761":
            raise ValueError(f"Invalid key name '{name}'. Expected 'sntrup761'.")
        return name, name

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "Sntrup761PublicKey":
        """Load a McEliece public key from raw bytes."""
        return super().from_public_bytes(data, name)  # type: ignore


class Sntrup761PrivateKey(PQKEMPrivateKey):
    """
    Represents an SNTRUP761 private key.

    This class provides functionality for validating, managing, and using SNTRUP761 private keys.
    """

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"SNTRUP761"

    def _check_name(self, name: str):
        """
        Validate the provided algorithm name.

        :param name: Algorithm name to validate.
        :raises ValueError: If the algorithm name is not "sntrup761".
        """
        if name != "sntrup761":
            raise ValueError(f"Invalid key name '{name}'. Expected 'sntrup761'.")
        return name, name

    def public_key(self) -> Sntrup761PublicKey:
        """
        Derive the corresponding SNTRUP761 public key from this private key.

        :return: An instance of `Sntrup761PublicKey`.
        """
        return Sntrup761PublicKey(public_key=self._public_key_bytes, alg_name="sntrup761")

    @classmethod
    def generate(cls) -> "Sntrup761PrivateKey":
        """
        Generate a new SNTRUP761 private key.

        :return: An instance of `Sntrup761PrivateKey`.
        """
        return Sntrup761PrivateKey(alg_name="sntrup761")


##########################
# FrodoKEM key
##########################


class FrodoKEMPublicKey(PQKEMPublicKey):
    """Represents a FrodoKEM public key."""

    def _get_header_name(self) -> bytes:
        """Return the key name to write the PEM-header for the key."""
        return b"FrodoKEM"

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Validate the provided algorithm name."""
        if name.lower() not in FRODOKEM_NAME_2_OID:
            raise ValueError(f"Invalid key name '{name}'. Expected one of {FRODOKEM_NAME_2_OID.keys()}.")

        _other = name.upper().replace("FRODOKEM", "FrodoKEM")
        return name, _other

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "FrodoKEMPublicKey":
        """Load an ML-KEM public key from raw bytes."""
        return super().from_public_bytes(data, name)  # type: ignore


class FrodoKEMPrivateKey(PQKEMPrivateKey):
    """Represents a FrodoKEM private key."""

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Validate the provided algorithm name."""
        if name not in FRODOKEM_NAME_2_OID:
            raise ValueError(f"Invalid key name '{name}'. Expected one of {FRODOKEM_NAME_2_OID.keys()}.")

        _other = name.upper().replace("FRODOKEM", "FrodoKEM")
        return name, _other

    def _get_header_name(self) -> bytes:
        """Return the key name to write the PEM-header for the key."""
        return b"FrodoKEM"

    def public_key(self) -> FrodoKEMPublicKey:
        """Derive the corresponding public key from the private key."""
        return FrodoKEMPublicKey(public_key=self._public_key_bytes, alg_name=self.name)
