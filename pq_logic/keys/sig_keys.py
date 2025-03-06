# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""
Wrapper classes for Post-Quantum signature Keys.

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

##########################
# ML-DSA
##########################
import importlib.util
import logging
import os
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder
from resources.oid_mapping import compute_hash, sha_alg_name_to_oid
from resources.oidutils import SLH_DSA_NAME_2_OID_PRE_HASH

from pq_logic.fips import fips204, fips205
from pq_logic.fips.fips204 import ML_DSA
from pq_logic.fips.fips205 import SLH_DSA, integer_to_bytes
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey

if importlib.util.find_spec("oqs") is not None:
    import oqs
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None

FALCON_NAMES = ["falcon-512", "falcon-1024", "falcon-padded-512", "falcon-padded-1024"]
ML_DSA_NAMES = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]


class MLDSAPublicKey(PQSignaturePublicKey):
    """Represent an ML-DSA public key."""

    def _initialize_key(self) -> None:
        """Initialize the ML-DSA public key."""
        self.ml_class = ML_DSA(self.name)

    @property
    def sig_size(self) -> int:
        """Return the size of the signature."""
        sig_size = {"ml-dsa-44": 2420, "ml-dsa-65": 3309, "ml-dsa-87": 4627}
        return sig_size[self.name]

    @property
    def key_size(self) -> int:
        """Return the size of the public key."""
        key_size = {"ml-dsa-44": 1312, "ml-dsa-65": 1952, "ml-dsa-87": 2592}
        return key_size[self.name]

    def verify(
        self,
        signature: bytes,
        data: bytes,
        hash_alg: Optional[str] = None,
        is_prehashed: bool = False,
        ctx: bytes = b"",
    ) -> None:
        """Verify the signature of the data.

        :param signature: The signature to verify.
        :param data: The data to verify.
        :param ctx: The context to add for the signature. Defaults to `b""`.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        :param is_prehashed: Whether the data is prehashed. Defaults to `False`.
        """
        logging.info("ctx is currently not supported, possible in liboqs version 13.")

        if len(ctx) > 255:
            raise ValueError(f"The context length is longer than 255 bytes. Got: {len(ctx)}")

        hash_alg = self.check_hash_alg(hash_alg=hash_alg, allow_failure=False)
        ml_ = fips204.ML_DSA(self.name)
        if hash_alg is None:
            sig = ml_.verify(pk=self.public_bytes_raw(), sig=signature, m=data, ctx=ctx)

        else:
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                data = compute_hash(hash_alg, data)

            mp = b"\x01" + ml_.integer_to_bytes(len(ctx), 1) + ctx + oid + data
            sig = ml_.verify_internal(pk=self._public_key_bytes, mp=mp, sig=signature)

        if not sig:
            raise InvalidSignature()

    def check_hash_alg(self, hash_alg: Optional[str], allow_failure: bool = True) -> Optional[str]:
        """Check if the hash algorithm is valid.

        :param hash_alg: The hash algorithm to check.
        :param allow_failure: Whether to allow failure or not.
        """
        if hash_alg is None:
            return None

        if isinstance(hash_alg, hashes.SHA512):
            return "sha512"

        if hash_alg not in [None, "sha512"]:
            if not allow_failure:
                raise ValueError(f"The provided hash algorithm is not supported for ML-DSA. Provided: {hash_alg}")
            logging.info("%s does not support the hash algorithm: %s", self.name, hash_alg)
            return None

        return hash_alg

    def _check_name(self, name: str) -> Tuple[str, str]:
        """Check if the parsed name is valid.

        :param name: The name to check.
        """
        name = name.lower()
        if name not in ML_DSA_NAMES:
            raise ValueError(f"Invalid signature algorithm name provided: {name}.")

        return name, name.upper()

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "MLDSAPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :param name: The name of the signature algorithm.
        """
        key = MLDSAPublicKey(alg_name=name, public_key=data)
        if key.key_size != len(data):
            raise ValueError(f"Invalid public key size. Expected: {key.key_size}, got: {len(data)}")
        return key


class MLDSAPrivateKey(PQSignaturePrivateKey):
    """Represents an ML-DSA private key."""

    _public_key: Optional[bytes] = None

    def _initialize(
        self, sig_alg: str, private_bytes: Optional[bytes] = None, public_key: Optional[bytes] = None
    ) -> None:
        """Initialize the ML-DSA private key.

        :param sig_alg: The signature algorithm name.
        :param private_bytes: The private key bytes.
        :param public_key: The public key bytes.
        :return: The initialized ML-DSA private key.
        """
        self._check_name(sig_alg)
        self.sig_alg = sig_alg
        self.ml_class = ML_DSA(sig_alg)
        self._seed = os.urandom(32)
    def _initialize_key(self) -> None:
        """Initialize the ML-DSA private key."""
        self.ml_class = ML_DSA(self.name)

        if self._private_key_bytes is None and self._public_key_bytes is None:
            self._seed = self._seed or os.urandom(32)
            self._public_key_bytes, self._private_key_bytes = self.ml_class.keygen_internal(xi=self._seed)

        elif self._public_key_bytes is None and self._private_key_bytes is not None:
            self._public_key_bytes = self.derive_public_key_from_secret_key(sk=self._private_key_bytes)
        else:
            raise ValueError("Invalid key initialization")

    @staticmethod
    def _from_seed(alg_name: str, seed: Optional[bytes]) -> Tuple[bytes, bytes, bytes]:
        """Generate a ML-DSA private key from the seed."""
        _ml_class = ML_DSA(alg_name)
        if seed is None:
            seed = os.urandom(32)

        _public_key, _private_key = ML_DSA(alg_name).keygen_internal(xi=seed)
        return _private_key, _public_key, seed

    @classmethod
    def from_seed(cls, alg_name: str, seed: bytes = None) -> "MLDSAPrivateKey":
        """Generate a MLDSAPrivateKey.

        :param alg_name: The name of the ML-DSA parameter set (e.g., "ml-dsa-44").
        :param seed: The seed to use for the key generation. Defaults to `None`.
        (will generate a random 32-bytes, seed if not provided).
        :return: The generated MLDSAPrivateKey.
        """
        if seed is None:
            seed = os.urandom(32)
        return cls(alg_name=alg_name, seed=seed)

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str) -> "MLDSAPrivateKey":
        """Create a private key from the given byte string.

        :param data: The byte string to create the private key from.
        :param name: The name of the signature algorithm.
        """
        if len(data) == 32:
            return cls.from_seed(alg_name=name, seed=data)

        key = cls(alg_name=name, private_bytes=data)
        if key.key_size != len(data):
            raise ValueError(f"Invalid private key size. Expected: {key.key_size}, got: {len(data)}")

        return key

    def _get_header_name(self) -> bytes:
        """Return the algorithm name."""
        return b"ML-DSA"

    @classmethod
    def generate(cls, name: str):
        """Generate a MLDSAPrivateKey."""
        return cls(name)

    def _check_name(self, name: str):
        """Check if the name is valid."""
        name = name.lower()
        if name not in ML_DSA_NAMES:
            raise ValueError(f"Invalid signature algorithm name provided.: {name}")

        return name, name.upper()

    @property
    def key_size(self) -> int:
        """Return the size of the private key."""
        key_size = {"ml-dsa-44": 2560, "ml-dsa-65": 4032, "ml-dsa-87": 4896}
        return key_size[self.name]

    @property
    def sig_size(self) -> bytes:
        """Return the size of the signature."""
        sig_size = {"ml-dsa-44": 2420, "ml-dsa-65": 3309, "ml-dsa-87": 4627}
        return sig_size[self.name]

    def public_key(self) -> MLDSAPublicKey:
        """Derive the corresponding public key.

        :return: An `MLDSAPublicKey` instance.
        """
        return MLDSAPublicKey(alg_name=self.name, public_key=self._public_key_bytes)

    def sign(
        self,
        data: bytes,
        hash_alg: Union[None, str, hashes.HashAlgorithm] = None,
        ctx: bytes = b"",
        is_prehashed: bool = False,
    ) -> bytes:
        """Sign the data with ML-DSA private key.

        :param data: The data to sign.
        :param ctx: The optional context to add for the signature. Defaults to `b""`.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        :param is_prehashed: Whether the data is prehashed. Defaults to `False`.
        :return: The computed signature.
        """
        logging.info("ctx is currently not supported, possible in liboqs version 13.")

        if len(ctx) > 255:
            raise ValueError(f"The context length is longer then 255 bytes.Got: {len(ctx)}")

        if hash_alg is None:
            ml_ = fips204.ML_DSA(self.name)
            sig = ml_.sign(sk=self._private_key_bytes, m=data, ctx=ctx)
        else:
            ml_ = fips204.ML_DSA(self.name)
            hash_alg = self.check_hash_alg(hash_alg=hash_alg)
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                pre_hashed = compute_hash(hash_alg, data)
            else:
                pre_hashed = data

            mp = b"\x01" + ml_.integer_to_bytes(len(ctx), 1) + ctx + oid + pre_hashed
            sig = ml_.sign_internal(self._private_key_bytes, mp, os.urandom(32))

        if not sig:
            raise ValueError("Could not sign the data with ML-DSA")

        return sig


##########################
# SLH-DSA
##########################


class SLHDSAPublicKey(PQSignaturePublicKey):
    """Represent an SLH-DSA public key."""

    def _initialize(self, sig_alg: str, public_key: bytes) -> None:
        """Initialize the SLH-DSA public key.

        :param sig_alg: The signature algorithm name.
        :param public_key: The public key bytes.
        :return: The initialized SLH-DSA public key.
        """
        self.sig_alg = sig_alg.replace("_", "-")
        self._slh_class: SLH_DSA = fips205.SLH_DSA_PARAMS[self.sig_alg]
        self._public_key_bytes = public_key

    @property
    def name(self):
        """Return the name of the key."""
        return self.sig_alg

    def _check_name(self, name: str):
        """Check if the parsed name is valid.

        :param name: The name to check.
        """
        pass

    def check_hash_alg(self, hash_alg: Union[None, str, hashes.HashAlgorithm]) -> Optional[str]:
        """Check if the hash algorithm is valid to be used with SLH-DSA.

        :param hash_alg: The hash algorithm to check.
        :return: The hash algorithm name or None.
        """
        if hash_alg is None:
            return None

        if isinstance(hash_alg, hashes.HashAlgorithm):
            hash_alg = hash_alg.name.lower()

        alg = self.name + "-" + hash_alg
        if SLH_DSA_NAME_2_OID_PRE_HASH.get(alg):
            return hash_alg
        logging.info(f"{self.name} does not support the hash algorithm: {hash_alg}")
        return None

    def verify(
        self,
        signature: bytes,
        data: bytes,
        hash_alg: Optional[str] = None,
        is_prehashed: bool = False,
        ctx: bytes = b"",
    ) -> None:
        """Verify the signature of the data.

        :param signature: The signature to verify.
        :param data: The data to verify.
        :param ctx: The context to add for the signature. Defaults to `b""`.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        :param is_prehashed: Whether the data is prehashed. Defaults to `False`.
        :raises InvalidSignature: If the signature is invalid.
        """
        hash_alg = self.check_hash_alg(hash_alg=hash_alg)
        if hash_alg is None:
            sig = self._slh_class.slh_verify(m=data, sig=signature, pk=self._public_key_bytes, ctx=ctx)

        else:
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                pre_hashed = compute_hash(hash_alg, data)
            else:
                pre_hashed = data

            mp = b"\x01" + integer_to_bytes(len(ctx), 1) + ctx + oid + pre_hashed
            sig = self._slh_class.slh_verify_internal(m=mp, sig=signature, pk=self._public_key_bytes)

        if not sig:
            raise InvalidSignature()


class SLHDSAPrivateKey(PQSignaturePrivateKey):
    """Represents an SLH-DSA private key."""

    def _initialize(
        self, sig_alg: str, private_bytes: Optional[bytes] = None, public_key: Optional[bytes] = None
    ) -> None:
        """Initialize the SLH-DSA private key.

        :param sig_alg: The signature algorithm name.
        :param private_bytes: The private key.
        :param public_key: The public key.
        """
        self.sig_alg = sig_alg.replace("_", "-")

        self._slh_class: SLH_DSA = fips205.SLH_DSA_PARAMS[self.sig_alg]

        if private_bytes is None:
            self._public_key_bytes, self._private_key = self._slh_class.slh_keygen()
        else:
            self._private_key = private_bytes
            self._public_key_bytes = public_key

    @property
    def name(self):
        """Return the name of the key."""
        return self.sig_alg

    def _get_key_name(self) -> bytes:
        """Return the algorithm name."""
        return b"SLH-DSA"

    def _check_name(self, name: str):
        """Check if the name is valid."""

    def check_hash_alg(self, hash_alg: Union[None, str, hashes.HashAlgorithm]) -> Optional[str]:
        """Check if the hash algorithm is valid for the SLH-DSA key.

        :param hash_alg: The hash algorithm to check.
        :return: The hash algorithm name or None.
        """
        return self.public_key().check_hash_alg(hash_alg=hash_alg)

    def public_key(self) -> SLHDSAPublicKey:
        """Derive the corresponding public key.

        :return: An `SLHDSAPublicKey` instance.
        """
        return SLHDSAPublicKey(sig_alg=self.sig_alg, public_key=self._public_key_bytes)

    def sign(self, data: bytes, hash_alg: Optional[str] = None, ctx: bytes = b"", is_prehashed: bool = False) -> bytes:
        """Sign the data with SLH-DSA private key.

        :param data: The data to sign.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        Defaults to `None`.
        :param ctx: The optional context to add for the signature. Defaults to `b""`.
        :param is_prehashed: Whether the data is prehashed. Defaults to False.
        :return: The computed signature.
        :raises ValueError: If the context is too long (255), or if the signature cannot be computed.
        """
        hash_alg = self.check_hash_alg(hash_alg=hash_alg)
        if hash_alg is None:
            sig = self._slh_class.slh_sign(m=data, sk=self._private_key, ctx=ctx)

        else:
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                data = compute_hash(hash_alg, data)
            else:
                data = data

            mp = b"\x01" + integer_to_bytes(len(ctx), 1) + ctx + oid + data
            sig = self._slh_class.slh_sign_internal(m=mp, sk=self._private_key)

        if not sig:
            raise ValueError("Could not sign the data with SLH-DSA")

        return sig


##########################
# Falcon
##########################


# TODO remove if FN-DSA is available.
class FalconPublicKey(PQSignaturePublicKey):
    """Represent a Falcon public key."""

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return self.sig_alg.lower()

    def _check_name(self, name: str):
        """Check if the parsed name is valid."""
        if name not in FALCON_NAMES:
            names = ", ".join(f"`{name}`" for name in FALCON_NAMES)
            raise ValueError(f"Invalid `Falcon` signature algorithm name provided.: {name} Supported names: {names}")

        self.sig_alg = name.capitalize()

    def check_hash_alg(
        self, hash_alg: Union[None, str, hashes.HashAlgorithm], allow_failure: bool = True
    ) -> Optional[str]:
        """Check if the hash algorithm is valid.

        Falcon does not support any hash algorithms, so always return `None`.

        :param hash_alg: The hash algorithm to check.
        :param allow_failure: The flag to allow failure or not.
        :return: The hash algorithm name or None.
        """
        if hash_alg is not None:
            logging.info(f"{self.name} does not support the hash algorithm: {hash_alg}")
        return None


class FalconPrivateKey(PQSignaturePrivateKey):
    """Represent a Falcon private key."""

    @property
    def name(self):
        """Return the name of the key."""
        return self.sig_alg.lower()

    def _get_key_name(self) -> bytes:
        """Return the algorithm name."""
        return b"FALCON"

    def public_key(self) -> FalconPublicKey:
        """Derive the corresponding public key."""
        return FalconPublicKey(sig_alg=self.name, public_key=self._public_key_bytes)

    def _check_name(self, name: str):
        """Check if the name is valid.

        :param name: The name to check.
        """
        names = ", ".join(f"`{name}`" for name in FALCON_NAMES)
        if name not in FALCON_NAMES:
            raise ValueError(f"Invalid `Falcon` signature algorithm name provided.: {name} Supported names: {names}")

        self.sig_alg = name.capitalize()
