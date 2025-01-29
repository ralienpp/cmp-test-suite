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

import logging
import os
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder
from resources.oid_mapping import compute_hash, sha_alg_name_to_oid
from resources.oidutils import SLH_DSA_NAME_2_OID_PRE_HASH

from pq_logic.fips import fips204, fips205
from pq_logic.fips.fips204 import ML_DSA
from pq_logic.fips.fips205 import SLH_DSA, integer_to_bytes
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey

##########################
# ML-DSA
##########################

try:
    import oqs
except ImportError:
    logging.info("liboqs support is disabled.")
    oqs = None


FALCON_NAMES = ["falcon-512", "falcon-1024", "falcon-padded-512", "falcon-padded-1024"]
ML_DSA_NAMES = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]


class MLDSAPublicKey(PQSignaturePublicKey):
    """Represent an ML-DSA public key."""

    def _init(self, sig_alg: str, public_key: bytes) -> None:
        """Initialize the ML-DSA public key.

        :param sig_alg: The signature algorithm name.
        :param public_key: The public key bytes.
        :return: The initialized ML-DSA public key.
        """
        self._check_name(sig_alg)
        self.ml_class = ML_DSA(sig_alg)
        self._public_key_bytes = public_key

    @property
    def sig_size(self) -> int:
        """Return the size of the signature."""
        if oqs is None:
            sig_size = {"ml-dsa-44": 2420, "ml-dsa-65": 3309, "ml-dsa-87": 4627}
            return sig_size[self.name]

        return self.sig_method.details["length_signature"]

    @property
    def key_size(self) -> int:
        """Return the size of the public key."""
        key_size = {"ml-dsa-44": 1312, "ml-dsa-65": 1952, "ml-dsa-87": 2592}
        return key_size[self.name]

    def verify(
        self,
        signature: bytes,
        data: bytes,
        ctx: bytes = b"",
        hash_alg: Optional[str] = None,
        is_prehashed: bool = False,
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
                pre_hashed = compute_hash(hash_alg, data)
            else:
                pre_hashed = data

            mp = b"\x01" + ml_.integer_to_bytes(len(ctx), 1) + ctx + oid + pre_hashed
            sig = ml_.verify_internal(pk=self._public_key_bytes, mp=mp, sig=signature)

        if not sig:
            raise InvalidSignature()

    @property
    def name(self) -> str:
        """Return the name of the algorithm."""
        return self.sig_alg.lower()

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
            logging.info(f"{self.name} does not support the hash algorithm: {hash_alg}")
            return None

        return hash_alg

    def _check_name(self, name: str):
        """Check if the parsed name is valid.

        :param name: The name to check.
        """
        name = name.lower()
        if name not in ML_DSA_NAMES:
            raise ValueError(f"Invalid signature algorithm name provided: {name}.")

        self.sig_alg = name

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "MLDSAPublicKey":
        """Create a public key from the given byte string.

        :param data: The byte string to create the public key from.
        :param name: The name of the signature algorithm.
        """
        key = cls(sig_alg=name, public_key=data)
        if key.key_size != len(data):
            raise ValueError(f"Invalid public key size. Expected: {key.key_size}, got: {len(data)}")

        return key


class MLDSAPrivateKey(PQSignaturePrivateKey):
    """Represents an ML-DSA private key."""

    def _initialize(
        self, sig_alg: str, private_bytes: Optional[bytes] = None, public_key: Optional[bytes] = None
    ) -> None:
        """Initialize the ML-DSA private key.

        :param sig_alg: The signature algorithm name.
        :param private_bytes: The private key bytes.
        :param public_key: The public key bytes.
        :return: The initialized ML-DSA private key.
        """
        if oqs is not None:
            super()._initialize(sig_alg=sig_alg, private_bytes=private_bytes, public_key=public_key)
        else:
            logging.info("ML-DSA Key generation is done with pure python.")
            self._check_name(sig_alg)
            self.sig_alg = sig_alg
            self.ml_class = ML_DSA(sig_alg)

            if private_bytes is None:
                self._public_key, self._private_key = self.ml_class.keygen_internal(xi=os.urandom(32))
            else:
                self._private_key = private_bytes
                self._public_key = public_key

    @classmethod
    def key_gen(cls, name: str, seed: bytes = None):
        """Generate a MLDSAPrivateKey.

        :param name: The name of the ML-DSA parameter set (e.g., "ml-dsa-44").
        :param seed: The seed to use for the key generation. Defaults to `None`.
        (will generate a random 32-bytes, seed if not provided).
        :return: The generated MLDSAPrivateKey.
        """
        if seed is None:
            seed = os.urandom(32)

        _public_key, _private_key = ML_DSA(name).keygen_internal(xi=seed)
        return cls(sig_alg=name, private_bytes=_private_key, public_key=_public_key)

    def _get_key_name(self) -> bytes:
        """Return the algorithm name."""
        return b"ML-DSA"

    @classmethod
    def generate(cls, name: str):
        """Generate a MLDSAPrivateKey."""
        return cls(name)

    @property
    def name(self) -> str:
        """Return the name of the key."""
        return self.sig_alg.lower()

    def _check_name(self, name: str):
        """Check if the name is valid."""
        name = name.lower()
        if name not in ML_DSA_NAMES:
            raise ValueError(f"Invalid signature algorithm name provided.: {name}")

        self.sig_alg = name

    @property
    def key_size(self) -> int:
        """Return the size of the private key."""
        key_size = {"ml-dsa-44": 2560, "ml-dsa-65": 4032, "ml-dsa-87": 4896}
        return key_size[self.name]

    def public_key(self) -> MLDSAPublicKey:
        """Derive the corresponding public key.

        :return: An `MLDSAPublicKey` instance.
        """
        return MLDSAPublicKey(sig_alg=self.sig_alg, public_key=self._public_key)

    def sign(
        self,
        data: bytes,
        ctx: bytes = b"",
        hash_alg: Union[None, str, hashes.HashAlgorithm] = None,
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

        elif hash_alg is None:
            ml_ = fips204.ML_DSA(self.name)
            sig = ml_.sign(sk=self.private_bytes_raw(), m=data, ctx=ctx)
        else:
            ml_ = fips204.ML_DSA(self.name)
            hash_alg = self.check_hash_alg(hash_alg=hash_alg)
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                pre_hashed = compute_hash(hash_alg, data)
            else:
                pre_hashed = data

            mp = b"\x01" + ml_.integer_to_bytes(len(ctx), 1) + ctx + oid + pre_hashed
            sig = ml_.sign_internal(self._private_key, mp, os.urandom(32))

        if not sig:
            raise ValueError("Could not sign the data with ML-DSA")

        return sig


##########################
# SLH-DSA
##########################


class SLHDSAPublicKey(PQSignaturePublicKey):
    """Represent an SLH-DSA public key."""

    def _init(self, sig_alg: str, public_key: bytes) -> None:
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

    def verify(self, signature: bytes, data: bytes, ctx: bytes = b"", hash_alg: Optional[str] = None) -> None:
        """Verify the signature of the data.

        :param signature: The signature to verify.
        :param data: The data to verify.
        :param ctx: The context to add for the signature. Defaults to `b""`.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        :raises InvalidSignature: If the signature is invalid.
        """
        return self._slh_class.slh_verify(m=data, sig=signature, pk=self._public_key_bytes, ctx=ctx)


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
            self._private_key, self._public_key = self._slh_class.slh_keygen()
        else:
            self._private_key = private_bytes
            self._public_key = public_key

    @property
    def name(self):
        """Return the name of the key."""
        return self.sig_alg

    def _get_key_name(self) -> bytes:
        """Return the name of the key, to save it in a file as PEM-header."""
        return b"SLH-DSA"

    def _check_name(self, name: str):
        """Check if the name is valid."""
        pass

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
        return SLHDSAPublicKey(sig_alg=self.sig_alg, public_key=self._public_key)

    def sign(self, data: bytes, hash_alg: Optional[str] = None, ctx: bytes = b"", is_prehashed: bool = False) -> bytes:
        """Sign the data with SLH-DSA private key.

        :param data: The data to sign.
        :param hash_alg: The hash algorithm to use for the pre-hashing of the data.
        Defaults to `None`.
        :param ctx: The optional context to add for the signature. Defaults to `b""`.
        :param is_prehashed: Whether the data is prehashed. Defaults to False.
        :return: The computed signature.
        :raises ValueError: If the data is and no hash algorithm is specified.
        ValueError: If the context is too long (255).
        ValueError: If the signature cannot be computed.
        """
        hash_alg = self.check_hash_alg(hash_alg=hash_alg)
        if hash_alg is None:
            sig = self._slh_class.slh_sign(m=data, sk=self._private_key, ctx=ctx)

        else:
            oid = encoder.encode(sha_alg_name_to_oid(hash_alg))

            if not is_prehashed:
                pre_hashed = compute_hash(hash_alg, data)
            else:
                pre_hashed = data

            mp = b"\x01" + integer_to_bytes(len(ctx), 1) + ctx + oid + pre_hashed
            sig = self._slh_class.slh_sign_internal(self._private_key, mp)

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
        return FalconPublicKey(sig_alg=self.name, public_key=self._public_key)

    def _check_name(self, name: str):
        """Check if the name is valid.

        :param name: The name to check.
        """
        names = ", ".join(f"`{name}`" for name in FALCON_NAMES)
        if name not in FALCON_NAMES:
            raise ValueError(f"Invalid `Falcon` signature algorithm name provided.: {name} Supported names: {names}")

        self.sig_alg = name.capitalize()
