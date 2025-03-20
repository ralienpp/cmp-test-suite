# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Key factory to create all supported keys."""

import copy
from typing import Dict, List, Optional, Tuple, Union

import pyasn1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5958, rfc6664
from resources.asn1utils import try_decode_pyasn1
from resources.exceptions import BadAlg, BadAsn1Data, InvalidKeyCombination, InvalidKeyData
from resources.oid_mapping import get_curve_instance
from resources.oidutils import (
    CMS_COMPOSITE_OID_2_NAME,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    TRAD_STR_OID_TO_KEY_NAME,
    XWING_OID_STR,
)

from pq_logic.keys.chempat_key import ChempatPublicKey
from pq_logic.hybrid_structures import (
    CompositeSignaturePrivateKeyAsn1,
    CompositeSignaturePublicKeyAsn1,
)
from pq_logic.keys.abstract_wrapper_keys import AbstractCompositePublicKey
from pq_logic.keys.composite_kem05 import (
    CompositeKEMPrivateKey,
    CompositeKEMPublicKey,
)
from pq_logic.keys.composite_kem06 import (
    CompositeDHKEMRFC9180PrivateKey,
    CompositeDHKEMRFC9180PublicKey,
    CompositeKEM06PrivateKey,
    CompositeKEM06PublicKey,
)
from pq_logic.keys.composite_sig03 import (
    CompositeSig03PrivateKey,
    CompositeSig03PublicKey,
)
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey, CompositeSig04PublicKey
from pq_logic.keys.hybrid_key_factory import HybridKeyFactory
from pq_logic.keys.kem_keys import FrodoKEMPublicKey, MLKEMPublicKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey
from pq_logic.keys.trad_kem_keys import DHKEMPrivateKey, DHKEMPublicKey, RSADecapKey, RSAEncapKey
from pq_logic.keys.trad_key_factory import generate_trad_key, parse_trad_key_from_one_asym_key
from pq_logic.keys.xwing import XWingPublicKey
from pq_logic.tmp_oids import (
    CHEMPAT_OID_2_NAME,
    COMPOSITE_KEM05_OID_2_NAME,
    COMPOSITE_KEM06_NAME_2_OID,
    COMPOSITE_KEM06_OID_2_NAME,
    COMPOSITE_SIG04_NAME_2_OID,
    COMPOSITE_SIG04_OID_2_NAME,
    id_rsa_kem_spki,
)


def _any_string_in_string(string: str, options: List[str]) -> str:
    """Check if any of the options is in the string and return the first match.

    :param string: The string to check.
    :param options: The list of options to check for.
    :return: The first option that is in the string.
    :raises ValueError: If none of the options is in the string.
    """
    for option in options:
        if option in string:
            return option
    raise ValueError(f"Invalid key type: {string} not in {options}")


class CombinedKeyFactory:
    """Factory for creating all known key types."""

    @staticmethod
    def _generate_composite_key_by_name(algorithm: str):
        """Generate a composite key based on the provided key type.

        :param algorithm: The type of key to generate (e.g., "composite-kem", "composite-sig", "composite-dhkem").
        :return: A generated key object.
        :raises InvalidKeyCombination: If the key type is not supported.
        """
        algorithm = algorithm.lower()
        prefix = _any_string_in_string(algorithm, ["kem-06", "kem-05", "dhkem", "kem", "sig-04", "sig-03", "sig"])
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
        pq_key = PQKeyFactory.generate_pq_key(pq_name)

        if "-hash" in algorithm:
            algorithm = algorithm.replace("-hash", "", 1)

        rest = algorithm.replace(f"composite-{prefix}-{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["rsa", "ecdsa", "ecdh", "ec", "ed25519", "ed448", "x25519", "x448"])
        rest = rest.replace(f"{trad_name}", "").replace("-pss", "").strip()

        curve = None
        length = None
        if rest.isdigit():
            length = rest
        else:
            curve = rest.replace("-", "", 1).lower() if rest else None

        trad_key = generate_trad_key(trad_name, curve=curve, length=length)
        key = CombinedKeyFactory.generate_key(
            f"composite-{prefix}",
            pq_key=pq_key,
            trad_key=trad_key,
        )

        pub_key = key.public_key()
        # RSA is only allowed as PSS for composite-sig-04-ml-dsa-87-rsa4096
        if isinstance(pub_key, CompositeSig04PublicKey):
            _ = pub_key.get_oid(use_pss=True)
            return key

        # verify that a correct key was generated.
        # privates are allowed to be invalid for composite-sig keys, because
        # of RSA.
        pub_key.get_oid()
        return key

    @staticmethod
    def _generate_chempat_key_by_name(algorithm: str):
        """Generate a Chempat key based on the provided key type.

        :param algorithm: The type of key to generate (e.g., "chempat").
        :return: A generated key object.
        :raises ValueError: If the key type is not supported.
        """
        algorithm = algorithm.lower()
        rest = algorithm.replace("chempat-", "", 1)
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=rest)
        rest = rest.replace(f"{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["ecdh", "x448", "x25519"])
        rest = rest.replace(trad_name, "", 1)
        curve = rest.replace("-", "", 1) if rest else None
        return HybridKeyFactory.generate_hybrid_key("chempat", pq_name=pq_name, trad_name=trad_name, curve=curve)

    @staticmethod
    def generate_key_from_name(algorithm: str):
        """Generate a key based on the provided key type, including composite CMS keys.

        :param algorithm: The type of key to generate (e.g., "rsa", "ml-kem-768", "composite-kem-ml-kem-768-rsa2048").
        :return: Generated key object.
        :raises ValueError: If the key type is not supported.
        """
        if algorithm.startswith("composite"):
            return CombinedKeyFactory._generate_composite_key_by_name(algorithm)

        if algorithm.startswith("chempat") or algorithm.startswith("Chempat"):
            return CombinedKeyFactory._generate_chempat_key_by_name(algorithm)

        return CombinedKeyFactory.generate_key(algorithm)

    @staticmethod
    def get_all_kem_coms_as_dict() -> Dict[str, List[Dict]]:
        """Return all KEM composites key combinations as a dictionary.

        Enables to display all possible key combinations, or generate keys with
        in all valid combinations.

        :return: Dictionary with all KEM composites key combinations.
        """
        return HybridKeyFactory.get_all_kem_coms_as_dict()

    @staticmethod
    def generate_key(algorithm: str, **kwargs):
        """Generate a key based on the provided key type, including composite CMS keys.

        :param algorithm: The type of key to generate (e.g., "rsa", "ml-kem-768", "composite", "composite_cms").
        :param kwargs: Additional parameters required by the specific key generator.
        :return: Generated key object.
        :raises ValueError: If the key type is not supported.
        """
        if kwargs.get("by_name", False):
            return CombinedKeyFactory.generate_key_from_name(algorithm)

        if algorithm in ["rsa", "ecdsa", "ed25519", "ed448", "bad-rsa-key"]:
            return generate_trad_key(algorithm, **kwargs)

        if algorithm == "rsa-kem":
            trad_key = kwargs.get("trad_key") or generate_trad_key("rsa", **kwargs)
            return RSADecapKey(trad_key)

        if PQKeyFactory.may_be_pq_alg(algorithm=algorithm):
            return PQKeyFactory.generate_pq_key(algorithm=algorithm)

        if algorithm in HybridKeyFactory.supported_algorithms():
            if kwargs.get("pq_key") is not None or kwargs.get("trad_key") is not None:
                return HybridKeyFactory.from_keys(
                    algorithm=algorithm, pq_key=kwargs.get("pq_key"), trad_key=kwargs.get("trad_key")
                )

            return HybridKeyFactory.generate_hybrid_key(algorithm=algorithm, **kwargs)

        options = ", ".join(CombinedKeyFactory.supported_algorithms())
        raise ValueError(f"Unsupported key type: **{algorithm}** Supported are {options}")

    @staticmethod
    def _comp_load_trad_key(
        public_key: bytes,
        trad_name: str,
        curve: Optional[str],
    ):
        """Load a traditional composite public key from the provided bytes.

        :param public_key: The public key bytes.
        :param trad_name: The traditional key type.
        :param curve: The name of the elliptic curve.
        :return: The loaded public key.
        :raises ValueError: If the traditional key type is not supported or cannot be loaded.
        """
        if trad_name == "rsa":
            return serialization.load_der_public_key(public_key)
        if trad_name in ["ecdsa", "ecdh", "ec"]:
            curve_instance = get_curve_instance(curve_name=curve)
            return ec.EllipticCurvePublicKey.from_encoded_point(curve_instance, public_key)
        if trad_name == "x25519":
            return x25519.X25519PublicKey.from_public_bytes(public_key)
        if trad_name == "x448":
            return x448.X448PublicKey.from_public_bytes(public_key)

        if trad_name == "ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(public_key)

        if trad_name == "ed448":
            return ed448.Ed448PublicKey.from_public_bytes(public_key)

        raise ValueError(f"Unsupported traditional public key type: {trad_name}")

    @staticmethod
    def _get_pq_and_trad_names(
        name: str,
    ) -> Tuple[str, str, Optional[str], Optional[str]]:
        """Get the post-quantum and traditional key names from the provided hybrid key name.

        :return: The post-quantum and traditional key names and the curve and RSA length.
        """
        # names starts with <pq_name>-<trad_name><trad_params>.
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=name)
        rest = name.replace(f"{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["rsa", "ecdsa", "ecdh", "ec", "ed25519", "x25519", "x448", "ed448"])
        rest = rest.replace(f"{trad_name}", "")

        curve = None
        length = None

        if trad_name in ["ed25519", "ed448", "x25519", "x448"]:
            pass

        elif not rest.isdigit():
            curve = rest.replace("-", "") if rest else None
        else:
            length = rest

        return pq_name, trad_name, curve, length

    @staticmethod
    def _load_composite_kem06_public_key(oid: univ.ObjectIdentifier, public_key: bytes):
        """Load a composite KEM 06 public key from the provided OID and public key bytes.

        :param oid: The OID of the key.
        :param public_key: The public key bytes.
        :return: The loaded public key.
        :raises BadAsn1Data: If the public key structure is invalid or cannot be decoded.
        :raises InvalidKeyCombination: If the key is invalid or the combination is not supported.
        """
        orig_name = COMPOSITE_KEM06_OID_2_NAME[oid]
        # TODO maybe fix to use the name with the version.
        name = orig_name.replace("composite-kem-", "", 1)
        name = name.replace("composite-kem06-", "", 1)
        name = name.replace("composite-dhkem-", "", 1)
        pq_name, trad_name, curve, length = CombinedKeyFactory._get_pq_and_trad_names(name)
        data = public_key[4:]
        pq_key, rest = PQKeyFactory.from_public_bytes(name=pq_name, data=data, allow_rest=True)

        if trad_name != "rsa":
            curve = "" if curve is None else "-" + curve
            trad_key = DHKEMPublicKey.from_public_bytes(data=rest, name=trad_name + curve)
        else:
            trad_key = serialization.load_der_public_key(rest)

        if "dhkem" not in orig_name:
            return CompositeKEM06PublicKey(pq_key, trad_key)  # type: ignore
        return CompositeDHKEMRFC9180PublicKey(pq_key, trad_key)  # type: ignore

    @staticmethod
    def _get_comp_sig04_key(oid: univ.ObjectIdentifier, public_key: bytes) -> CompositeSig04PublicKey:
        """Load a Composite signature version 4 public key."""
        name = COMPOSITE_SIG04_OID_2_NAME[oid]
        prefix = _any_string_in_string(name, ["sig-04-hash", "sig-04"])
        name = name.replace(f"composite-{prefix}-", "", 1)
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=name)

        # only temporary solution.
        key = PQKeyFactory.generate_pq_key(algorithm=pq_name).public_key()

        key_size = key.key_size
        # currently ignores the size! This is a temporary solution.
        data = public_key[4:]
        mldsa_key_data = data[:key_size]
        trad_data = data[key_size:]

        rest = name.replace(f"{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["rsa", "ecdsa", "ecdh", "ec", "ed25519", "x25519", "x448", "ed448"])
        rest = rest.replace(f"{trad_name}", "")
        curve = None
        if not rest.isdigit():
            curve = rest.replace("-", "", 1) if rest else None

        trad_key = CombinedKeyFactory._comp_load_trad_key(public_key=trad_data, trad_name=trad_name, curve=curve)

        pq_key, rest = PQKeyFactory.from_public_bytes(name=pq_name, data=mldsa_key_data)

        public_key = CompositeSig04PublicKey(pq_key, trad_key)
        public_key.get_oid(use_pss=True)

        return public_key

    @staticmethod
    def _get_composite_public_key(oid: univ.ObjectIdentifier, public_key: bytes) -> AbstractCompositePublicKey:
        """Get a composite public key from the provided OID and public key bytes.

        :param oid: The OID of the key.
        :param public_key: The public key bytes.
        :return: The loaded public key.
        """
        if oid in COMPOSITE_SIG04_OID_2_NAME:
            name = COMPOSITE_SIG04_OID_2_NAME[oid]
        elif oid in CMS_COMPOSITE_OID_2_NAME:
            name = CMS_COMPOSITE_OID_2_NAME[oid]
        elif oid in COMPOSITE_KEM05_OID_2_NAME:
            name = COMPOSITE_KEM05_OID_2_NAME[oid]
        else:
            raise BadAlg(f"Unsupported composite key OID: {oid}")

        prefix = _any_string_in_string(name, ["dhkem", "kem", "sig-hash", "sig"])
        name = name.replace(f"composite-{prefix}-", "", 1)
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=name)
        rest = name.replace(f"{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["rsa", "ecdsa", "ecdh", "ec", "ed25519", "x25519", "x448", "ed448"])
        rest = rest.replace(f"{trad_name}", "")
        curve = None
        if not rest.isdigit():
            curve = rest.replace("-", "", 1) if rest else None

        obj, rest = decoder.decode(public_key, CompositeSignaturePublicKeyAsn1())
        if rest != b"":
            raise BadAsn1Data("Extra data after decoding public key")

        pq_pub_bytes = obj[0].asOctets()
        trad_pub_bytes = obj[1].asOctets()
        pq_key, _ = PQKeyFactory.from_public_bytes(name=pq_name, data=pq_pub_bytes, allow_rest=False)
        trad_key = CombinedKeyFactory._comp_load_trad_key(public_key=trad_pub_bytes, trad_name=trad_name, curve=curve)
        if prefix == "dhkem":
            return CompositeDHKEMRFC9180PublicKey(pq_key, trad_key)
        if prefix == "kem":
            return CompositeKEMPublicKey(pq_key, trad_key)
        return CompositeSig03PublicKey(pq_key, trad_key)  # type: ignore

    @staticmethod
    def load_public_key_from_spki(spki: Union[rfc5280.SubjectPublicKeyInfo, bytes]):
        """Load a public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: The loaded public key.
        """
        if isinstance(spki, bytes):
            spki = try_decode_pyasn1(spki, rfc5280.SubjectPublicKeyInfo())[0]

        oid = spki["algorithm"]["algorithm"]

        if oid in COMPOSITE_SIG04_OID_2_NAME:
            return CombinedKeyFactory._get_comp_sig04_key(oid, spki["subjectPublicKey"].asOctets())

        if oid in CMS_COMPOSITE_OID_2_NAME:
            return CombinedKeyFactory._get_composite_public_key(oid, spki["subjectPublicKey"].asOctets())

        if oid in COMPOSITE_KEM06_OID_2_NAME:
            return CombinedKeyFactory._load_composite_kem06_public_key(oid, spki["subjectPublicKey"].asOctets())

        if oid in COMPOSITE_KEM05_OID_2_NAME:
            return CombinedKeyFactory.load_composite_kem_key(spki)

        if oid in CHEMPAT_OID_2_NAME or oid in CHEMPAT_OID_2_NAME:
            return CombinedKeyFactory.load_chempat_key(spki)

        if oid in PQ_OID_2_NAME or str(oid) in PQ_OID_2_NAME:
            return PQKeyFactory.load_public_key_from_spki(spki=spki)

        if str(oid) == XWING_OID_STR:
            subject_public_key = spki["subjectPublicKey"].asOctets()
            return XWingPublicKey.from_public_bytes(subject_public_key)

        if oid == id_rsa_kem_spki:
            return RSAEncapKey.from_spki(spki)

        return serialization.load_der_public_key(encoder.encode(spki))

    @staticmethod
    def load_composite_kem_key(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a composite KEM public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: Instance of the appropriate CompositeKEMPublicKey subclass.
        """
        oid = spki["algorithm"]["algorithm"]
        alg_name = COMPOSITE_KEM05_OID_2_NAME[oid]

        obj, rest = decoder.decode(spki["subjectPublicKey"].asOctets(), CompositeSignaturePublicKeyAsn1())
        if rest != b"":
            raise ValueError("Extra data after decoding public key")

        pq_pub_bytes = obj[0].asOctets()
        trad_pub_bytes = obj[1].asOctets()

        pq_name = _any_string_in_string(
            alg_name,
            [
                "ml-kem-512",
                "ml-kem-768",
                "ml-kem-1024",
                "frodokem-976-aes",
                "frogokem-1344-aes",
                "frodokem-976-shake",
                "frodokem-1344-shake",
            ],
        )

        if pq_name.startswith("ml"):
            pq_pub = MLKEMPublicKey(
                public_key=pq_pub_bytes,
                alg_name=pq_name.upper(),
            )
        else:
            pq_pub = FrodoKEMPublicKey(
                public_key=pq_pub_bytes,
                alg_name=pq_name,
            )

        trad_name = _any_string_in_string(alg_name, ["rsa", "ecdh", "ed25519", "ed448", "x25519", "x448"])

        if trad_name == "x25519":
            trad_pub = x25519.X25519PublicKey.from_public_bytes(trad_pub_bytes)
        elif trad_name == "x448":
            trad_pub = x448.X448PublicKey.from_public_bytes(trad_pub_bytes)
        elif trad_name == "ecdh":
            curve_name = _any_string_in_string(
                alg_name.lower(), ["secp256r1", "secp384r1", "brainpoolp256r1", "brainpoolß384r1"]
            )
            curve = get_curve_instance(curve_name)
            trad_pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, trad_pub_bytes)
        elif trad_name.startswith("rsa"):
            trad_pub = serialization.load_der_public_key(trad_pub_bytes)
        else:
            raise ValueError(f"Unsupported traditional public key type: {trad_name}")

        if "dhkem" in alg_name:
            return CompositeDHKEMRFC9180PublicKey(pq_pub, trad_pub)
        return CompositeKEMPublicKey(pq_pub, trad_pub)

    @staticmethod
    def supported_algorithms():
        """List all supported key types by this factory.

        :return: List of supported key types.
        """
        trad_names = ["rsa", "ecdsa", "ed25519", "ed448", "bad-rsa-key", "x25519", "x448", "rsa-kem"]
        hybrid_names = HybridKeyFactory.supported_algorithms()
        pq_names = PQKeyFactory.supported_algorithms()
        return trad_names + pq_names + hybrid_names

    @staticmethod
    def load_chempat_key(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a Chempat public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: Instance of the appropriate ChempatPublicKey subclass.
        :raises KeyError: If the key OID is invalid.
        """
        oid = spki["algorithm"]["algorithm"]
        alg_name = CHEMPAT_OID_2_NAME.get(oid)
        alg_name = alg_name or CHEMPAT_OID_2_NAME[str(oid)]
        if alg_name is None:
            raise KeyError(f"Invalid Chempat key OID: {oid}")
        raw_bytes = spki["subjectPublicKey"].asOctets()
        return ChempatPublicKey.from_public_bytes(data=raw_bytes, name=alg_name)

    @staticmethod
    def _decode_keys_for_composite(name: str, private_key: bytes, public_key: Optional[bytes] = None):
        """Decode a composite key from the provided bytes.

        :return: The decoded composite key.
        """
        prefix = _any_string_in_string(name, ["dhkem", "kem", "sig-hash", "sig"])
        name = name.replace(f"composite-{prefix}-", "", 1)
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=name)
        rest = name.replace(f"{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["rsa", "ecdsa", "ecdh", "ec", "ed25519", "x25519", "x448", "ed448"])

        obj, rest = decoder.decode(private_key, asn1Spec=CompositeSignaturePrivateKeyAsn1())
        if rest:
            raise BadAsn1Data("CompositeSignaturePrivateKey")

        if public_key is not None:
            obj, rest = decoder.decode(public_key, asn1Spec=CompositeSignaturePrivateKeyAsn1())
            if rest:
                raise ValueError("Found remainder after decoding `CompositeSignaturePublicKey`.")

        obj[0]["privateKeyAlgorithm"]["algorithm"] = PQ_NAME_2_OID[pq_name]
        pq_key = PQKeyFactory.from_one_asym_key(obj[0])
        if trad_name == "rsa" and prefix == "kem":
            trad_key = RSADecapKey.from_pkcs8(obj[1])
            return CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)  # type: ignore

        trad_key = serialization.load_der_private_key(encoder.encode(obj[1]), password=None)

        if prefix == "kem":
            return CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)

        if prefix == "dhkem":
            return CompositeDHKEMRFC9180PrivateKey(pq_key=pq_key, trad_key=trad_key)  # type: ignore

        return CompositeSig03PrivateKey(pq_key=pq_key, trad_key=trad_key)

    @staticmethod
    def _load_private_key_from_data(name, trad_data, curve: Optional[str] = None):
        """Load a traditional private key from the provided data."""
        if name in ["x25519", "x448", "ecdh"]:
            key = DHKEMPrivateKey.from_private_bytes(name=name, data=trad_data, curve=curve)
            return key._private_key
        if name == "ed25519":
            return Ed25519PrivateKey.from_private_bytes(data=trad_data)
        if name == "ed448":
            return Ed448PrivateKey.from_private_bytes(data=trad_data)
        if name == "ecdsa":
            if curve is None:
                raise ValueError("EdDSA and EdDH curves are not provided.")

            trad_key = serialization.load_der_private_key(trad_data, password=None)
        else:
            trad_key = serialization.load_der_private_key(trad_data, password=None)

        return trad_key

    @staticmethod
    def _decode_composite_kem06(
        name: str,
        private_key: bytes,
        public_key: Optional[bytes],
    ) -> CompositeKEM06PrivateKey:
        tmp_name = name.replace("composite-kem-06", "", 1)
        tmp_name = tmp_name.replace("composite-kem", "", 1)
        pq_name, trad_name, curve, length = CombinedKeyFactory._get_pq_and_trad_names(tmp_name)

        _length = int.from_bytes(private_key[:4], "big", signed=False)

        data = private_key[4:]
        trad_data = data[_length:]
        pq_data = data[:_length]

        pq_key_data, rest = decoder.decode(pq_data, asn1Spec=univ.OctetString())
        if rest:
            raise BadAsn1Data("CompositeKEM06PrivateKey")

        pq_key_data = pq_key_data.asOctets()

        pq_key = PQKeyFactory.generate_pq_key(pq_name)
        loaded_pq_key = pq_key.from_private_bytes(pq_key_data, name=pq_name)

        trad_data, rest = decoder.decode(trad_data, univ.OctetString())

        if rest:
            raise BadAsn1Data("CompositeKEM06PrivateKey")

        trad_data = trad_data.asOctets()
        trad_key = CombinedKeyFactory._load_private_key_from_data(trad_name, trad_data=trad_data, curve=curve)
        private_key = CompositeKEM06PrivateKey(pq_key=loaded_pq_key, trad_key=trad_key)
        if public_key is not None:
            oid = COMPOSITE_KEM06_NAME_2_OID[name]
            pub_key = CombinedKeyFactory._load_composite_kem06_public_key(oid, public_key)

            if pub_key != private_key.public_key():
                raise InvalidKeyData("The composite KEM06 public key does not match the private key.")

        return private_key

    @staticmethod
    def _decode_composite_sig04_key(
        name: str,
        private_key: bytes,
        public_key: Optional[bytes],
    ) -> CompositeSig04PrivateKey:
        """Load a composite sig version 4 private key."""
        prefix = _any_string_in_string(name, ["sig-04-hash", "sig-04"])
        name = name.replace(f"composite-{prefix}-", "", 1)
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=name)
        rest = name.replace(f"{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["rsa", "ecdsa", "ecdh", "ec", "ed25519", "ed448"])
        rest = rest.replace(f"{trad_name}", "").replace("-pss", "")
        curve = rsa_length = None
        if trad_name in ["ed25519", "ed448"]:
            pass

        elif not rest.isdigit():
            curve = _any_string_in_string(
                rest.lower(), ["secp256r1", "secp384r1", "brainpoolp256r1", "brainpoolp384r1"]
            )
        else:
            rsa_length = int(rest)

        tmp = MLDSAPrivateKey(pq_name)
        try:
            other = copy.deepcopy(private_key)
            obj, _ = decoder.decode(other, asn1Spec=CompositeSignaturePrivateKeyAsn1())
        except pyasn1.error.PyAsn1Error:
            pass
        else:
            tmp_data = obj[0]["privateKey"].asOctets()
            if len(tmp_data) == tmp.key_size + 32:
                raise NotImplementedError("Not implemented yet, to load a private key with the seed and the raw data.")

            trad_key = serialization.load_der_private_key(encoder.encode(obj[1]), password=None)
            if len(tmp_data) == tmp.key_size + tmp.public_key().key_size:
                ml_priv = MLDSAPrivateKey.from_private_bytes(tmp_data[: tmp.key_size], name=pq_name)
                ml_pub = MLDSAPublicKey.from_public_bytes(tmp_data[tmp.key_size :], name=pq_name)

                if ml_priv.public_key() != ml_pub:
                    raise ValueError("The loaded public key is no match with the loaded private key.")

                return CompositeSig04PrivateKey(pq_key=ml_priv, trad_key=trad_key)

            ml_dsa_key = CombinedKeyFactory.load_key_from_one_asym_key(encoder.encode(obj[0]))

            if ml_dsa_key.name != pq_name:
                raise ValueError(
                    f"Invalid composite signature version 4 {pq_name} key."
                    f"After loading: {ml_dsa_key.name}, Expected: {pq_name}"
                )
            return CompositeSig04PrivateKey(pq_key=ml_dsa_key, trad_key=trad_key)

        # Currently ignores the size! This is a temporary solution.
        _length = int.from_bytes(private_key[:4], "big")

        data = private_key[4:]
        trad_data = data[_length:]
        pq_data = data[:_length]

        obj, rest = decoder.decode(pq_data, asn1Spec=univ.OctetString())
        if rest:
            raise BadAsn1Data("CompositeSig04PrivateKey")

        mldsa_key = obj.asOctets()

        if len(mldsa_key) not in [tmp.key_size, 32, tmp.key_size + 32]:
            raise ValueError(
                f"Invalid composite signature version 4 {pq_name} key."
                f"Composite name: {name} "
                f"Expected: {tmp.key_size}, 32, {tmp.key_size + 32}, got: {len(mldsa_key)}"
            )

        if len(mldsa_key) == tmp.key_size + 32:
            tmp1 = MLDSAPrivateKey(pq_name, seed=mldsa_key[:32])
            tmp2 = MLDSAPrivateKey(pq_name, seed=mldsa_key[tmp.key_size :])
            if tmp1.private_bytes_raw() == mldsa_key[32:]:
                mldsa_key = mldsa_key[:32]

            elif tmp2.private_bytes_raw() == mldsa_key[tmp.key_size]:
                mldsa_key = mldsa_key[tmp.key_size :]
            else:
                raise ValueError(f"Invalid composite signature version 4 {pq_name} key.")

        trad_data, rest = decoder.decode(trad_data, univ.OctetString())

        if rest:
            raise BadAsn1Data("CompositeSig04PrivateKey")

        trad_data = trad_data.asOctets()
        pq_key = MLDSAPrivateKey.from_private_bytes(name=pq_name, data=mldsa_key)
        if trad_name == "ed25519":
            trad_key = Ed25519PrivateKey.from_private_bytes(trad_data)
        elif trad_name == "ed448":
            trad_key = Ed448PrivateKey.from_private_bytes(trad_data)
        elif trad_name == "ecdsa":
            trad_key = serialization.load_der_private_key(trad_data, password=None)

            if curve != trad_key.curve.name:
                raise InvalidKeyCombination(
                    f"Invalid curve for composite signature version 4 "
                    f"Expected ECDSA: {curve}, got:{trad_key.curve.name}."
                )

        else:
            trad_key = serialization.load_der_private_key(trad_data, password=None)

            if rsa_length != trad_key.key_size:
                raise InvalidKeyCombination(
                    f"Invalid key size for composite signature version 4 "
                    f"Expected RSA: {rsa_length}, got:{trad_key.key_size}."
                )

        comp_key = CompositeSig04PrivateKey(pq_key=pq_key, trad_key=trad_key)

        if public_key is None:
            return comp_key

        oid = COMPOSITE_SIG04_NAME_2_OID[comp_key.name]
        public_key = CombinedKeyFactory._get_comp_sig04_key(oid, public_key=public_key)

        if comp_key.public_key() != public_key:
            raise ValueError("The loaded public is no match with the composite sig v04 private key")
        return comp_key

    @staticmethod
    def load_key_from_one_asym_key(data: Union[bytes, rfc5958.OneAsymmetricKey], must_be_version_2: bool = False):
        """Parse a key from a OneAsymmetricKey structure.

        :param data: The OneAsymmetricKey structure or DER encoded data.
        :param must_be_version_2: If True, the key must be version 2 (include the public key). Defaults to `False`.
        :return: The loaded private key.
        :raises ValueError: If the key type is invalid.
        :raises BadAlg: If the algorithm is not supported.
        """
        if isinstance(data, bytes):
            one_asym_key, _ = decoder.decode(data, asn1Spec=rfc5958.OneAsymmetricKey())
        else:
            one_asym_key = data

        oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]
        private_bytes = one_asym_key["privateKey"].asOctets()
        public_bytes = one_asym_key["publicKey"].asOctets() if one_asym_key["publicKey"].isValue else None

        if oid in COMPOSITE_SIG04_OID_2_NAME:
            _name = COMPOSITE_SIG04_OID_2_NAME[oid]
            return CombinedKeyFactory._decode_composite_sig04_key(_name, private_bytes, public_bytes)

        if oid in COMPOSITE_KEM06_OID_2_NAME:
            _name = COMPOSITE_KEM06_OID_2_NAME[oid]
            return CombinedKeyFactory._decode_composite_kem06(_name, private_bytes, public_bytes)

        if oid in COMPOSITE_KEM05_OID_2_NAME:
            _name = COMPOSITE_KEM05_OID_2_NAME[oid]
            return CombinedKeyFactory._decode_keys_for_composite(_name, private_bytes, public_bytes)

        if oid in CMS_COMPOSITE_OID_2_NAME:
            name = CMS_COMPOSITE_OID_2_NAME[oid]
            return CombinedKeyFactory._decode_keys_for_composite(name, private_bytes, public_bytes)

        if oid == id_rsa_kem_spki:
            return RSADecapKey.from_pkcs8(data)

        if oid in TRAD_STR_OID_TO_KEY_NAME or oid == rfc6664.id_ecPublicKey:
            return parse_trad_key_from_one_asym_key(one_asym_key=one_asym_key, must_be_version_2=must_be_version_2)

        if oid in PQ_OID_2_NAME:
            return PQKeyFactory.from_one_asym_key(one_asym_key)

        return HybridKeyFactory.from_one_asym_key(one_asym_key)


def _load_traditional_private_key(name: str, private_data: bytes, curve: Optional[str] = None):
    """Load a traditional private key from the given private key data."""
    if name in ["x25519", "x448", "ecdh"]:
        return DHKEMPrivateKey.from_private_bytes(name, private_data, curve=curve)._private_key
    elif name == "ed25519":
        return Ed25519PrivateKey.from_private_bytes(private_data)
    elif name == "ed448":
        return Ed448PrivateKey.from_private_bytes(private_data)
    else:
        return serialization.load_der_private_key(private_data, password=None)
