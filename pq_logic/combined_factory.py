# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Key factory to create all supported keys."""

from typing import Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, x448, x25519
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5958
from resources.exceptions import BadAlg, BadAsn1Data
from resources.oid_mapping import get_curve_instance
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, PQ_OID_2_NAME, XWING_OID_STR

from pq_logic.chempatkem import ChempatPublicKey
from pq_logic.hybrid_structures import (
    CompositeSignaturePublicKeyAsn1,
)
from pq_logic.keys.abstract_wrapper_keys import AbstractCompositePublicKey
from pq_logic.keys.comp_sig_cms03 import (
    CompositeSigCMSPublicKey,
)
from pq_logic.keys.composite_kem import (
    CompositeDHKEMRFC9180PublicKey,
    CompositeKEMPublicKey,
)
from pq_logic.keys.hybrid_key_factory import HybridKeyFactory
from pq_logic.keys.kem_keys import FrodoKEMPublicKey, MLKEMPublicKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.keys.trad_key_factory import generate_trad_key
from pq_logic.keys.trad_keys import RSADecapKey, RSAEncapKey
from pq_logic.keys.xwing import XWingPublicKey
from pq_logic.tmp_oids import CHEMPAT_OID_2_NAME, COMPOSITE_KEM_OID_2_NAME, id_rsa_kem_spki


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

    raise ValueError(f"Invalid key type: {string}")


class CombinedKeyFactory:
    """Factory for creating all known key types."""

    @staticmethod
    def _geneerate_composite_key_by_name(algorithm: str):
        """Generate a composite key based on the provided key type.

        :param algorithm: The type of key to generate (e.g., "composite-kem", "composite-sig", "composite-dhkem").
        :return: A generated key object.
        :raises ValueError: If the key type is not supported.
        """
        prefix = _any_string_in_string(algorithm, ["dhkem", "kem", "sig"])
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)

        rest = algorithm.replace(f"composite-{prefix}-{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["rsa", "ecdsa", "ecdh", "ec"])
        rest = rest.replace(f"{trad_name}", "")

        curve = None
        length = None
        if rest.isdigit():
            length = int(rest)
        else:
            curve = rest.replace("-", "", 1) if rest else None

        return CombinedKeyFactory.generate_key(
            f"composite-{prefix}",
            pq_name=pq_name,
            trad_name=trad_name,
            length=length,
            curve=curve,
        )

    @staticmethod
    def _generate_chempat_key_by_name(algorithm: str):
        """Generate a Chempat key based on the provided key type.

        :param algorithm: The type of key to generate (e.g., "chempat").
        :return: A generated key object.
        :raises ValueError: If the key type is not supported.
        """
        algorithm = algorithm.replace("Chempat", "chempat", 1)
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
        rest = algorithm.replace(f"chempat-{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["ecdh", "x448", "x25519"])
        rest = rest.replace(trad_name, "")
        curve = rest.replace("-", "", 1) if rest else None
        return CombinedKeyFactory.generate_key("chempat", pq_name=pq_name, trad_name=trad_name, curve=curve)

    @staticmethod
    def generate_key_from_name(algorithm: str):
        """Generate a key based on the provided key type, including composite CMS keys.

        :param algorithm: The type of key to generate (e.g., "rsa", "ml-kem-768", "composite-kem-ml-kem-768-rsa2048").
        :return: Generated key object.
        :raises ValueError: If the key type is not supported.
        """
        if algorithm.startswith("composite"):
            return CombinedKeyFactory._geneerate_composite_key_by_name(algorithm)

        if algorithm.startswith("chempat"):
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
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: The loaded public key.
        """
        oid = spki["algorithm"]["algorithm"]

        if oid in CMS_COMPOSITE_OID_2_NAME:
            return CompositeSigCMSPublicKey.from_spki(spki)

        if str(oid) in COMPOSITE_KEM_OID_2_NAME:
            return CombinedKeyFactory.load_composite_kem_key(spki)

        if str(oid) in CHEMPAT_OID_2_NAME or oid in CHEMPAT_OID_2_NAME:
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
        alg_name = COMPOSITE_KEM_OID_2_NAME[str(oid)]

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
                kem_alg=pq_name.upper(),
            )
        else:
            pq_pub = FrodoKEMPublicKey(
                public_key=pq_pub_bytes,
                kem_alg=pq_name,
            )

        trad_name = _any_string_in_string(alg_name, ["rsa", "ecdh", "ed25519", "ed448", "x25519", "x448"])

        if trad_name == "x25519":
            trad_pub = x25519.X25519PublicKey.from_public_bytes(trad_pub_bytes)
        elif trad_name == "x448":
            trad_pub = x448.X448PublicKey.from_public_bytes(trad_pub_bytes)
        elif trad_name == "ecdh":
            curve_name = _any_string_in_string(
                alg_name, ["secp256r1", "secp384r1", "brainpoolP256r1", "brainpoolP384r1"]
            )
            curve = get_curve_instance(curve_name)
            trad_pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, trad_pub_bytes)
        elif trad_name.startswith("rsa"):
            trad_pub = serialization.load_der_public_key(trad_pub_bytes)
        else:
            raise ValueError(f"Unsupported traditional public key type: {trad_name}")

        if alg_name.startswith("dhkem"):
            return CompositeDHKEMRFC9180PublicKey(pq_pub, trad_pub)
        return CompositeKEMPublicKey(pq_pub, trad_pub)

    @staticmethod
    def supported_algorithms():
        """List all supported key types by this factory.

        :return: List of supported key types.
        """
        trad_names = ["rsa", "ecdsa", "ed25519", "ed448", "bad-rsa-key", "x25519", "x448"]
        hybrid_names = HybridKeyFactory.supported_algorithms()
        pq_names = PQKeyFactory.supported_algorithms()
        return trad_names + pq_names + hybrid_names

    @staticmethod
    def load_key_from_one_asym_key(one_asym_key: rfc5958.OneAsymmetricKey):
        """Load a private key from a OneAsymmetricKey structure.

        :param one_asym_key: The OneAsymmetricKey structure.
        :return: The loaded private key.
        """
        from pq_logic.keys.key_pyasn1_utils import parse_key_from_one_asym_key

        der_data = encoder.encode(one_asym_key)
        return parse_key_from_one_asym_key(der_data)

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
