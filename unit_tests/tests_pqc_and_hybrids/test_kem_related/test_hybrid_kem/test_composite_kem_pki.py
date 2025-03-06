# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.hybrid_key_factory import HybridKeyFactory
from pq_logic.keys.composite_kem import (
    CompositeDHKEMRFC9180PrivateKey,
    CompositeKEMPrivateKey,
)
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.tmp_oids import id_mlkem768_rsa2048
from resources.keyutils import generate_key


class TestCompositeMLKEM(unittest.TestCase):

    def setUp(self):
        # RSA-based composite keys
        self.private_key_rsa_1: CompositeKEMPrivateKey = generate_key("composite-kem", pq_name="ml-kem-768", trad_name="rsa")

        # EC-based composite keys
        self.private_key_ec_1: CompositeKEMPrivateKey = generate_key("composite-kem", pq_name="ml-kem-768", curve="secp384r1")
        self.private_key_ec_2 = generate_key("ecc", curve="secp384r1")

        # X-based composite keys
        self.private_key_x_1: CompositeKEMPrivateKey = generate_key("composite-kem",pq_name="ml-kem-768", trad_name="x25519")
        self.private_key_x_2 =  generate_key("x25519")

    def test_get_oid_composite_valid(self):
        """
        GIVEN a valid composite key.
        WHEN the OID is requested.
        THEN the OID should not be None.
        """
        oid = self.private_key_rsa_1.get_oid()
        self.assertEqual(oid, id_mlkem768_rsa2048,"OID should not be None for valid inputs.")

    def test_encaps_and_decaps_rsa(self):
        """
        GIVEN an RSA-based composite key.
        WHEN encapsulating and decapsulating
        :return:
        """
        shared_secret, ct_vals = self.private_key_rsa_1.public_key().encaps()
        decaps_ss = self.private_key_rsa_1.decaps(ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for RSA-based keys.")

    def test_encaps_and_decaps_ec(self):
        """
        GIVEN an EC-based composite key.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        shared_secret, ct_vals = self.private_key_ec_1.public_key().encaps(self.private_key_ec_2)
        decaps_ss = self.private_key_ec_1.decaps(ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for EC-based keys.")

    def test_encaps_and_decaps_x25519(self):
        """
        GIVEN a X25519-based composite key.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        shared_secret, ct_vals = self.private_key_x_1.public_key().encaps(self.private_key_x_2)
        decaps_ss = self.private_key_x_1.decaps(ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for X25519-based keys.")

    def test_encaps_and_decaps_x448(self):
        """"""
        comp_key = HybridKeyFactory.generate_comp_kem_key(
            pq_name="ml-kem-1024", trad_name="x448")
        key2 = generate_key("x448")
        shared_secret, ct_vals = comp_key.public_key().encaps(key2)
        decaps_ss = comp_key.decaps(ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for X448-based keys.")


    def test_encaps_and_decaps_frodokem_x25519(self):
        """
        GIVEN two FrodoKEM 976 AES-based composite keys.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        comp_key = HybridKeyFactory.generate_comp_kem_key(
            pq_name="frodokem-976-aes", trad_name="x25519")

        key2 = generate_key("x25519")

        shared_secret, ct_vals = comp_key.public_key().encaps(key2)
        decaps_ss = comp_key.decaps(ct=ct_vals)
        self.assertEqual(shared_secret, decaps_ss, "Shared secret mismatch for FrodoKEM X25519-based keys.")


    def test_encaps_and_decaps_mlkem768_dhkemrfc9180_x25519(self):
        """
        GIVEN a ML-KEM 768-based composite key.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        trad_key1 = generate_key("x25519")
        pq_key1 = PQKeyFactory.generate_pq_key("ml-kem-768")

        key1 = CompositeDHKEMRFC9180PrivateKey(pq_key=pq_key1, trad_key=trad_key1)

        ss, ct = key1.public_key().encaps()

        ss2 = key1.decaps(ct)
        self.assertEqual(ss, ss2)

    def test_encaps_and_decaps_frodokem_976_aes_dhkemrfc9180_x25519(self):
        """
        GIVEN a FrodoKEM 976 AES-based composite key.
        WHEN the encapsulation and decapsulation is performed.
        THEN the shared secret should be equal.
        """
        trad_key1 = generate_key("x25519")
        pq_key1 = PQKeyFactory.generate_pq_key("frodokem-976-aes")
        key1 = CompositeDHKEMRFC9180PrivateKey(pq_key=pq_key1, trad_key=trad_key1)

        ss, ct = key1.public_key().encaps()

        ss2 = key1.decaps(ct)
        self.assertEqual(ss, ss2)