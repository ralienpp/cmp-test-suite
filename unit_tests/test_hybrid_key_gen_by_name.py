import unittest
from pq_logic.tmp_oids import COMPOSITE_SIG04_NAME_2_OID, COMPOSITE_SIG03_NAME_2_OID, COMPOSITE_KEM05_NAME_2_OID, \
    CHEMPAT_NAME_2_OID, CHEMPAT_OID_2_NAME, COMPOSITE_KEM05_OID_2_NAME, COMPOSITE_SIG03_OID_2_NAME, \
    COMPOSITE_SIG04_OID_2_NAME, COMPOSITE_KEM06_NAME_2_OID, COMPOSITE_KEM06_OID_2_NAME
from resources.keyutils import generate_key, get_key_name
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import PQ_SIG_PRE_HASH_NAME_2_OID


class TestCompositeSig04(unittest.TestCase):

    def test_pq_sig_keys(self):
        """
        GIVEN all PQ signature algorithms.
        WHEN generating keys by name,
        THEN is the correct key generated.
        """
        for name in PQ_SIG_PRE_HASH_NAME_2_OID:
            key = generate_key(name, by_name=True)
            hash_alg = name.split("-")[-1]
            self.assertEqual(name, key.name + "-" + hash_alg)


    def test_composite_sig04(self):
        """
        GIVEN all known composite signature version 4 algorithms.
        WHEN generating keys by name,
        THEN is the correct key generated.
        """
        for name in COMPOSITE_SIG04_NAME_2_OID:
            use_pss = "pss" in name
            pre_hash = "hash" in name
            key = generate_key(name, by_name=True)
            _oid = key.public_key().get_oid(use_pss=use_pss, pre_hash=pre_hash) # type: ignore
            err_msg = f"Expected: {name} Got: {may_return_oid_to_name(_oid)}"
            self.assertEqual(COMPOSITE_SIG04_OID_2_NAME.get(_oid), name, err_msg)

    def test_composite_sig03(self):
        """
        GIVEN all known composite signature version 3 algorithms.
        WHEN generating keys by name,
        THEN is the correct key generated.
        """
        for name in COMPOSITE_SIG03_NAME_2_OID:
            use_pss = "pss" in name
            pre_hash = "hash" in name
            key = generate_key(name, by_name=True)
            _oid = key.public_key().get_oid(use_pss=use_pss, pre_hash=pre_hash) # type: ignore
            err_msg = f"Expected: {name} Got: {may_return_oid_to_name(_oid)}"
            self.assertEqual(COMPOSITE_SIG03_OID_2_NAME.get(_oid), name, err_msg)

    def test_composite_kem(self):
        """
        GIVEN all known composite KEM algorithms.
        WHEN generating keys by name,
        THEN is the correct key generated.
        """
        for name in COMPOSITE_KEM05_NAME_2_OID:
            key = generate_key(name, by_name=True)
            _oid = key.public_key().get_oid()
            err_msg = f"Expected: {name} Got: {may_return_oid_to_name(_oid)}"
            self.assertEqual(COMPOSITE_KEM05_OID_2_NAME.get(_oid), name, err_msg)

    def test_chempat(self):
        """
        GIVEN all known Chempat algorithms.
        WHEN generating keys by name,
        THEN is the correct key generated.
        """
        for name in CHEMPAT_NAME_2_OID:
            key = generate_key(name, by_name=True)
            _oid = key.public_key().get_oid()
            err_msg = f"Expected: {name} Got: {may_return_oid_to_name(_oid)}"
            self.assertEqual(CHEMPAT_OID_2_NAME.get(_oid), name, err_msg)

    def test_composite_kem_06(self):
        """
        GIVEN all known composite KEM 06 algorithms.
        WHEN generating keys by name,
        THEN is the correct key generated.
        """
        for x in COMPOSITE_KEM06_NAME_2_OID:
            key = generate_key(x, by_name=True)
            _oid = key.public_key().get_oid()
            err_msg = f"Expected: {x} Got: {may_return_oid_to_name(_oid)}"
            self.assertEqual(COMPOSITE_KEM06_OID_2_NAME.get(_oid), x, err_msg)


    def test_generate_trad_key(self):
        """
        GIVEN all known key traditional key names.
        WHEN generating keys by name,
        THEN is the correct key generated.
        """
        for name in ["rsa", "ecdsa", "ed25519" , "ed448",
                     "x448", "x25519"]:
            key = generate_key(name, by_name=True)
            key_name = get_key_name(key)
            self.assertEqual(name, key_name, "Expected: {} Got: {}".format(name, key_name))

        rsa_kem = generate_key("rsa-kem", by_name=True)
        self.assertEqual(get_key_name(rsa_kem), "rsa-kem")
        ec_dh_key = generate_key("ecdh", by_name=True)
        self.assertEqual(get_key_name(ec_dh_key), "ecdsa")


if __name__ == '__main__':
    unittest.main()