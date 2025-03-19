import unittest

from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey
from resources.keyutils import generate_key


class TestCompSig04KeyGeneration(unittest.TestCase):

    def test_comp_sig04_key_generation(self):
        """
        GIVEN a composite signature key in version 4.
        WHEN generating the key.
        THEN the key is generated successfully.
        """
        key2 = generate_key("composite-sig-04")
        self.assertIsInstance(key2, CompositeSig04PrivateKey)

    def test_comp_sig04_key_generation_by_name_rsa4096(self):
        """
        GIVEN a composite signature key in version 4.
        WHEN generating the key by name.
        THEN the key is generated successfully.
        """
        key = generate_key("composite-sig-04-ml-dsa-87-rsa4096", by_name=True)
        self.assertEqual(key.name, "composite-sig-04-ml-dsa-87-rsa4096")
        self.assertIsInstance(key, CompositeSig04PrivateKey)
        self.assertEqual(key.trad_key.key_size, 4096)

    def test_comp_sig04_key_generation_by_name(self):
        """
        GIVEN a composite signature key in version 4.
        WHEN generating the key by name.
        THEN the key is generated successfully.
        """
        key = generate_key("composite-sig-04")
        key2 = generate_key(key.name, by_name=True)
        self.assertEqual(key.name, key2.name)
        self.assertIsInstance(key2, CompositeSig04PrivateKey)
