import unittest

from resources.cert_linters_utils import validate_crl_pkilint
from resources.utils import load_and_decode_pem_file


class TestLintCRL(unittest.TestCase):
    def test_crl_with_aki(self):
        """
        GIVEN a CRL without the AuthorityKeyIdentifier extension.
        WHEN the CRL is validated using the pkilint tool.
        THEN a ValueError is raised.
        """
        loaded_data = load_and_decode_pem_file("data/unittest/test_verify_crl.crl")
        with self.assertRaises(ValueError):
            validate_crl_pkilint(data=loaded_data)
