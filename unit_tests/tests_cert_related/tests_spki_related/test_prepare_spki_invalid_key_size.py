# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.ca_ra_utils import validate_cert_template
from resources.certbuildutils import prepare_cert_template, prepare_subject_public_key_info
from resources.exceptions import BadAsn1Data
from resources.keyutils import load_private_key_from_file


class TestPrepareSPKIInvalidKeySize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
        cls.comp_key = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")

    @staticmethod
    def _prepare_cert_template(key):
        """Prepare a certificate template."""
        spki = prepare_subject_public_key_info(key, invalid_key_size=True)
        cert_template = prepare_cert_template(key, subject="CN=Hans the Tester", spki=spki)
        return cert_template

    def test_prepare_spki_invalid_key_size_rsa(self):
        """
        GIVEN a SPKI with an invalid key size.
        WHEN preparing the SPKI,
        THEN an exception is raised.
        """
        cert_template = self._prepare_cert_template(self.rsa_key)
        with self.assertRaises(BadAsn1Data):
            validate_cert_template(cert_template)

    def test_prepare_spki_invalid_key_size_ml_dsa(self):
        """
        GIVEN a SPKI with an invalid key size.
        WHEN preparing the SPKI,
        THEN an exception is raised.
        """
        cert_template = self._prepare_cert_template(self.mldsa_key)
        with self.assertRaises(BadAsn1Data):
            validate_cert_template(cert_template)

    def test_prepare_spki_invalid_key_size_composite(self):
        """
        GIVEN a SPKI with an invalid key size.
        WHEN preparing the SPKI,
        THEN an exception is raised.
        """
        cert_template = self._prepare_cert_template(self.comp_key)
        with self.assertRaises(BadAsn1Data):
            validate_cert_template(cert_template)
