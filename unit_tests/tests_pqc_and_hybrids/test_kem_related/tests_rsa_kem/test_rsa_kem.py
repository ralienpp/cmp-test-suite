# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

# test_rsa_kem.py

import binascii
import unittest
from typing import Tuple

from cryptography.hazmat.primitives import serialization

from pq_logic.kem_mechanism import RSAKem
from resources.httputils import ssl_client

RSAKem

from resources.cryptoutils import compute_ansi_x9_63_kdf
from resources.keyutils import generate_key
from resources.utils import decode_pem_string, load_and_decode_pem_file


def i2osp(x: int, x_len: int) -> bytes:
    """
    Integer-to-Octet-String primitive.
    """
    h = x.to_bytes(x_len, byteorder="big")
    if len(h) > x_len:
        raise ValueError("Integer too large to encode at the specified length.")
    return h

def _perform_rsa_kem_encapsulate(public_key, z_value, ss_len: int = 16) -> Tuple[bytes, bytes]:
    """Perform RSA-KEM encapsulation, with a known integer z."""
    numbers = public_key.public_numbers()
    n = numbers.n
    e = numbers.e
    n_len = (n.bit_length() + 7) // 8

    # z must be < n
    if z_value >= n:
        raise ValueError("z_value >= modulus, invalid ephemeral integer")

    # RSA-KEM steps
    c = pow(z_value, e, n)
    ct = i2osp(c, n_len)
    Z = i2osp(z_value, n_len)
    SS = compute_ansi_x9_63_kdf(Z, ss_len, hash_alg="sha256", other_info=b"", use_version_2=False)
    return SS, ct

def _perform_rsa_kem_decapsulation(private_key, ct: bytes, ss_len: int = 16) -> bytes:
    """Perform RSA-KEM decapsulation."""
    Z = RSAKem().decaps(private_key, ct)
    SS = compute_ansi_x9_63_kdf(Z, ss_len, hash_alg="sha256", other_info=b"",
                                use_version_2=False)
    return SS

def rsa_kem_encapsulate(public_key, ss_len: int = 32) -> Tuple[bytes, bytes]:
    """Perform RSA-KEM encapsulation."""
    return RSAKem(ss_length=ss_len).encaps(public_key)



class TestRSAKEM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = generate_key("rsa")
        cls.public_key = cls.private_key.public_key()

    def test_rsa_kem_random_correctness(self):
        """
        GIVEN an RSA public key and private key.
        WHEN we encapsulate and decapsulate a random ephemeral integer z,
        THEN should the shared secret be the same.
        """
        ss_len = 32
        SS_encapsulated, ct  = rsa_kem_encapsulate(self.public_key, ss_len)
        SS_decapsulated = _perform_rsa_kem_decapsulation(self.private_key, ct, ss_len)

        self.assertEqual(
            SS_encapsulated, SS_decapsulated, "Random ephemeral z: mismatch between encapsulated & decapsulated SS"
        )

    def test_rsa_kem_ciphertext_length(self):
        """
        GIVEN an RSA public key.
        WHEN we encapsulate and shorten the ciphertext by one byte.
        THEN should a ValueError be raised, due to being too short.
        """
        ss_len = 16
        ct, _ = rsa_kem_encapsulate(self.public_key, ss_len)
        bad_ct = ct[:-1]
        with self.assertRaises(ValueError):
            RSAKem().decaps(self.private_key, bad_ct)

    def test_rsa_kem_ciphertext_range(self):
        """
        GIVEN an RSA public key.
        WHEN we encapsulate and add one byte to the ciphertext.
        THEN should a ValueError be raised, due to being too large.
        """
        n_len = (self.public_key.public_numbers().n.bit_length() + 7) // 8
        bad_ct = b"\xff" * n_len
        with self.assertRaises(ValueError):
            RSAKem().decaps(self.private_key, bad_ct)

    def test_rsa_kem_known_vector(self):
        """
        GIVEN an RSA public key and private key.
        WHEN we encapsulate and decapsulate a known ephemeral integer z,
        THEN should the shared secret be the same as the known test vectors.
        """

        bob_private_key_pem = b"""\
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
"""


        bob_pubkey_pem = b"""\
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA3ocW14cxncPJ47fnEjBZ
AyfC2lqapL3ET4jvV6C7gGeVrRQxWPDwl+cFYBBR2ej3j3/0ecDmu+XuVi2+s5JH
Keeza+itfuhsz3yifgeEpeK8T+SusHhn20/NBLhYKbh3kiAcCgQ56dpDrDvDcLqq
vS3jg/VO+OPnZbofoHOOevt8Q/roahJe1PlIyQ4udWB8zZezJ4mLLfbOA9YVaYXx
2AHHZJevo3nmRnlgJXo6mE00E/6qkhjDHKSMdl2WG6mO9TCDZc9qY3cAJDU6Ir0v
SH7qUl8/vN13y4UOFkn8hM4kmZ6bJqbZt5NbjHtY4uQ0VMW3RyESzhrO02mrp39a
uLNnH3EXdXaV1tk75H3qC7zJaeGWMJyQfOE3YfEGRKn8fxubji716D8UecAxAzFy
FL6m1JiOyV5acAiOpxN14qRYZdHnXOM9DqGIGpoeY1UuD4Mo05osOqOUpBJHA9fS
whSZG7VNf+vgNWTLNYSYLI04KiMdulnvU6ds+QPz+KKtAgMBAAE=
-----END PUBLIC KEY-----
"""

        bob_public_key = serialization.load_pem_public_key(bob_pubkey_pem)
        der_data = decode_pem_string(bob_private_key_pem)
        bob_private_key = serialization.load_der_private_key(der_data, password=None)

        z_hex = (
            "9c126102a5c1c0354672a3c2f19fc9ddea988f815e1da812c7bd4f8eb082bdd1"
            "4f85a7f7c2f1af11d5333e0d6bcb375bf855f208da72ba27e6fb0655f2825aa6"
            "2b93b1f9bbd3491fed58f0380fa0de36430e3a144d569600bd362609be5b9481"
            "0875990b614e406fa6dff500043cbca95968faba61f795096a7fb3687a51078c"
            "4ca2cb663366b0bea0cd9cccac72a25f3f4ed03deb68b4453bba44b943f4367b"
            "67d6cd10c8ace53f545aac50968fc3c6ecc80f3224b64e37038504e2d2c0e2b2"
            "9d45e46c62826d96331360e4c17ea3ef89a9efc5fac99eda830e81450b6534dc"
            "0bdf042b8f3b706649c631fe51fc2445cc8d447203ec2f41f79cdfea16de1ce6"
            "abdfdc1e2ef2e5d5d8a65e645f397240ef5a26f5e4ff715de782e30ecf477293"
            "e89e13171405909a8e04dd31d21d0c57935fc1ceea8e1033e31e1bc8c56da0f3"
            "d79510f3f380ff58e5a61d361f2f18e99fbae5663172e8cd1f21deaddc5bbbea"
            "060d55f1842b93d1a9c888d0bf85d0af9947fe51acf940c7e7577eb79cabecb3"
        )
        z_value = int(z_hex, 16)

        expected_ct_hex = (
            "c071fc273af8e7bdb152e06bf73310361074154a43abcf3c93c13499d2065344"
            "3eed9ef5d3c0685e4aa76a6854815bb97691ff9f8dac15eea7d74f452bf350a6"
            "46163d68288e978cbf7a73089ee52712f9a4f49e06ace7bbc85ab14d4e336c97"
            "c5728a2654138c7b26e8835c6b0a9fbed26495c4eadf745a2933be283f6a88b1"
            "6695fc06666873cfb6d36718ef3376cefc100c3941f3c494944078325807a559"
            "186b95ccabf3714cfaf79f83bd30537fdd9aed5a4cdcbd8bd0486faed73e9d48"
            "6b3087d6c806546b6e2671575c98461e441f65542bd95de26d0f53a64e7848d7"
            "31d9608d053e8d345546602d86236ffe3704c98ad59144f3089e5e6d527b5497"
            "ba103c79d62e80d0235410b06f71a7d9bd1c38000f910d6312ea2f20a3557535"
            "ad01b3093fb5f7ee507080d0f77d48c9c3b3796f6b7dd3786085fb895123f04c"
            "a1f1c1be22c747a8dface32370fb0d570783e27dbb7e74fca94ee39676fde3d8"
            "a9553d878224736e37e191dab953c7e228c07ad5ca3122421c14debd072a9ab6"
        )
        expected_ct = binascii.unhexlify(expected_ct_hex)

        expected_ss_hex = "3cf82ec41b54ed4d37402bbd8f805a52"

        ss_len = 16
        actual_ss, actual_ct = _perform_rsa_kem_encapsulate(bob_public_key, z_value=z_value, ss_len=ss_len)

        self.assertEqual(
            actual_ss.hex(),
            expected_ss_hex,
        )

        decapsulated_ss = _perform_rsa_kem_decapsulation(bob_private_key, expected_ct, ss_len)
        self.assertEqual(
            decapsulated_ss.hex(),
            expected_ss_hex,
        )


if __name__ == "__main__":
    unittest.main()
