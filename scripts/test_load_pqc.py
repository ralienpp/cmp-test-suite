# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Verify the signatures of the certificates in the pqc-certificates repository."""

import argparse
import glob
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime

import resources.protectionutils

sys.path.append(".")

import cryptography
import pyasn1
from cryptography.exceptions import InvalidSignature
from pq_logic.hybrid_sig.catalyst_logic import verify_catalyst_signature
from pq_logic.hybrid_sig.chameleon_logic import build_delta_cert_from_paired_cert
from pq_logic.keys.abstract_wrapper_keys import PQPrivateKey, PQPublicKey
from pq_logic.keys.composite_sig03 import CompositeSig03PublicKey
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480
from resources.certutils import parse_certificate
from resources.exceptions import BadAlg
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import KEY_CLASS_MAPPING
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, PQ_KEM_OID_2_NAME
from unit_tests.utils_for_test import print_chain_subject_and_issuer


def get_key_name(key) -> str:
    """Return the name of the key."""
    if isinstance(key, (PQPublicKey, PQPrivateKey)):
        return key.name
    else:
        return str(KEY_CLASS_MAPPING.get(type(key).__name__, key))


def _load_chameleon_cert(pem_file: str):
    """Load a chameleon certificate."""
    with open(pem_file, "rb") as file:
        cert = parse_certificate(file.read())
        print_chain_subject_and_issuer([cert])
        delta_cert = build_delta_cert_from_paired_cert(cert)
        print_chain_subject_and_issuer([delta_cert])


def main():
    """Run the script."""
    repo_url = "https://github.com/IETF-Hackathon/pqc-certificates"
    data_dir = "./data"
    providers_dir = os.path.join(data_dir, "pqc-certificates", "providers")
    pem_files = []

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    repo_path = os.path.join(data_dir, "pqc-certificates")
    if not os.path.exists(repo_path):
        print("Cloning repository...")
        subprocess.run(["git", "clone", repo_url, repo_path], check=True)
    else:
        print("Repository already cloned.")

    if os.path.exists(providers_dir):
        for root, dirs, files in os.walk(providers_dir):
            for file in files:
                if file.startswith("artifacts_") and file.endswith(".zip"):
                    zip_path = os.path.join(root, file)
                    print(f"Found zip file: {zip_path}")

                    extract_dir = os.path.join(root, "extracted", os.path.splitext(file)[0])
                    os.makedirs(extract_dir, exist_ok=True)

                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        zip_ref.extractall(extract_dir)

                    for subdir, _, extracted_files in os.walk(extract_dir):
                        for extracted_file in extracted_files:
                            if extracted_file.endswith(".der"):
                                pem_path = os.path.join(subdir, extracted_file)
                                pem_files.append(pem_path)


def verify_cert_sig(cert: rfc9480.CMPCertificate, verify_catalyst: bool = False):
    """Verify the signature of a certificate using the appropriate algorithm.

    :param cert: The certificate (`CMPCertificate`) to be verified.
    :raises ValueError: If the algorithm OID in the certificate is unsupported or invalid.
    :raises InvalidSignature: If the signature verification fails.
    """
    alg_id = cert["tbsCertificate"]["signature"]
    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    public_key = load_public_key_from_spki(spki)

    if spki["algorithm"]["algorithm"] in PQ_KEM_OID_2_NAME:
        return public_key.name

    signature = cert["signature"].asOctets()
    data = encoder.encode(cert["tbsCertificate"])

    if PQ_KEM_OID_2_NAME.get(alg_id["algorithm"]):
        return PQ_KEM_OID_2_NAME.get(alg_id["algorithm"])

    return verify_signature_with_alg_id(public_key, alg_id, data, signature, verify_catalyst=verify_catalyst)


def verify_signature_with_alg_id(
    public_key, alg_id: rfc9480.AlgorithmIdentifier, data: bytes, signature: bytes, verify_catalyst: bool = False
):
    """Verify the provided data and signature using the given algorithm identifier.

    Supports traditional-, pq- and composite signature algorithm.

    :param public_key: The public key object used to verify the signature.
    :param alg_id: An `AlgorithmIdentifier` specifying the algorithm and any
                   associated parameters for signature verification.
    :param data: The original message or data whose signature needs verification,
                 as a byte string.
    :param signature: The digital signature to verify, as a byte string.

    :raises ValueError: If the algorithm identifier is unsupported or invalid.
    :raises InvalidSignature: If the signature does not match the provided data
                              under the given algorithm and public key.
    """
    oid = alg_id["algorithm"]

    if verify_catalyst:
        verify_catalyst_signature(cert)

    else:
        resources.protectionutils.verify_signature_with_alg_id(
            public_key=public_key, alg_id=alg_id, signature=signature, data=data
        )
        if isinstance(public_key, CompositeSig03PublicKey):
            name: str = CMS_COMPOSITE_OID_2_NAME[oid]
            use_pss = name.endswith("-pss")
            pre_hash = True if "hash-" in name else False
            return public_key.get_name(use_pss=use_pss, pre_hash=pre_hash)
        else:
            return get_key_name(public_key)


if __name__ == "__main__":
    print("Starting verification of PQC certificates.")
    pem_files = []

    parser = argparse.ArgumentParser(
        description="Verify the signatures of the certificates in the pqc-certificates repository."
    )
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing files.")
    args = parser.parse_args()

    if args.overwrite:
        print("Overwriting existing files.")
        shutil.rmtree("./data/pqc-certificates")
        main()

    elif not os.path.isdir("./data/pqc-certificates"):
        print("Cloning repository...")
        main()
    else:
        # for file in glob.iglob(f"{dir_path}/**/*.crl", recursive=True):
        for file in glob.iglob("./data/pqc-certificates/providers/**", recursive=True):
            if file.endswith(".der"):
                pem_files.append(file)

        f = open("../validation_pem_files.txt", "w", encoding="utf-8")
        f.write("Validation of PQC Certificates\n")
        f.write("# SPDX-FileCopyrightText: Copyright 2024 Siemens AG\n# # SPDX-License-Identifier: Apache-2.0\n")
        f.write(f"Last Time Verified: {datetime.now()}\n")
        f.write(f"Collected {len(pem_files)}.pem files:\n\n")
        for pem in pem_files:
            if "_pub" in pem:
                f.write(f"SKIPPING PUBLIC KEY FILE:\t{pem}\n")
                continue

            if "_priv" in pem:
                f.write(f"SKIPPING PRIVATE KEY FILE:\t{pem}\n")
                continue

            try:
                if "chameleon" in pem:
                    _load_chameleon_cert(pem)
                    f.write(f"VALID CHAMELEON CERT\t{pem}\n")

                data = open(pem, "rb").read()
                cert = parse_certificate(data)
                name = verify_cert_sig(cert, verify_catalyst=True if "catalyst" in pem else False)
                if name in PQ_KEM_OID_2_NAME.values():
                    f.write(f"VALID KEY LOAD CERT\t{name}\t{pem}\n")
                f.write(f"VALID SIGNATURE\t{name}\t{pem}\n")
            except InvalidSignature:
                f.write(f"INVALID SIGNATURE\t{pem}\n")
            except ValueError as e:
                f.write(f"ValueError\t{pem}\t{e}\n")
            except pyasn1.error.PyAsn1Error as e:
                f.write(f"PARSING ERROR\t{pem}\t{e}\n")
            except (cryptography.exceptions.UnsupportedAlgorithm, BadAlg) as e:
                f.write(f"UNSUPPORTED ALGORITHM\t{pem}\tUnable to decode.{e}\n")

        f.close()
