import sys
from typing import Optional


sys.path.append(".")

from resources.typingutils import PrivateKey

from pq_logic.hybrid_sig.chameleon_logic import build_paired_csrs, build_chameleon_cert_from_paired_csr
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import sun_csr_to_cert
from unit_tests.pq_workflow_exp import build_sun_hybrid_composite_csr
from pq_logic.hybrid_sig.cert_binding_for_multi_auth import build_related_cert_from


from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480

from resources.certbuildutils import generate_certificate, build_csr
from resources.keyutils import generate_key
from tabulate import tabulate


def _get_cert_length(cert: rfc9480.CMPCertificate) -> int:
    """Get the length of the certificate.

    :param cert: The certificate to get the length of.
    :return: The length of the certificate.
    """
    return len(encoder.encode(cert))


def build_example_paired_chameleon(
    ca_key: Optional[PrivateKey] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
):
    """Build a certificate with the size of the key."""

    ca_key = ca_key or generate_key("rsa", length=2048)
    ca_cert = ca_cert = generate_certificate(ca_key, common_name="CN=CA RSA2048", ski=True)

    cm = "CN=Hans the Tester"

    # RSA
    rsa_key = generate_key("rsa", length=2048)
    mldsa_key = generate_key("ml-dsa-44")
    csrs = build_paired_csrs(rsa_key, mldsa_key, cm)
    paired_cert, delta = build_chameleon_cert_from_paired_csr(csrs, ca_key=ca_key, ca_cert=ca_cert)
    entry = {
        "Name:": f"Chameleon Cert RSA2048:{mldsa_key.name.upper()}",
        "Cert. Size (bytes)": _get_cert_length(paired_cert),
        "Extra Info": f"Delta Size: {_get_cert_length(delta)}",
    }
    return entry


def build_example_sun_hybrid():
    """Build a certificate with the size of the key."""

    signing_key = generate_key("composite-sig", trad_key=generate_key("rsa", length=2048))
    comp_key = generate_key("composite-sig", trad_key=generate_key("rsa", length=2048))

    issuer_cert = generate_certificate(signing_key, common_name="CN=CA RSA2048", ski=True)

    hash_alg = "sha256"
    csr = build_sun_hybrid_composite_csr(
        signing_key=comp_key,
        common_name="CN=Hans the Tester",
        pub_key_hash_alg=hash_alg,
        pub_key_location="https://example.com/pubkey",
        sig_hash_alg=hash_alg,
        sig_value_location="https://example.com/sig",
    )
    from4, form1 = sun_csr_to_cert(
        csr=csr,
        issuer_private_key=signing_key.trad_key,
        alt_private_key=signing_key.pq_key,
        issuer_cert=issuer_cert,
    )

    entry = {
        "Name:": f"Sun Hybrid Cert Form 4: {comp_key.name}",
        "Cert. Size (bytes)": _get_cert_length(from4),
        "Extra Info": f"hash_alg={hash_alg}",
    }

    return entry


def build_related_cert(
    ca_key: PrivateKey, ca_cert: rfc9480.CMPCertificate, cert: Optional[rfc9480.CMPCertificate] = None
):
    """Build a certificate with the size of the key."""

    cm = "CN=Hans the Tester"

    if cert is not None:
        rsa_key = generate_key("rsa", length=2048)
        cert = generate_certificate(rsa_key, common_name=cm, ski=True)

    singing_key = generate_key("ml-dsa-44")

    csr = build_csr(
        common_name=cm,
        signing_key=singing_key,
    )

    cert = build_related_cert_from(
        csr=csr,
        related_cert=cert,
        ca_key=ca_key,
        ca_cert=ca_cert,
    )

    entry = {
        "Name:": f"Related Cert: {singing_key.name}",
        "Cert. Size (bytes)": _get_cert_length(cert),
        "Extra Info": "hash_alg=sha256",
    }

    return entry


def build_build_sig_cert_size():
    """Build a certificate with the size of the key."""

    ca_key = generate_key("rsa", length=2048)
    ca_cert = generate_certificate(ca_key, common_name="CN=CA RSA2048", ski=True)

    cm = "CN=Hans the Tester"

    data = []
    # RSA
    rsa_key = generate_key("rsa", length=2048)
    rsa_cert = generate_certificate(rsa_key, common_name=cm, ski=True)
    entry = {"Name:": "rsa2048", "Cert. Size (bytes)": _get_cert_length(rsa_cert)}
    data.append(entry)

    # ECDSA
    ecdsa_key = generate_key("ecdsa", curve="secp256r1")
    cert = generate_certificate(ecdsa_key, common_name=cm, ski=True)
    entry = {"Name:": f"ec-{ecdsa_key.curve.name}", "Cert. Size (bytes)": _get_cert_length(cert)}
    data.append(entry)

    # ML-DSA
    mldsa_key = generate_key("ml-dsa-44")
    cert = generate_certificate(mldsa_key, common_name=cm, ski=True)
    entry = {"Name:": mldsa_key.name, "Cert. Size (bytes)": _get_cert_length(cert)}
    data.append(entry)

    # SLH-DSA
    slh_dsa_key = generate_key("slh-dsa-sha2-128s")
    cert = generate_certificate(slh_dsa_key, common_name=cm, ski=True)
    entry = {"Name:": slh_dsa_key.name, "Cert. Size (bytes)": _get_cert_length(cert)}
    data.append(entry)

    # Composite-Sig + RSA
    rsa_key = generate_key("rsa", length=2048)
    comp_key = generate_key("composite-sig", trad_key=rsa_key)
    cert = generate_certificate(comp_key, common_name=cm, ski=True)
    entry = {"Name:": comp_key.name, "Cert. Size (bytes)": _get_cert_length(cert)}
    data.append(entry)

    # Composite-Sig + ECDSA
    ecdsa_key = generate_key("ecdsa", curve="secp256r1")
    comp_key = generate_key("composite-sig", trad_key=ecdsa_key)
    cert = generate_certificate(comp_key, common_name=cm, ski=True)
    entry = {"Name:": comp_key.name, "Cert. Size (bytes)": _get_cert_length(cert)}
    data.append(entry)

    data.append(build_example_paired_chameleon(ca_key=ca_key, ca_cert=ca_cert))
    data.append(build_example_sun_hybrid())
    data.append(build_related_cert(ca_key=ca_key, ca_cert=ca_cert, cert=rsa_cert))

    table = tabulate(data, headers="keys", tablefmt="fancy_grid")

    print(table)


build_build_sig_cert_size()
