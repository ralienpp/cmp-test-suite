# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains the CA Handler for the Mock CA."""

import logging
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import ocsp

sys.path.append(".")

from cryptography import x509
from flask import Flask, Response, request
from pq_logic.hybrid_issuing import (
    build_catalyst_signed_cert_from_req,
    build_cert_discovery_cert_from_p10cr,
    build_cert_from_catalyst_request,
    build_chameleon_from_p10cr,
    build_related_cert_from_csr,
    build_sun_hybrid_cert_from_request,
)
from pq_logic.hybrid_sig import sun_lamps_hybrid_scheme_00
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import extract_sun_hybrid_alt_sig, sun_cert_template_to_cert
from pq_logic.py_verify_logic import verify_hybrid_pkimessage_protection
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480
from resources.ca_ra_utils import (
    build_cp_cmp_message,
    build_cp_from_p10cr,
    build_ip_cmp_message,
    build_pki_conf_from_cert_conf,
    build_rp_from_rr,
)
from resources.certbuildutils import (
    build_certificate,
    prepare_cert_template,
    prepare_crl_distribution_point_extension,
    prepare_ocsp_extension,
)
from resources.certutils import parse_certificate
from resources.cmputils import build_cmp_error_message, get_cert_response_from_pkimessage
from resources.exceptions import BadCertTemplate, BadMessageCheck, BadRequest, CMPTestSuiteError, TransactionIdInUse
from resources.general_msg_utils import build_genp_kem_ct_info_from_genm
from resources.keyutils import generate_key, load_private_key_from_file
from resources.protectionutils import (
    get_protection_type_from_pkimessage,
    protect_pkimessage,
    verify_pkimessage_protection,
)
from resources.typingutils import PrivateKey, PublicKey
from resources.utils import load_and_decode_pem_file

from mock_ca.mock_fun import CertRevStateDB


@dataclass
class SunHybridState:
    """A simple class to store the state of the SunHybridHandler."""

    sun_hybrid_certs: Dict[int, rfc9480.CMPCertificate] = field(default_factory=dict)
    sun_hybrid_pub_keys: Dict[int, PublicKey] = field(default_factory=dict)
    sun_hybrid_signatures: Dict[int, bytes] = field(default_factory=dict)


@dataclass
class MockCAState:
    """A simple class to store the state of the MockCAHandler.

    Attributes:
        currently_used_ids: The currently used IDs.
        issued_certs: The issued certificates.
        kem_mac_based: The KEM-MAC-based shared secrets.
        to_be_confirmed_certs: The certificates to be confirmed.

    """

    cert_state_db: CertRevStateDB = field(default_factory=CertRevStateDB)
    currently_used_ids: Set[bytes] = field(default_factory=set)
    issued_certs: List[rfc9480.CMPCertificate] = field(default_factory=list)
    # stores the transaction id mapped to the shared secret.
    kem_mac_based: Dict[bytes, bytes] = field(default_factory=dict)
    # stores the (txid, sender_raw) mapped to the certificate.
    to_be_confirmed_certs: Dict[Tuple[bytes, bytes], List[rfc9480.CMPCertificate]] = field(default_factory=dict)
    challenge_rand_int: Dict[bytes, int] = field(default_factory=dict)
    sun_hybrid_state: SunHybridState = field(default_factory=SunHybridState)

    def store_transaction_certificate(self, pki_message, certs: List[rfc9480.CMPCertificate]) -> None:
        """Store a transaction certificate.

        :param pki_message: The PKIMessage request.
        :param certs: A list of certificates to store.
        :raises TransactionIdInUse: If the transaction ID is already in use.
        """
        transaction_id = pki_message["header"]["transactionID"].asOctets()
        sender = pki_message["header"]["sender"]

        if transaction_id in self.currently_used_ids:
            raise TransactionIdInUse(f"Transaction ID {transaction_id.hex()} already exists for sender {sender}")

        der_sender = encoder.encode(sender)
        self.to_be_confirmed_certs[(transaction_id, der_sender)] = certs
        self.currently_used_ids.add(transaction_id)

    def add_kem_mac_shared_secret(self, pki_message: rfc9480.PKIMessage, shared_secret: bytes) -> None:
        """Add the shared secret for the KEM-MAC-based protection.

        :param pki_message: The PKIMessage request.
        :param shared_secret: The shared secret.
        """
        transaction_id = pki_message["header"]["transactionID"].asOctets()
        self.kem_mac_based[transaction_id] = shared_secret

    def get_kem_mac_shared_secret(self, pki_message: rfc9480.PKIMessage) -> Optional[bytes]:
        """Retrieve the shared secret for the KEM-MAC-based protection.

        :param pki_message: The PKI message containing the request.
        :return: The shared secret.
        """
        transaction_id = pki_message["header"]["transactionID"].asOctets()
        return self.kem_mac_based.get(transaction_id)

    def get_issued_certs(self, pki_message: rfc9480.PKIMessage) -> List[rfc9480.CMPCertificate]:
        """Retrieve the issued certificates.

        :param pki_message: The PKI message containing the request.
        :return: The issued certificates.
        """
        transaction_id = pki_message["header"]["transactionID"].asOctets()
        der_sender = encoder.encode(pki_message["header"]["sender"])
        return self.to_be_confirmed_certs[(transaction_id, der_sender)]

    def get_cert_by_serial_number(self, serial_number: int) -> rfc9480.CMPCertificate:
        """Get the Sun-Hybrid certificate for the specified serial number.

        :param serial_number: The serial number of the certificate.
        :return: The certificate.
        :raises BadRequest: If the certificate could not be found.
        """
        for cert in self.issued_certs:
            if serial_number == int(cert["tbsCertificate"]["serialNumber"]):
                return cert

        raise BadRequest(f"Could not find certificate with serial number {serial_number}")

    def add_certs(self, certs: List[rfc9480.CMPCertificate]) -> None:
        """Add the issued certificates to the state.

        :param certs: The certificates to add.
        """
        self.issued_certs.extend(certs)

    def check_request_for_compromised_key(self, request: rfc9480.PKIMessage) -> bool:
        """Check the request for a compromised key."""
        return self.cert_state_db.check_request_for_compromised_key(request)


def _build_error_from_exception(e: CMPTestSuiteError) -> rfc9480.PKIMessage:
    """Build an error response from an exception.

    :param e: The exception.
    :return: The error response, as raw bytes.
    """
    msg = build_cmp_error_message(failinfo=e.failinfo, texts=e.message, status="rejection", error_texts=e.error_details)
    return msg


class CAHandler:
    """A simple class to handle the CA operations."""

    def __init__(
        self,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: PrivateKey,
        config: dict,
        ca_alt_key: Optional[PrivateKey] = None,
        state: Optional[MockCAState] = None,
        port: int = 5000,
    ):
        """Initialize the CA Handler.

        :param config: The configuration for the CA Handler.
        """
        self.ocsp_extn = prepare_ocsp_extension(ocsp_url=f"http://localhost:{port}/ocsp")
        self.crl_extn = prepare_crl_distribution_point_extension(crl_url=f"http://localhost:{port}/crl")
        self.comp_key = generate_key("composite-sig")
        self.comp_cert = build_certificate(private_key=self.comp_key, is_ca=True, common_name="CN=Test CA")[0]
        self.config = config
        self.sun_hybrid_key = generate_key("composite-sig")
        cert_template = prepare_cert_template(
            self.sun_hybrid_key,
            subject="CN=Hans the Tester",
        )
        self.sun_hybrid_cert, cert1 = sun_cert_template_to_cert(
            cert_template=cert_template,
            ca_cert=ca_cert,
            ca_key=self.sun_hybrid_key.trad_key,
            alt_private_key=self.sun_hybrid_key.pq_key,
            pub_key_loc=f"http://localhost:{port}/pubkey/1",
            sig_loc=f"http://localhost:{port}/sig/1",
            serial_number=1,
            extensions=[self.ocsp_extn, self.crl_extn],
        )

        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.ca_alt_key = ca_alt_key
        self.state = state or MockCAState()
        self.shared_secrets = b"SiemensIT"
        self.cert_chain = [self.ca_cert, self.comp_cert, self.sun_hybrid_cert, cert1]

        alt_sig = extract_sun_hybrid_alt_sig(cert1)
        self.state.sun_hybrid_state.sun_hybrid_certs[1] = self.sun_hybrid_cert
        self.state.sun_hybrid_state.sun_hybrid_pub_keys[1] = self.sun_hybrid_key.pq_key.public_key()
        self.state.sun_hybrid_state.sun_hybrid_signatures[1] = alt_sig

        if config.get("hybrid_kem_path"):
            self.hybrid_kem = load_private_key_from_file(config["hybrid_kem_path"])

            if config.get("hybrid_cert_path"):
                self.hybrid_cert = parse_certificate(load_and_decode_pem_file(config["hybrid_cert_path"]))
            else:
                self.hybrid_cert, _ = build_certificate(
                    private_key=self.hybrid_kem,
                    hash_alg="sha256",
                    is_ca=True,
                    common_name="CN=Hans the Tester",
                )

        else:
            self.xwing_cert = parse_certificate(load_and_decode_pem_file("data/unittest/hybrid_cert_xwing.pem"))
            self.xwing_key = load_private_key_from_file("data/keys/private-key-xwing.pem")

    def sign_response(
        self,
        response: rfc9480.PKIMessage,
        request_msg: rfc9480.PKIMessage,
        secondary_cert: Optional[rfc9480.CMPCertificate] = None,
    ) -> rfc9480.PKIMessage:
        """Sign the response.

        :param response: The PKI message to sign.
        :param request_msg: The request message.
        :param secondary_cert: An optional secondary certificate to include in the response. Defaults to `None`.
        :return: The signed PKI message.
        """
        if get_protection_type_from_pkimessage(request_msg) == "mac":
            pki_message = protect_pkimessage(
                pki_message=response,
                password=self.shared_secrets,
                protection="password_based_mac",
            )
            if secondary_cert:
                pki_message["extraCerts"].append(secondary_cert)
            pki_message["extraCerts"].extend(self.cert_chain)
            return pki_message

        protected = protect_pkimessage(
            pki_message=response,
            private_key=self.ca_key,
            protection="signature",
            cert=self.ca_cert,
            exclude_cert=True,
        )
        protected["extraCerts"].append(self.ca_cert)
        if secondary_cert:
            protected["extraCerts"].append(secondary_cert)

        if len(self.cert_chain) > 1:
            protected["extraCerts"].extend(self.cert_chain[1:])
        return protected

    def process_normal_request(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the normal request.

        :return: The PKI message containing the response.
        """
        logging.debug("Processing request with body: %s", pki_message["body"].getName())
        try:
            if pki_message["body"].getName() == "rr":
                response = self.process_rr(pki_message)
            elif pki_message["body"].getName() == "certConf":
                response = self.process_cert_conf(pki_message)
            elif pki_message["body"].getName() == "kur":
                response = self.process_kur(pki_message)
            elif pki_message["body"].getName() == "genm":
                response = self.process_genm(pki_message)
            elif pki_message["body"].getName() == "cr":
                response = self.process_cr(pki_message)
            elif pki_message["body"].getName() == "ir":
                response = self.process_ir(pki_message)
            elif pki_message["body"].getName() == "p10cr":
                response = self.process_p10cr(pki_message)
            else:
                raise NotImplementedError(
                    f"Method not implemented, to handle the provided message: {pki_message['body'].getName()}."
                )
        except CMPTestSuiteError as e:
            return _build_error_from_exception(e)
        except Exception as e:
            return _build_error_from_exception(
                CMPTestSuiteError(f"An error occurred: {str(e)}", failinfo="systemFailure")
            )

        return self.sign_response(response=response, request_msg=pki_message)

    def process_genm(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the GenM message.

        :param pki_message: The GenM message.
        :return: The PKI message containing the response.
        """
        ss, genp = build_genp_kem_ct_info_from_genm(
            genm=pki_message,  # type: ignore
        )
        self.state.add_kem_mac_shared_secret(pki_message=pki_message, shared_secret=ss)
        return genp  # type: ignore

    def process_rr(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the RR message.

        :param pki_message: The RR message.
        :return: The PKI message containing the response.
        """
        pki_message, data = build_rp_from_rr(
            request=pki_message,
            shared_secret=self.state.get_kem_mac_shared_secret(pki_message=pki_message),
            certs=self.state.issued_certs,
        )
        self.state.cert_state_db.add_rev_entry(data)

        return pki_message

    def process_kur(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the KUR message.

        :param pki_message: The KUR message.
        :return: The PKI message containing the response.
        """
        verify_pkimessage_protection(
            pki_message=pki_message,
            shared_secret=self.state.get_kem_mac_shared_secret(pki_message=pki_message),
            private_key=self.xwing_key,
            password=self.shared_secrets,
        )
        # self.state.cert_state_db.add_update_entry(entries)

        raise NotImplementedError("Method not implemented, to return a `rp` message,but the protection was correct.")

    def process_cert_conf(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the CertConf message.

        :param pki_message: The CertConf message.
        :return: The PKIMessage containing the response.
        """
        issued_certs = self.state.get_issued_certs(pki_message=pki_message)
        pki_message = build_pki_conf_from_cert_conf(
            pki_message=pki_message,
            issued_certs=issued_certs,
        )
        self.state.add_certs(certs=issued_certs)
        return pki_message

    def _check_for_compromised_key(self, pki_message: rfc9480.PKIMessage) -> None:
        """Check the request for a compromised key.

        :param pki_message: The PKIMessage request.
        :raises BadCertTemplate: If the certificate template is invalid.
        """
        result = self.state.cert_state_db.check_request_for_compromised_key(pki_message)
        if result:
            raise BadCertTemplate("The certificate template contained a compromised key.")

    def process_p10cr(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the P10CR message.

        :param pki_message: The client request.
        :return: The CA response.
        """
        pki_message, cert = build_cp_from_p10cr(
            request=pki_message,
            set_header_fields=True,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
            implicit_confirm=True,
        )
        self.state.store_transaction_certificate(
            transaction_id=pki_message["header"]["transactionID"].asOctets(),
            sender=pki_message["header"]["sender"],
            certs=[cert],
        )
        return pki_message

    def process_cr(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the CR message.

        :param pki_message: The client request.
        :return: The CA response.
        """
        pki_message, certs = build_cp_cmp_message(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            implicit_confirm=True,
        )
        self.state.store_transaction_certificate(
            transaction_id=pki_message["header"]["transactionID"].asOctets(),
            sender=pki_message["header"]["sender"],
            certs=certs,
        )
        return pki_message

    def process_ir(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the IR message.

        :param pki_message: The IR message.
        :return: The PKI message containing the response.
        """
        logging.debug("Processing IR message")
        logging.debug("CA Key: %s", self.ca_key)

        if not pki_message["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("Protection algorithm was not set.")

        response, certs = build_ip_cmp_message(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            implicit_confirm=True,
            extensions=[self.ocsp_extn, self.crl_extn],
        )
        logging.debug("RESPONSE: %s", pki_message.prettyPrint())
        self.state.store_transaction_certificate(
            pki_message=pki_message,
            certs=certs,
        )
        return response

    def process_chameleon(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the Chameleon message.

        :param pki_message: The Chameleon message.
        :return: The PKI message containing the response.
        """
        if pki_message["body"].getName() == "p10cr":
            response, paired_cert, delta_cert = build_chameleon_from_p10cr(
                request=pki_message,
                ca_cert=self.ca_cert,
                ca_key=self.ca_key,
                extensions=[self.ocsp_extn, self.crl_extn],
            )
            self.state.store_transaction_certificate(
                pki_message=pki_message,
                certs=[paired_cert, delta_cert],
            )
            return response

        raise NotImplementedError(
            f"Not implemented to handle a chameleon request with body: {pki_message['body'].getName()}"
        )

    def process_sun_hybrid(
        self,
        pki_message: rfc9480.PKIMessage,
        bad_alt_sig: bool = False,
    ) -> rfc9480.PKIMessage:
        """Process the Sun Hybrid message.

        :param pki_message: The Sun Hybrid message.
        :param bad_alt_sig: If `True`, the alternative signature will be invalid.
        :return: The PKI message containing the response.
        """
        if pki_message["body"].getName() == "certConf":
            return self.process_cert_conf(pki_message)

        for _ in range(100):
            serial_number = x509.random_serial_number()
            if serial_number not in self.state.sun_hybrid_state.sun_hybrid_certs:
                break

        response, cert4, cert1 = build_sun_hybrid_cert_from_request(
            request=pki_message,
            ca_key=self.sun_hybrid_key,
            serial_number=serial_number,
            ca_cert=self.ca_cert,
            pub_key_loc=f"http://localhost:5000/pubkey/{serial_number}",
            sig_loc=f"http://localhost:5000/sig/{serial_number}",
            extensions=[self.ocsp_extn, self.crl_extn],
            bad_alt_sig=bad_alt_sig,
        )

        result = True  # _is_encrypted_cert(response)
        if not result:
            self.state.store_transaction_certificate(
                pki_message=pki_message,
                certs=[cert4],
            )
            return self.sign_response(response=response, request_msg=pki_message)
        else:
            public_key = sun_lamps_hybrid_scheme_00.get_sun_hybrid_alt_pub_key(cert1["tbsCertificate"]["extensions"])
            alt_sig = extract_sun_hybrid_alt_sig(cert1)
            self.state.sun_hybrid_state.sun_hybrid_certs[serial_number] = cert4
            self.state.sun_hybrid_state.sun_hybrid_pub_keys[serial_number] = public_key
            self.state.sun_hybrid_state.sun_hybrid_signatures[serial_number] = alt_sig

            self.state.add_certs(certs=[cert4])

        return self.sign_response(
            response=response,
            request_msg=pki_message,
            secondary_cert=cert1,
        )

    def process_multi_auth(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the Multi-Auth message.

        :param pki_message: The PKIMessage which is hybrid protected.
        :return:
        """
        verify_hybrid_pkimessage_protection(
            pki_message=pki_message,
        )
        return self.process_normal_request(pki_message)

    def process_cert_discovery(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the Cert Discovery request message.

        :param pki_message: The Cert Discovery message.
        :return: The PKI message containing the response.
        """
        if pki_message["body"].getName() != "p10cr":
            raise NotImplementedError("Only support p10cr for cert discovery requests.")

        serial_number = None
        for _ in range(100):
            serial_number = x509.random_serial_number()
            if serial_number not in self.state.sun_hybrid_state.sun_hybrid_certs:
                break
            serial_number = None

        if serial_number is None:
            raise Exception("Could not generate a unique serial number.")

        pki_message = build_cert_discovery_cert_from_p10cr(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            serial_number=serial_number,
            url=f"http://127.0.0.1:5000/cert/{serial_number}",
            load_chain=False,
        )
        return self.sign_response(response=pki_message, request_msg=pki_message)

    def process_related_cert(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the Related Cert request message.

        :param pki_message: The Related Cert message.
        :return: The PKI message containing the response.
        """
        if pki_message["body"].getName() != "p10cr":
            raise NotImplementedError("Only support p10cr for related cert requests.")

        pki_message = build_related_cert_from_csr(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )
        return self.sign_response(response=pki_message, request_msg=pki_message)

    def process_catalyst_sig(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the Catalyst Sig request message.

        :param pki_message: The Catalyst Sig message.
        :return: The PKI message containing the response.
        """
        pki_message = build_catalyst_signed_cert_from_req(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )
        return self.sign_response(response=pki_message, request_msg=pki_message)

    def process_catalyst_issuing(self, pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
        """Process the Catalyst request message.

        :param pki_message: The Catalyst message.
        :return: The PKI message containing the response.
        """
        pki_message = build_cert_from_catalyst_request(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )
        return self.sign_response(response=pki_message, request_msg=pki_message)


app = Flask(__name__)
state = MockCAState()

ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

handler = CAHandler(ca_cert=ca_cert, ca_key=ca_key, config={})
handler.state = state


@app.route("/cert/<serial_number>", methods=["GET"])
def get_cert(serial_number):
    """Get the Sun-Hybrid certificate for the specified serial number."""
    serial_number = int(serial_number)
    sun_hybrid_cert = state.get_cert_by_serial_number(serial_number)
    return encoder.encode(sun_hybrid_cert)


@app.route("/pubkey/<serial_number>", methods=["GET"])
def get_pubkey(serial_number):
    """Get the Sun-Hybrid public key for the specified serial number."""
    serial_number = int(serial_number)
    sun_hybrid_cert = state.sun_hybrid_state.sun_hybrid_pub_keys[serial_number]
    return encoder.encode(sun_hybrid_cert)


@app.route("/sig/<serial_number>", methods=["GET"])
def get_signature(serial_number):
    """Get the Sun-Hybrid signature for the specified serial number."""
    serial_number = int(serial_number)
    alt_sig = state.sun_hybrid_state.sun_hybrid_signatures[serial_number]
    return alt_sig


@app.route("/issuing", methods=["POST"])
def handle_issuing() -> Response:
    """Handle the issuing request.

    :return: The DER-encoded response.
    """
    try:
        # Access the raw data from the request body
        data = request.get_data()
        pki_message, _ = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
        pki_message = handler.process_normal_request(pki_message)
        logging.warning("Response: %s", pki_message.prettyPrint())
        response_data = encoder.encode(pki_message)
        return Response(response_data, content_type="application/octet-stream")
    except Exception as e:
        # Handle any errors gracefully
        return Response(f"Error: {str(e)}", status=500, content_type="text/plain")


@app.route("/chameleon", methods=["POST"])
def handle_chameleon():
    """Handle the chameleon request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message, _ = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
    pki_message = handler.process_normal_request(pki_message)
    return handler.process_chameleon(
        pki_message=pki_message,
    )


@app.route("/sun_hybrid", methods=["POST"])
def handle_sun_hybrid():
    """Handle the Sun Hybrid request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message, _ = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
    pki_message = handler.process_normal_request(pki_message)
    return handler.process_sun_hybrid(
        pki_message=pki_message,
    )


@app.route("/multi-auth", methods=["POST"])
def handle_multi_auth():
    """Handle the multi-auth request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message, _ = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
    pki_message = handler.process_normal_request(pki_message)
    return handler.process_multi_auth(
        pki_message=pki_message,
    )


@app.route("/cert-discovery", methods=["POST"])
def handle_cert_discovery():
    """Handle the cert discovery request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message, _ = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
    pki_message = handler.process_cert_discovery(pki_message)
    return pki_message


@app.route("/related-cert", methods=["POST"])
def handle_related_cert():
    """Handle the related cert request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message, _ = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
    pki_message = handler.process_related_cert(pki_message)
    return pki_message


@app.route("/catalyst-sig", methods=["POST"])
def handle_catalyst_sig():
    """Handle the catalyst sig request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message, _ = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
    pki_message = handler.process_catalyst_sig(pki_message)
    return pki_message


@app.route("/catalyst-issuing", methods=["POST"])
def handle_catalyst():
    """Handle the catalyst request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message, _ = decoder.decode(data, asn1Spec=rfc9480.PKIMessage())
    pki_message = handler.process_catalyst_issuing(pki_message)
    return pki_message


if __name__ == "__main__":
    app.run(port=5000, debug=True)
