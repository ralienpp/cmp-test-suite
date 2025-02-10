from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Union

from cryptography import x509
from cryptography.x509 import CertificateRevocationList, ocsp
from pq_logic.migration_typing import HybridPublicKey
from pyasn1_alt_modules import rfc5280, rfc9480
from resources import ca_ra_utils, certutils, keyutils
from resources.copyasn1utils import copy_subject_public_key_info
from resources.oid_mapping import hash_name_to_instance
from resources.typingutils import PrivateKeySig, PublicKey
from unit_tests.utils_for_test import convert_to_crypto_lib_cert


@dataclass
class RevokedEntry:
    """A revoked entry containing the reason and the certificate."""

    reason: str
    cert: rfc9480.CMPCertificate


@dataclass
class RevokedEntryList:
    """A list of revoked entries."""

    entries: List[RevokedEntry] = field(default_factory=list)

    def __post_init__(self):
        """Convert the entries to RevokedEntry instances."""
        data = []
        for entry in self.entries:
            if isinstance(entry, dict):
                data.append(RevokedEntry(**entry))
            else:
                data.append(entry)

        self.entries = data

    def get_cert_by_serial_number(self, serial_number: int) -> Optional[rfc9480.CMPCertificate]:
        """Return the certificate with the given serial number."""
        for entry in self.entries:
            if int(entry.cert["tbsCertificate"]["serialNumber"]) == serial_number:
                return entry.cert
        return None

    @property
    def serial_numbers(self) -> List[int]:
        """Return the serial numbers of the revoked certificates."""
        return [int(entry.cert["tbsCertificate"]["serialNumber"]) for entry in self.entries]

    @property
    def certs(self) -> List[rfc9480.CMPCertificate]:
        """Return the certificates."""
        return [entry.cert for entry in self.entries]

    def add_entry(self, entry: Union[RevokedEntry, dict, List[dict]]) -> None:
        """Add a revoked entry to the list."""
        if isinstance(entry, dict):
            entry = [RevokedEntry(**entry)]
        elif isinstance(entry, list):
            entry = [RevokedEntry(**entry) for entry in entry]
        else:
            entry = [entry]

        self.entries.extend(entry)

    @property
    def compromised_keys(self) -> List[PublicKey]:
        """Return the compromised keys."""
        data = []
        for entry in self.entries:
            public_key = keyutils.load_public_key_from_spki(entry.cert["tbsCertificate"]["subjectPublicKeyInfo"])

            if isinstance(public_key, HybridPublicKey):
                data.append(public_key.pq_key)
                data.append(public_key.trad_key)
                data.append(public_key)
            else:
                data.append(public_key)
        return data

    def _contains(self, key: Union[PublicKey, HybridPublicKey]) -> bool:
        """Check if the key is in the list of compromised keys."""
        if isinstance(key, HybridPublicKey):
            return (
                key.pq_key in self.compromised_keys
                or key.trad_key in self.compromised_keys
                or key in self.compromised_keys
            )
        return key in self.compromised_keys

    def contains_key(
        self, structure_or_key: Union[PublicKey, HybridPublicKey, rfc9480.CMPCertificate, rfc9480.CertTemplate]
    ) -> bool:
        """Check if the key is in the list of compromised keys.

        :param structure_or_key: The key to check or a certificate or certificate template.
        """
        if isinstance(structure_or_key, HybridPublicKey):
            return self._contains(structure_or_key)
        elif isinstance(structure_or_key, PublicKey):
            return self._contains(structure_or_key)

        elif isinstance(structure_or_key, rfc9480.CMPCertificate):
            public_key = keyutils.load_public_key_from_spki(structure_or_key["tbsCertificate"]["subjectPublicKeyInfo"])
            return self._contains(public_key)
        elif isinstance(structure_or_key, rfc9480.CertTemplate):
            spki = copy_subject_public_key_info(
                filled_sub_pubkey_info=structure_or_key["publicKey"],
                target=rfc5280.SubjectPublicKeyInfo(),
            )
            public_key = keyutils.load_public_key_from_spki(spki)
            return self._contains(public_key)
        else:
            raise ValueError(f"Unsupported key type: {type(structure_or_key).__name__}")


@dataclass
class CertRevStateDB:
    """The certificate revocation state database."""

    rev_entry_list: RevokedEntryList = field(default_factory=RevokedEntryList)
    update_entry_list: RevokedEntryList = field(default_factory=RevokedEntryList)
    _update_eq_rev: bool = True

    def get_ocsp_response(
        self,
        request: ocsp.OCSPRequest,
        sign_key: PrivateKeySig,
        ca_cert: rfc9480.CMPCertificate,
        responder_cert: Optional[rfc9480.CMPCertificate] = None,
    ) -> ocsp.OCSPResponse:
        """Get the OCSP response for the request."""
        num = request.serial_number

        nums = self.rev_entry_list.serial_numbers
        nums = nums if self._update_eq_rev else nums + self.update_entry_list.serial_numbers

        if num in nums:
            status = "revoked"
        else:
            status = "good"

        return certutils.build_ocsp_response(
            cert=self.rev_entry_list.get_cert_by_serial_number(num),
            ca_cert=ca_cert,
            request=request,
            status=status,
            responder_key=sign_key,
            responder_cert=responder_cert,
        )

    def get_crl_response(
        self,
        sign_key: PrivateKeySig,
        ca_cert: rfc9480.CMPCertificate,
        hash_alg: Optional[str] = None,
    ) -> CertificateRevocationList:
        """Get the CRL response for the request.

        :param sign_key: The private key to sign the CRL.
        :param ca_cert: The CA certificate.
        :param hash_alg: The hash algorithm to use for signing.
        """
        nums = self.rev_entry_list.serial_numbers
        nums = nums if self._update_eq_rev else nums + self.update_entry_list.serial_numbers

        ca_cert = convert_to_crypto_lib_cert(ca_cert)
        builder = x509.CertificateRevocationListBuilder(issuer_name=ca_cert.subject)
        for serial_number in nums:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(serial_number).revocation_date(datetime.now()).build()
            )

        hash_inst = None
        if hash_alg is not None:
            hash_inst = hash_name_to_instance(hash_alg)
        return builder.sign(private_key=sign_key, algorithm=hash_inst)

    def add_compromised_key(self, entry: Union[dict, RevokedEntry]) -> None:
        """Add a compromised key to the list."""
        self.rev_entry_list.add_entry(entry)

    def add_rev_entry(self, entry: Union[RevokedEntry, dict, List[dict]]) -> None:
        """Add a revoked entry to the list."""
        self.rev_entry_list.add_entry(entry)

    def add_update_entry(self, entry: Union[RevokedEntry, dict, List[dict]]) -> None:
        """Add an updated entry to the list."""
        self.update_entry_list.add_entry(entry)

    def check_request_for_compromised_key(self, request: rfc9480.PKIMessage) -> bool:
        """Check if the request contains a compromised key.

        :param request: The certificate request.
        :return: Whether the request contains a compromised key.
        """
        if request["body"].getName() == "p10cr":
            public_key = keyutils.load_public_key_from_spki(
                request["body"]["p10cr"]["certificationRequestInfo"]["subjectPublicKeyInfo"]
            )
            return self.rev_entry_list.contains_key(public_key)

        body_name = request["body"].getName()

        if body_name in ["ir", "cr", "crr", "kur"]:
            for entry in request["body"][body_name]:
                public_key = ca_ra_utils.get_public_key_from_cert_req_msg(entry)
                if self.rev_entry_list.contains_key(public_key):
                    return True

        return False
