# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Defines the keys-typings for newly created wrapper keys."""

from typing import Iterable, Union

from pyasn1_alt_modules import rfc9480
from resources.typingutils import PrivateKeySig, PublicKeySig

from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey, PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey, HybridKEMPublicKey, HybridPublicKey
from pq_logic.keys.composite_sig import CompositeSigCMSPrivateKey, CompositeSigCMSPublicKey
from pq_logic.keys.trad_keys import RSADecapKey, RSAEncapKey

KEMPrivateKey = Union[PQKEMPrivateKey, HybridKEMPrivateKey, RSADecapKey]
KEMPublicKey = Union[PQKEMPublicKey, HybridKEMPublicKey, RSAEncapKey]

HybridPublicKey = HybridPublicKey

CertOrCerts = Union[rfc9480.CMPCertificate, Iterable[rfc9480.CMPCertificate]]

# Type for all keys which are allowed to verify signatures.
VerifyKey = Union[PQSignaturePublicKey, PublicKeySig, CompositeSigCMSPublicKey]

# Type for all keys which are allowed to sign data.
SignKey = Union[PrivateKeySig, CompositeSigCMSPrivateKey, PQSignaturePrivateKey]
