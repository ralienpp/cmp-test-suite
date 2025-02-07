# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Defines the keys-typings for newly created wrapper keys."""

from typing import Sequence, Union

from pyasn1_alt_modules import rfc9480
from resources.typingutils import PrivateKeySig, PublicKeySig

from pq_logic.keys.abstract_composite import (
    AbstractCompositeKEMPrivateKey,
    AbstractCompositeKEMPublicKey,
    AbstractCompositeSigPrivateKey,
    AbstractCompositeSigPublicKey,
)
from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPrivateKey, AbstractHybridRawPublicKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey, PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, CompositeSigCMSPublicKey

HybridKEMPrivateKey = Union[AbstractCompositeKEMPrivateKey, AbstractHybridRawPrivateKey]
HybridKEMPublicKey = Union[AbstractHybridRawPublicKey, AbstractCompositeKEMPublicKey]

KEMPrivateKey = Union[PQKEMPrivateKey, HybridKEMPrivateKey]
KEMPublicKey = Union[PQKEMPublicKey, HybridKEMPublicKey]

HybridSignKey = Union[AbstractCompositeSigPrivateKey]
HybridVerifyKey = Union[AbstractCompositeSigPublicKey]
CertOrCerts = Union[rfc9480.CMPCertificate, Sequence[rfc9480.CMPCertificate]]

# Type for all keys which are allowed to verify signatures.
VerifyKey = Union[PQSignaturePublicKey, PublicKeySig, CompositeSigCMSPublicKey]

# Type for all keys which are allowed to sign data.
SignKey = Union[PrivateKeySig, CompositeSigCMSPrivateKey, PQSignaturePrivateKey]
