# Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: 2024 SPDX-FileCopyrightText:
#
# SPDX-License-Identifier: Apache-2.0

"""Type aliases to enhance code readability, maintainability, and type safety.

Type aliases are used to create descriptive names for commonly used types, making the codebase
easier to understand and work with.
"""

from typing import Optional, Sequence, Union

from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pq_logic.keys.abstract_pq import (
    PQSignaturePrivateKey,
    PQSignaturePublicKey,
)
from pq_logic.keys.abstract_wrapper_keys import (
    HybridSigPrivateKey,
    HybridSigPublicKey,
    KEMPrivateKey,
    KEMPublicKey,
    WrapperPrivateKey,
    WrapperPublicKey,
)
from pq_logic.keys.stateful_hash_sig import PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey
from pyasn1_alt_modules import rfc5280, rfc5652, rfc9480, rfc9629

ECSignKey = Union[
    Ed25519PrivateKey,
    Ed448PrivateKey,
    EllipticCurvePrivateKey,
]

TradSignKey = Union[
    RSAPrivateKey,
    ECSignKey,
    DSAPrivateKey,
]

ECVerifyKey = Union[
    Ed25519PublicKey,
    Ed448PublicKey,
    EllipticCurvePublicKey,
]
TradVerifyKey = Union[
    RSAPublicKey,
    ECVerifyKey,
    DSAPublicKey,
]

# Type alias for supported private key types
PrivateKey = Union[TradSignKey, DHPrivateKey, X25519PrivateKey, X448PrivateKey, WrapperPrivateKey]


# Type alias for supported public key types
PublicKey = Union[TradVerifyKey, DHPublicKey, X25519PublicKey, X448PublicKey, WrapperPublicKey]


# Keys which can be used for signing and verification of a signature.
# They are used to ensure that only authorized keys are used for signing.
SignKey = Union[
    TradSignKey,
    PQSignaturePrivateKey,
    PQHashStatefulSigPrivateKey,
    HybridSigPrivateKey,
]
VerifyKey = Union[
    TradVerifyKey,
    PQSignaturePublicKey,
    PQHashStatefulSigPublicKey,
    HybridSigPublicKey,
]

# These `cryptography` keys can be used to sign a certificate.
# For signature protection, a certificate is required in the
# first position of the `pyasn1 rfc9480.PKIMessage` `extraCerts` field.
# To ensure the correct keys are used, this type is introduced.
PrivSignCertKey = Union[TradSignKey, PQSignaturePrivateKey, HybridSigPrivateKey]

# This is a "stringified integer", to make it easier to pass numeric data
# to RobotFramework keywords. Normally, if you want
# to pass an integer, you have to write it as `${45}` - which hinders readability.
# With a stringified integer, we provide
# some syntactic sugar, enabling both notations: `${45}` and `45`.
Strint = Union[str, int]

# At different stages of RobotFramework tests we deal with
# certificates in forms, e.g., pyasn1 structures, or filepaths. This type
# is used in functions that can accept either of these formats
# and will transform them internally, as required.
CertObjOrPath = Union[rfc9480.CMPCertificate, str]


# The `ECDHPrivKeyTypes` includes all private key types supported
# for ECDH operations. This type ensures that only compatible
# private keys are used in ECDH-related operations.
# Used in Key Generation Authority logic to make sure the key agreement
# used the correct type.
ECDHPrivKeyTypes = Union[EllipticCurvePrivateKey, X25519PrivateKey, X448PrivateKey]

# The `ECDHPubKeyTypes` includes all public key types supported
# for ECDH operations. This type ensures that only compatible
# public keys are used in ECDH-related operations.
# Used in Key Generation Authority logic to make sure the key agreement
# used the correct type.
ECDHPubKeyTypes = Union[EllipticCurvePublicKey, X25519PublicKey, X448PublicKey]


# The `KGAKeyTypes` includes all private key types supported
# for operations in the Key Generation Authority (KGA) logic.
# This type ensures that only compatible private keys are used
# for key exchange and key encipherment.
EnvDataPrivateKey = Union[RSAPrivateKey, ECDHPrivKeyTypes, KEMPrivateKey]

EnvDataPublicKey = Union[RSAPublicKey, ECDHPubKeyTypes, KEMPublicKey]
CertOrCerts = Union[rfc9480.CMPCertificate, Sequence[rfc9480.CMPCertificate]]

# Often can either an utf-8 string or a hey string or a bytes object be used,
# to parse a shared secret or a key.
OptSecret = Optional[Union[str, bytes]]

# All recipient info types supported by the CMP protocol.
# This type is used to ensure that all recipient info types are handled correctly
# in CMP-related operations.
RecipInfo = Union[
    rfc5652.RecipientInfo,
    rfc5652.KeyTransRecipientInfo,
    rfc5652.KeyAgreeRecipientInfo,
    rfc5652.PasswordRecipientInfo,
    rfc9629.KEMRecipientInfo,
    rfc5652.OtherRecipientInfo,
]

ControlsType = Union[
    rfc9480.Controls,
    Sequence[rfc9480.AttributeTypeAndValue],
    rfc9480.AttributeTypeAndValue,
]

ExtensionsType = Union[
    rfc9480.Extensions,
    Sequence[rfc5280.Extension],
    rfc5280.Extension,
]
