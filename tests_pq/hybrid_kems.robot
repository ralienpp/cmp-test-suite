# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Test cases targeting hybrid KEMs.

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/certextractutils.py
Library             ../resources/checkutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/hybrid_prepare.py
Library             ../pq_logic/pq_compute_utils.py
Library             ../pq_logic/pq_validation_utils.py
Library             ../pq_logic/py_verify_logic.py


Test Tags           hybrid-kem   hybrid   kem
Suite Setup         Set Up Test Suite


*** Test Cases ***


CA MUST Issue a valid X-WING Certificate
    [Documentation]    According to draft-connolly-cfrg-xwing-kem-06, a valid IR message
    ...                is sent for an X-WING Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is X25519. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   xwing
    ${key}=    Generate Key  xwing
    ${cm}=  Get Next Common Name
    ${ir}=  Build Ir From Key    ${key}   common_name=${cm}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=     Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${ISSUING_SUFFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    xwing

CA MUST Issue A Valid Chempat sntrup761-X25519 Certificate
    [Documentation]    According to draft-josefsson-chempat-02, a valid IR message
    ...                is sent for a Chempat Certificate. The post-quantum component is sntrup761
    ...                and the traditional component is X25519. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   chempat
    ${key}=    Generate Key  chempat   pq_name=sntrup761   trad_name=x25519
    ${cm}=  Get Next Common Name
    ${ir}=  Build Ir From Key    ${key}   common_name=${cm}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=     Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${ISSUING_SUFFIX}
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    Chempat-X25519-sntrup761

CA MUST Issue A Valid Chempat X25519-mceliece348864 Certificate
    [Documentation]    According to draft-josefsson-chempat-02, a valid IR message
    ...                is sent for a Chempat Certificate. The post-quantum component is mceliece348864
    ...                and the traditional component is X25519. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   chempat
    ${response}  ${key}=   Exchange Hybrid PKIMessage    chempat    mceliece-348864    x25519
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    Chempat-X25519-mceliece348864

CA MUST Issue A Valid Chempat X25519-ML-KEM-768 Certificate
    [Documentation]    According to draft-josefsson-chempat-02, a valid IR message
    ...                is sent for a Chempat Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is X25519. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   chempat
    ${response}  ${key}=   Exchange Hybrid PKIMessage    chempat    ml-kem-768    x25519
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    Chempat-X25519-ML-KEM-768

CA MUST ISSUE A Valid Chempat X25519-FrodoKEM-976-aes Certificate
    [Documentation]    According to draft-josefsson-chempat-02, a valid IR message
    ...                is sent for a Chempat Certificate. The post-quantum component is frodokem-976-aes
    ...                and the traditional component is X25519. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   chempat
    ${response}  ${key}=   Exchange Hybrid PKIMessage    chempat    frodokem-976-aes    x25519
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    Chempat-X25519-frodokem-976-aes

CA MUST Issue A Valid Chempat P256-FrodoKEM-976-aes Certificate
    [Documentation]    According to draft-josefsson-chempat-02, a valid IR message
    ...                is sent for a Chempat Certificate. The post-quantum component is frodokem-976-aes
    ...                and the traditional component is P256. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   chempat
    ${response}  ${key}=   Exchange Hybrid PKIMessage    chempat    frodokem-976-aes  ecdh   curve=secp256r1
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    Chempat-P256-frodokem-976-aes

CA MUST Issue A Valid Composite ML-KEM-768-RSA2048 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is RSA2048. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   composite-kem   rsa
    ${response}  ${key}=   Exchange Hybrid PKIMessage    composite-kem    ml-kem-768  rsa   length=2048
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    composite-kem-ml-kem-768-rsa2048

CA MUST Issue A Valid Composite ML-KEM-768-RSA3072 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is RSA3072. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   composite-kem   rsa
    ${response}  ${key}=   Exchange Hybrid PKIMessage    composite-kem    ml-kem-768  rsa   length=3072
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    composite-kem-ml-kem-768-rsa3072

CA MUST Issue A Valid Composite ML-KEM-768-RSA4096 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is RSA4096. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   composite-kem   rsa
    ${response}  ${key}=   Exchange Hybrid PKIMessage    composite-kem    ml-kem-768  rsa  length=4096
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    composite-kem-ml-kem-768-rsa4096

CA MUST Issue A Valid Composite ML-KEM-768-ECDH-secp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is ECDH-secp384r1. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   composite-kem   ecdh-secp384r1
    ${response}  ${key}=   Exchange Hybrid PKIMessage    composite-kem    ml-kem-768   ecdh   curve=secp384r1
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    composite-kem-ml-kem-768-ecdh-secp384r1

CA MUST Issue A Valid Composite ML-KEM-768-ECDH-brainpoolP256r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is ECDH-brainpoolP256r1. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   composite-kem   ecdh-brainpoolP256r1
    ${response}  ${key}=   Exchange Hybrid PKIMessage    composite-kem    ml-kem-768   ecdh   curve=brainpoolP256r1
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    composite-kem-ml-kem-768-ecdh-brainpoolP256r1

CA MUST Issue A Valid Composite ML-KEM-768-X25519 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is X25519. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   composite-kem   x25519
    ${response}  ${key}=   Exchange Hybrid PKIMessage    composite-kem    ml-kem-768   x25519
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    composite-kem-ml-kem-768-x25519

CA MUST Issue A Valid Composite ML-KEM-1024-ECDH-secp384r1
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-1024
    ...                and the traditional component is ECDH-secp384r1. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   composite-kem   ecdh-secp384r1
    ${response}  ${key}=   Exchange Hybrid PKIMessage    composite-kem   ml-kem-1024   ecdh  curve=secp384r1
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    composite-kem-ml-kem-1024-ecdh-secp384r1

CA MUST Issue A Valid Composite ML-KEM-1024-ECDH-brainpoolP384r1
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-1024
    ...                and the traditional component is ECDH-brainpoolP384r1. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   composite-kem   ecdh
    ${response}  ${key}=   Exchange Hybrid PKIMessage    composite-kem    ml-kem-1024  ecdh   curve=brainpoolP384r1
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    composite-kem-ml-kem-1024-ecdh-brainpoolP384r1

CA MUST Issue A Valid Composite ML-KEM-1024-X448 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-1024
    ...                and the traditional component is X448. The CA MUST process the request and issue a valid
    ...                encrypted certificate.
    [Tags]             positive   composite-kem   x448
    ${response}  ${key}=   Exchange Hybrid PKIMessage    composite-kem   ml-kem-1024   x448
    ${cert}=   Validate EncrCert For KEM    ${response}    ${key}
    Validate Migration OID In Certificate    ${cert}    composite-kem-ml-kem-1024-x448

CA MUST Reject Composite RSA Key with Invalid Size
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is RSA2048. The CA MUST reject the request and issue an error
    ...                message if the RSA key size is invalid.
    [Tags]             negative   composite-kem   rsa
    ${pq_key}=   Generate Key  ml-kem-768
    ${trad_key}=  Generate Key  bad-rsa-key   length=1024
    ${comp_key}=   Generate Key    composite-kem    pq_key=${pq_key}   trad_key=${trad_key}
    ${cm}=  Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo    ${comp_key}
    ${ir}=  Build Ir From Key   ${comp_key}   spki=${spki}   common_name=${cm}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=     Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${ISSUING_SUFFIX}
    PKIStatus Must Be    ${response}    status=rejection

CA MUST Reject Invalid Composite Public Key Size
    [Documentation]    According to draft-ietf-lamps-pq-hybrid-05, a valid IR message
    ...                is sent for a Composite ML-KEM Certificate. The post-quantum component is ML-KEM-768
    ...                and the traditional component is RSA2048. The CA MUST reject the request and issue an error
    ...                message if the public key size is invalid.
    [Tags]             negative   composite-kem   rsa
    ${pq_key}=   Generate Key  ml-kem-768
    ${trad_key}=  Generate Key  rsa   length=2048
    ${comp_key}=   Generate Key    composite-kem    pq_key=${pq_key}   trad_key=${trad_key}
    ${cm}=  Get Next Common Name
    ${spki}=   Prepare SubjectPublicKeyInfo    ${comp_key}   invalid_size=True
    ${ir}=  Build Ir From Key   ${comp_key}   spki=${spki}   common_name=${cm}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=     Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${ISSUING_SUFFIX}
    PKIStatus Must Be    ${response}    status=rejection
