# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Contains the test cases to ensure that all Composite Signature algorithms are
...                 supported by the CA

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


Test Tags           hybrid   hybrid-sig   composite-sig
Suite Setup         Set Up Test Suite

*** Keywords ***

Exchange Composite PKIMessage
    [Documentation]    Build and send a IR message with a composite algorithm
    ...                and signature.
    [Arguments]   ${algorithm}   ${pq_name}    ${trad_name}   &{optional_args}
    ${length}=  Get From Dictionary   ${optional_args}   length    ${None}
    ${curve}=   Get From Dictionary   ${optional_args}   curve    ${None}
    ${comp_key}=   Generate Key  ${algorithm}  pq_name=${pq_name}   trad_name=${trad_name}
    ...           length=${length}   curve=${curve}
    ${bad_pop}=  Get From Dictionary   ${optional_args}   bad_pop    False
    ${use_rsa_pss}=  Get From Dictionary    ${optional_args}  use_rsa_pss   False
    ${use_pre_hash}=  Get From Dictionary    ${optional_args}  use_pre_hash   False
    ${spki}=   Prepare SubjectPublicKeyInfo    ${comp_key}
    ...        use_pre_hash=${use_pre_hash}
    ...        use_rsa_pss=${use_rsa_pss}
    ${cm}=  Get Next Common Name
    ${cert_request}=   Prepare CertRequest  ${comp_key}  ${cm}  spki=${spki}
    ${popo}=   Prepare Signature POPO    ${comp_key}   ${cert_request}  bad_pop=${bad_pop}
    ...        use_rsa_pss=${use_rsa_pss}   use_pre_hash=${use_pre_hash}
    ${cert_req_msg}=   Prepare CertReqMsg  ${comp_key}   cert_request=${cert_request}  popo_structure=${popo}
    ${ir}=    Build Ir From Key    ${comp_key}  cert_req_msg=${cert_req_msg}
    ${protected_ir}=   Default Protect PKIMessage    ${ir}
    ${response}=  Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${COMPOSITE_URL_PREFIX}
    RETURN    ${response}

*** Test Cases ***

CA MUST Issue a Valid Composite Sig ML-DSA-44 RSA2048 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-44
    ...                and the traditional component is RSA2048. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   rsa
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  rsa   length=2048
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-44-rsa2048

CA Reject an Invalid POP For Composite Sig ML-DSA-44 RSA2048 IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA-PSS, and the pq algorithm
    ...                used is ML-DSA-44. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   rsa  badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  rsa
    ...                     length=2048   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue a Valid Composite Sig ML-DSA-44 RSA2048-PSS Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-44
    ...                and the traditional component is RSA2048-PSS. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   rsa-pss
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  rsa
    ...                      length=2048   use_rsa_pss=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-44-rsa2048-pss

CA MUST Reject an Invalid POP For Composite Sig ML-DSA-44 RSA2048-PSS IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA-PSS, and the pq algorithm
    ...                used is ML-DSA-44. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   rsa-pss   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  rsa
    ...                      length=2048   use_rsa_pss=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue a Valid Composite Sig ML-DSA-44 ED25519 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-44
    ...                and the traditional component is ED25519. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   ed25519
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  ed25519
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-44-ed25519

CA MUST Reject an Invalid POP For Composite Sig ML-DSA-44 ED25519 IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is ED25519, and the pq algorithm
    ...                used is ML-DSA-44. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   ed25519   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  ed25519  bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue a Valid Composite Sig ML-DSA-44 ECDSA-secp256r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-44
    ...                and the traditional component is ECDSA-secp256r1. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   ecdsa   secp256r1
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  ecdsa
    ...                     curve=secp256r1
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-44-ecdsa-secp256r1

CA MUST Reject an Invalid POP For Composite Sig ML-DSA-44 ECDSA-secp256r1 IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is ECDSA-secp256r1, and the pq algorithm
    ...                used is ML-DSA-44. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   ecdsa   secp256r1    badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  ecdsa
    ...                     curve=secp256r1  bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue a Valid Composite Sig ML-DSA-65 RSA3072-PSS Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-65
    ...                and the traditional component is RSA3072-PSS. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   rsa-pss
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=3072   use_rsa_pss=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-65-rsa3072-pss

CA MUST Reject and Invalid POP For Composite Sig ML-DSA-65 RSA3072-PSS IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA3072-PSS, and the pq algorithm
    ...                used is ML-DSA-65. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   rsa-pss   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=3072   use_rsa_pss=True  bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue a Valid Composite Sig ML-DSA-65 RSA3072 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-65
    ...                and the traditional component is RSA3072. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   rsa
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=3072
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-65-rsa3072

CA MUST Reject an Invalid POP For Composite Sig ML-DSA-65 RSA3072 IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA3072, and the pq algorithm
    ...                used is ML-DSA-65. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   rsa    badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=3072   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue a Valid Composite Sig ML-DSA-65 RSA4096-PSS Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-65
    ...                and the traditional component is RSA4096-PSS. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   rsa-pss
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=4096   use_rsa_pss=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-65-rsa4096-pss

CA MUST Reject an Invalid POP For Composite Sig ML-DSA-65 RSA4096-PSS IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA4096-PSS, and the pq algorithm
    ...                used is ML-DSA-65. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   rsa-pss    badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=4096   use_rsa_pss=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue a Valid Composite Sig ML-DSA-65 RSA4096 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-65
    ...                and the traditional component is RSA4096. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   rsa
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=4096
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-65-rsa4096

CA MUST Reject an Invalid POP For Composite Sig ML-DSA-65 RSA4096 IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA4096, and the pq algorithm
    ...                used is ML-DSA-65. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   rsa  badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=4096   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue a Valid Composite Sig ML-DSA-87 ECDSA-secp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-87
    ...                and the traditional component is ECDSA-secp384r1. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   ecdsa-secp384r1
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ecdsa   curve=secp384r1
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-87-ecdsa-secp384r1

CA MUST Reject an Invalid POP For Composite Sig ML-DSA-87 ECDSA-secp384r1 IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is ECDSA-secp384r1, and the pq algorithm
    ...                used is ML-DSA-87. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   ecdsa   secp384r1   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ecdsa
    ...                     curve=secp384r1   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue a Valid Composite Sig ML-DSA-87 ECDSA-brainpoolp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-87
    ...                and the traditional component is ECDSA-brainpoolp384r1. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   ecdsa-brainpoolp384r1
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ecdsa
    ...                     curve=brainpoolp384r1
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-87-ecdsa-brainpoolp384r1

CA MUST Reject Invalid POP For Composite Sig ML-DSA-87 ECDSA-brainpoolp384r1 IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is ECDSA-brainpoolp384r1, and the pq algorithm
    ...                used is ML-DSA-87. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   ecdsa  badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87
    ...                      ecdsa   curve=brainpoolp384r1    bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Accept a Valid Composite Sig ML-DSA-87 ED448 IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate. The post-quantum component is ML-DSA-87
    ...                and the traditional component is ED448. The CA MUST process the request and issue a valid
    ...                certificate.
    [Tags]             positive   composite-sig   ed448
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ed448
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-ml-dsa-87-ed448

CA MUST Reject Invalid POP FOR Composite Sig ML-DSA-87 ED448 IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is ED448, and the pq algorithm
    ...                used is ML-DSA-87. The CA MUST detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig   ed448   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ed448
    ...                     bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP


##########################
# Pre-hash version       # robocop: off=0702
##########################

CA MUST Issue an Composite Sig Hash ML-DSA-44 RSA2048-PSS Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-44 and the traditional component is RSA2048-PSS. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   rsa-pss
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  rsa
    ...                      length=2048   use_rsa_pss=True  use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-44-rsa2048-pss

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-44 RSA2048-PSS IR
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                for a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-44 and the traditional component is RSA2048-PSS. The CA MUST process the request and
    ...                issue a valid certificate.
    [Tags]             positive   composite-sig-hash   rsa-pss
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  rsa
    ...                      length=2048   use_rsa_pss=True  use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-44 ED25519 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-44 and the traditional component is ED25519. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   ed25519
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  ed25519
    ...                      use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-44-ed25519

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-44 ED25519 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-44 and the traditional component is ED25519. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   ed25519   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  ed25519
    ...                      use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-44 ECDSA-secp256r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-44 and the traditional component is ECDSA-secp256r1. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   ecdsa-secp256r1
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  ecdsa
    ...                      curve=secp256r1   use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-44-ecdsa-secp256r1

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-44 ECDSA-secp256r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-44 and the traditional component is ECDSA-secp256r1. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   ecdsa-secp256r1   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-44  ecdsa
    ...                      curve=secp256r1   use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-65 RSA3072-PSS Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-65 and the traditional component is RSA3072-PSS. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   rsa-pss
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=3072   use_rsa_pss=True  use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-65-rsa3072-pss

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-65 RSA3072-PSS Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-65 and the traditional component is RSA3072-PSS. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   rsa-pss   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=3072   use_rsa_pss=True  use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-65 RSA3072 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-65 and the traditional component is RSA3072. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   rsa
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=3072   use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-65-rsa3072

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-65 RSA3072 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-65 and the traditional component is RSA3072. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   rsa   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=3072  use_pre_hash=True   bad_pop=True   use_rsa_pss=False
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-65 RSA4096-PSS Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-65 and the traditional component is RSA4096-PSS. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   rsa-pss
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=4096   use_rsa_pss=True  use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-65-rsa4096-pss

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-65 RSA4096-PSS Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-65 and the traditional component is RSA4096-PSS. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   rsa-pss   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=4096   use_rsa_pss=True  use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-65 RSA4096 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-65 and the traditional component is RSA4096. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   rsa
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=4096   use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-65-rsa4096

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-65 RSA4096 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-65 and the traditional component is RSA4096. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   rsa   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  rsa
    ...                      length=4096   use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-65 ECDSA-secp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-65 and the traditional component is ECDSA-secp384r1. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   ecdsa-secp384r1
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  ecdsa
    ...                      curve=secp384r1   use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-65-ecdsa-secp384r1

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-65 ECDSA-secp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-65 and the traditional component is ECDSA-secp384r1. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   ecdsa-secp384r1   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  ecdsa
    ...                      curve=secp384r1   use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-65 ECDSA-secp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-65 and the traditional component is ECDSA-secp384r1. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   ecdsa-secp384r1
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  ecdsa
    ...                      curve=secp384r1   use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-65-ecdsa-secp384r1

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-65 ECDSA-brainpoolp256r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-65 and the traditional component is ECDSA-brainpoolp256r1. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   ecdsa-brainpoolp256r1   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-65  ecdsa
    ...                      curve=brainpoolp256r1   use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-87 ECDSA-secp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-87 and the traditional component is ECDSA-secp384r1. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   ecdsa-secp384r1
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ecdsa
    ...                      curve=secp384r1   use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-87-ecdsa-secp384r1

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-87 ECDSA-secp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-87 and the traditional component is ECDSA-secp384r1. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   ecdsa-secp384r1   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ecdsa
    ...                      curve=secp384r1   use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-87 ECDSA-brainpoolp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-87 and the traditional component is ECDSA-brainpoolp384r1. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   ecdsa-brainpoolp384r1
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ecdsa
    ...                      curve=brainpoolp384r1   use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-87-ecdsa-brainpoolp384r1

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-87 ECDSA-brainpoolp384r1 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-87 and the traditional component is ECDSA-brainpoolp384r1. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   ecdsa-brainpoolp384r1   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ecdsa
    ...                      curve=brainpoolp384r1   use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP

CA MUST Issue an Composite Sig Hash ML-DSA-87 ED448 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR message
    ...                is sent for a composite signature certificate with the pre-hash version. The post-quantum
    ...                component is ML-DSA-87 and the traditional component is ED448. The CA MUST process the
    ...                request and issue a valid certificate.
    [Tags]             positive   composite-sig-hash   ed448
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ed448
    ...                      use_pre_hash=True
    PKIStatus Must Be    ${response}    status=accepted
    Validate Certificate Was Issued For Expected Alg    ${response}    composite-sig-hash-ml-dsa-87-ed448

CA MUST Reject Invalid POP FOR Composite Sig Hash ML-DSA-87 ED448 Certificate
    [Documentation]    According to draft-ietf-lamps-pq-composite-sigs-03, a valid IR with an invalid POP for
    ...                a composite signature certificate with the pre-hash version. The post-quantum component
    ...                is ML-DSA-87 and the traditional component is ED448. The CA MUST detect the invalid POP
    ...                and reject the request. The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             negative   composite-sig-hash   ed448   badPOP
    ${response}  Exchange Composite PKIMessage    composite-sig    ml-dsa-87  ed448
    ...                      use_pre_hash=True   bad_pop=True
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP
