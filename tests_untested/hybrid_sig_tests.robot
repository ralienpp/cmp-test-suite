# SPDX-FileCopyrightText: Copyright 2024 Siemens AG # robocop: off=0704
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       This suite contains tests for the Composite Signature which are related to proof that the
...                 different parameters sets are correctly processed by the CA. The tests are based on the
...                 Composite Signature Draft CMS03, all not named features which are tested are directly related
...                 to the Composite Signature Draft CMS03 like the RSA key size tests and other test align with the
...                 mechanisms mentioned in RFC 9483 LwCMP.

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../pq_logic/hybrid_issuing.py
Library             ../pq_logic/hybrid_prepare.py
Library             ../pq_logic/pq_compute_utils.py
Library             ../pq_logic/pq_validation_utils.py
Library             ../pq_logic/py_verify_logic.py

Test Tags           hybrid-sig   composite-sig

Suite Setup         Set Up Test Suite


*** Variables ***
# To show what certificates are created during run time.
${COMP_SIG_CERT} =  ${None}
${COMP_SIG_KEY} =  ${None}
${REVOKED_COMP_KEY} =  ${None}
${REVOKED_COMP_CERT} =  ${None}


*** Test Cases ***
#### Composite Signature Positive Tests ####

# Normally, you would use `ir` as usual; this is just to demonstrate that csr can be used in almost the same way.

CA MUST Issue A Valid Composite RSA-PSS From CSR
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid CSR with a POP for the
    ...                composite signature version. The traditional algorithm used is RSA-PSS and ML-DSA-44 as pq
    ...                algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             positive   rsa-pss
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    ${key}    common_name=${cm}   use_rsa_pss=True
    ${p10cr}=          Build P10cr From CSR   ${csr}  recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${response}=       Exchange Migration PKIMessage    ${protected_p10cr}    ${CA_CMP_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=           Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage   ${cert}
    Validate Migration Oid In Certificate     ${cert}   ml-dsa-44-rsa2048-pss

CA MUST Issue a Valid Composite-Sig RSA Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is RSA and ML-DSA-44 as pq algorithm.
    ...                The CA MUST process the valid request and issue a valid certificate.
    [Tags]             positive   rsa
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=   Build Ir From Key    ${key}   common_name=${cm}  recipient=${RECIPIENT}
    ...                                    exclude_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange Migration PKIMessage    ${protected_ir}    ${CA_CMP_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is EC key on the secp256r1 curve
    ...                and ML-DSA-44 as pq algorithm. The CA MUST process the valid request and issue a valid
    ...                certificate.
    [Tags]             positive   ec
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=secp256r1   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange Migration PKIMessage    ${protected_ir}    ${CA_CMP_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite EC-brainpool Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is EC key on the brainpoolP256r1
    ...                curve and ML-DSA-65 as pq algorithm. The CA MUST process the valid request and issue a valid
    ...                certificate.
    [Tags]             positive   ec  brainpool
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa
    ...                                curve=brainpoolP256r1   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange Migration PKIMessage    ${protected_ir}    ${CA_CMP_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite ED25519 Certificate
    [Documentation]   Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...               composite signature version. The traditional algorithm used is ED25519 and ML-DSA-65 as pq
    ...               algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]            positive   ed25519
    ${key}=           Generate Key    algorithm=composite-sig  trad_name=ed25519   pq_name=ml-dsa-65
    ${cm}=            Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange Migration PKIMessage    ${protected_ir}    ${CA_CMP_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue a Valid Composite ED448 Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                composite signature version. The traditional algorithm used is ED448 and ML-DSA-87 as pq
    ...                algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             positive   ed448
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448   pq_name=ml-dsa-87
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange Migration PKIMessage    ${protected_ir}    ${CA_CMP_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Accept Valid Composite Sig IR With CertConf
    [Documentation]    According to RFC9483 Section 4.1.1, are we sending a valid IR which is signed by a valid
    ...                composite signature certificate and corresponding key. The CA MUST process the valid request
    ...                and update the certificate accordingly.
    [Tags]             positive   ir
    ${key}=    Generate Default Composite Sig Key
    ${cm}=    Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}
    ...                            exclude_fields=senderKID,sender
    ...                            implicit_confirm=${False}
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=    Exchange Migration PKIMessage    ${protected_ir}   ${CA_CMP_URL}  ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    # Should not contain the implicit confirm extension.
    ${result}=    Find OID In GeneralInfo    ${response}    1.3.6.1.5.5.7.4.13
    Should Be True    not ${result}
    ${cert}=    Confirm Certificate If Needed    ${response}   suffix=${COMPOSITE_URL_PREFIX}
    # does not use `caPubs`, because MUST be absent!
    ${cert_chain}=    Build Migration Cert Chain    ${cert}    certs=${response["extraCerts"]}
    VAR    ${COMP_SIG_CERT}        ${cert}        scope=SUITE   # robocop: off=no-suite-variable
    VAR    ${COMP_SIG_KEY}         ${key}         scope=SUITE   # robocop: off=no-suite-variable
    VAR    ${COMP_SIG_CERT_CHAIN}  ${cert_chain}  scope=SUITE   # robocop: off=no-suite-variable
    Write Certs To Dir    ${cert_chain}

CA MUST Accept a valid Composite Sig KUR
    [Documentation]    According to RFC9483 section 4.1.3, we send a valid KUR which is signed by a valid composite
    ...                signature certificate and corresponding key. The CA MUST process the valid request and update
    ...                the certificate accordingly.
    [Tags]             positive   kur
    ${result}=   Is Certificate And Key Set  ${COMP_SIG_CERT}  ${COMP_SIG_KEY}
    Skip If     not ${result}    The composite signature certificate and key are not set.
    ${key}=            Generate Default Composite Sig Key
    ${cm}=             Get Next Common Name
    ${kur}=    Build Key Update Request    ${key}   common_name=${cm}   recipient=${RECIPIENT}
    ...        exclude_fields=senderKID,sender
    ${protected_kur}=  Protect Hybrid PKIMessage
    ...                ${kur}
    ...                private_key=${COMP_SIG_KEY}
    ...                cert=${COMP_SIG_CERT}
    ${response}=    Exchange Migration PKIMessage    ${protected_kur}   ${CA_CMP_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    kup
    PKIStatus Must Be    ${response}    accepted
    ${cert}=           Get Cert From PKIMessage    ${response}
    ${cert_chain}=   Build Migration Cert Chain    ${cert}    certs=${response["extraCerts"]}
    VAR    ${COMP_SIG_CERT}        ${cert}        scope=SUITE   # robocop: off=no-suite-variable
    VAR    ${COMP_SIG_KEY}         ${key}         scope=SUITE   # robocop: off=no-suite-variable
    VAR    ${COMP_SIG_CERT_CHAIN}  ${cert_chain}  scope=SUITE   # robocop: off=no-suite-variable
    Write Certs To Dir    ${cert_chain}

CA MUST Revoke a valid Composite Sig Cert
    [Documentation]    According to RFC 9483 Section 4.2, the revocation request must be signed by the private key,
    ...                which corresponds to the certificate to be revoked. We send a valid revocation request for a
    ...                composite signature certificate. The CA MUST process the request and revoke the certificate.
    [Tags]             positive   rr
    ${key}=    Generate Default Composite Sig Key
    ${ir}=    Build Composite Signature Request    ${key}
    ${response}=    Exchange Migration PKIMessage    ${ir}    ${CA_CMP_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Confirm Certificate If Needed    ${response}
    ${cert_chain}=   Build Migration Cert Chain    ${cert}    certs=${response["extraCerts"]}
    ${rr}=   Build CMP Revoke Request    ${cert}    recipient=${RECIPIENT}
    ${protected_rr}=   Protect Hybrid PKIMessage    ${rr}   private_key=${key}    cert=${cert}
    ${response}=   Exchange Migration PKIMessage    ${protected_rr}    ${CA_CMP_URL}    ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}    accepted
    VAR    ${REVOKED_COMP_KEY}         ${key}         scope=SUITE    # robocop: off=no-suite-variable
    VAR    ${REVOKED_COMP_CERT}        ${cert}        scope=SUITE    # robocop: off=no-suite-variable
    VAR    ${REVOKED_COMP_CERT_CHAIN}  ${cert_chain}  scope=SUITE    # robocop: off=no-suite-variable
    Write Certs To Dir    ${cert_chain}
    Validate If Certificate Is Revoked    ${cert}

CA MUST Reject IR With Revoked Cert
    [Documentation]    According to RFC 9483 Section 4.1.1, the IR must be signed by a valid composite signature
    ...                certificate and corresponding key. We send a valid IR which is signed by a revoked composite
    ...                signature certificate. The CA MUST detect the revoked certificate and reject the request.
    [Tags]             negative   revocation
    ${result}=   Is Certificate And Key Set  ${REVOKED_COMP_CERT}  ${REVOKED_COMP_KEY}
    Skip If     not ${result}    The composite signature certificate and key are not set.
    ${ir}=    Build Composite Signature Request
    ${protected_ir}=    Protect Hybrid PKIMessage    ${ir}    private_key=${REVOKED_COMP_KEY}
    ...                                               cert=${REVOKED_COMP_CERT}
    ${response}=    Exchange Migration PKIMessage    ${protected_ir}    ${CA_CMP_URL}   ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}  signerNotTrusted
############################
## Pre-Hashed Versions  # robocop: off=0702
############################

CA MUST Issue A Valid Composite RSA-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is RSA and ML-DSA-44 as
    ...                pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True  use_rsa_pss=False
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite RSA-PSS-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is RSA-PSS and ML-DSA-44
    ...                as pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   rsa-pss  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True   use_rsa_pss=True
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is EC key on the secp256r1
    ...                curve and ML-DSA-44 as pq algorithm. The CA MUST process the valid request and issue a valid
    ...                certificate.
    [Tags]             composite-sig   positive   ec  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=secp256r1   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite EC-brainpool-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is EC key on the
    ...                brainpoolP256r1 curve and ML-DSA-65 as pq algorithm. The CA MUST process the valid request
    ...                and issue a valid certificate.
    [Tags]             composite-sig   positive   ec  prehashed  brainpool
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=brainpoolP256r1   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite ED25519-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is ED25519 and ML-DSA-65
    ...                as pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ed25519   prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed25519   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key     ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted

CA MUST Issue A Valid Composite ED448-Prehashed Certificate
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a POP for the
    ...                prehashed composite signature version. The traditional algorithm used is ED448 and ML-DSA-87 as
    ...                pq algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             composite-sig   positive   ed448  prehashed
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448   pq_name=ml-dsa-87
    ${cm}=             Get Next Common Name
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=True
    ${ir}=          Build Ir From Key    ${key}  spki=${spki}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    status=accepted


#### Composite Signature Negative Tests ####

CA MUST Reject An Invalid POP For Composite RSA
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA, and the pq algorithm
    ...                used is ML-DSA-44. The CA must detect the invalid POP and reject the request. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             composite-sig   negative  rsa-pss
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   bad_pop=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP  exclusive=True

CA MUST Reject An Invalid POP For Composite RSA-PSS
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with an invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is RSA-PSS, and the pq algorithm
    ...                used is ML-DSA-44. The CA must detect the invalid POP and reject the re quest. The CA MAY respond
    ...                with the optional failInfo `badPOP`.
    [Tags]             composite-sig   negative  rsa-pss
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   bad_pop=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP  exclusive=True

CA MUST Reject An Invalid POP For Composite EC
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is EC key on the secp256r1 curve
    ...                and ML-DSA-44 as pq algorithm. The CA must detect the invalid POP and reject the request. The CA
    ...                MAY respond with the optional failInfo `badPOP`.
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=secp256r1   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   bad_pop=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP  exclusive=True

CA MUST Reject An Invalid POP For Composite EC-brainpool
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is EC key on the brainpoolP256r1
    ...                curve and ML-DSA-65 as pq algorithm. The CA must detect the invalid POP and reject the request.
    ...                The CA MAY respond with the optional failInfo `badPOP`.
    [Tags]             composite-sig   negative  ec  brainpool
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ecdsa   curve=brainpoolP256r1   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   bad_pop=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP  exclusive=True

CA MUST Reject An Invalid POP For Composite ED25519
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is ED25519 and ML-DSA-65 as pq
    ...                algorithm. The CA must detect the invalid POP and reject the request. The CA MAY respond with the
    ...                optional failInfo `badPOP`.
    [Tags]             composite-sig   negative  ed25519
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed25519   pq_name=ml-dsa-65
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   bad_pop=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP  exclusive=True


CA MUST Reject An Invalid POP For Composite ED448
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid IR with a invalid POP for
    ...                a composite signature algorithm. The traditional algorithm used is ED448 and ML-DSA-87 as pq
    ...                algorithm. The CA must detect the invalid POP and reject the request. The CA MAY respond with the
    ...                optional failInfo `badPOP`.
    [Tags]             composite-sig   negative  ed448
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=ed448   pq_name=ml-dsa-87
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   bad_pop=True   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIStatus Must Be    ${response}    status=rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP  exclusive=True


#### Composite Signature Mixed/Security Tests ####

CA MUST Reject Composite RSA with invalid RSA key length
    [Documentation]    As defined in Composite Sig Draft CMS03, we send a valid IR with a POP for composite signature.
    ...                The traditional algorithm is RSA key with an invalid length (512-bits) and ML-DSA-44 as pq
    ...                algorithm. The CA MUST reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate` or `badRequest`.
    [Tags]             composite-sig   negative  rsa
    # generates a rsa key with length 512 bits.
    ${trad_key}=   Generate Key       algorithm=bad_rsa_key
    ${pq_key}=     Generate Key       algorithm=ml-dsa-44
    ${key}=            Generate Key    algorithm=composite-sig   trad_key=${trad_key}   pq_key=${pq_key}
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

#### Security Related #####

CA MUST Reject Composite Sig with Traditional Revoked key Due Compromise
    [Documentation]    As defined in Composite Sig Draft CMS03 Section 11.2, we generate a CSR with a composite signature.
    ...                The CSR is signed with a RSA key as traditional algorithm and a ML-DSA as pq algorithm.
    ...                The CA MUST reject the request and MAY respond with the optional failInfo `badCertTemplate`.
    [Tags]             composite-sig   negative  security   revocation
    ${result}=     Is Certificate And Key Set    ${REVOKED_CERT}    ${REVOKED_KEY}
    Skip if    not ${result}    The revocation certificate and key are not set.
    ${key}=            Generate Key    algorithm=composite-sig  trad_key=${REVOKED_KEY}
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${REVOKED_KEY}
    ...                cert=${REVOKED_CERT}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection

CA SHOULD Reject Issuing Already in use Traditional Key
    [Documentation]    As defined in Composite Sig Draft CMS03 Section 11.3, we generate a valid IR with a composite
    ...                signature algorithm. The traditional algorithm is already in use and a matching ML-DSA key is
    ...                generated. The CA SHOULD reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate` or `badRequest`.
    [Tags]             composite-sig   negative  security
    ${key}=            Generate Key    algorithm=composite-sig  trad_key=${ISSUED_KEY}
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   omit_fields=senderKID,sender
    ${protected_ir}=  Protect PKIMessage
    ...                pki_message=${ir}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=       Exchange PKIMessage    ${ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest# disable too many lines
# disable too many lines
# robocop: off=0506
