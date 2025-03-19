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

*** Keywords ***

Exchange Composite IR PKIMessage
    [Documentation]    According to Composite Sig Draft CMS03, exchange a PKIMessage for a composite IR-based certificate request. This keyword generates a composite key using the traditional algorithm (e.g., rsa, ecdsa, ed25519, ed448) and the specified PQ algorithm, builds an IR with an optional bad POP, protects the PKIMessage, and sends it to the CA.
    ...                Arguments:
    ...                - ${trad_name}: The traditional algorithm name.
    ...                - ${pq_name}: The PQ algorithm name.
    ...                - ${bad_pop}: Whether to manipulate the `POP`. Defaults to `False`.
    ...                - @{optional_args}: Additional key generation parameters (e.g., length, curve).
    ...
    ...                Returns:
    ...                - ${response}: The response PKIMessage.
    ...
    ...                Examples:
    ...                | Exchange Composite IR PKIMessage | rsa | ml-dsa-44 | False |
    ...                | Exchange Composite IR PKIMessage | rsa | ml-dsa-44 | True  | length=2048
    ...                | Exchange Composite IR PKIMessage | ecdsa | ml-dsa-44 | False | curve=secp256r1
    [Arguments]    ${trad_name}    ${pq_name}    ${bad_pop}=False    @{optional_args}
    ${trad_key}=   Generate Key    ${trad_name}   @{optional_args}
    ${pq_key}=     Generate Key    ${pq_name}    @{optional_args}
    ${cm}=         Get Next Common Name
    ${key}=    Generate Key    composite-sig    trad_key=${trad_name}    pq_key=${pq_key}
    ${use_pre_hash}=  Get From Dictionary   ${optional_args}    use_pre_hash    ${False}
    ${use_rsa_pss}=   Get From Dictionary       ${optional_args}    use_rsa_pss    ${False}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}   use_pre_hash=${use_pre_hash}   use_rsa_pss=${use_rsa_pss}
    ${ir}=      Build Ir From Key    ${key}    common_name=${cm}    bad_pop=${bad_pop}
    ...        recipient=${RECIPIENT}    exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=   Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}    ${COMPOSITE_URL_PREFIX}
    RETURN    ${response}

*** Test Cases ***
#### Composite Signature Positive Tests ####

# Normally, you would use `ir` as usual; this is just to demonstrate that csr can be used in almost the same way.

CA MUST Issue A Valid Composite RSA From CSR
    [Documentation]    Verifies compliance with Composite Sig Draft CMS03 by sending a valid CSR with a POP for the
    ...                composite signature version. The traditional algorithm used is RSA and ML-DSA-44 as pq
    ...                algorithm. The CA MUST process the valid request and issue a valid certificate.
    [Tags]             positive   rsa
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${csr}=            Build CSR    ${key}    common_name=${cm}   use_rsa_pss=True
    ${p10cr}=          Build P10cr From CSR   ${csr}  recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${response}=       Exchange Migration PKIMessage    ${protected_p10cr}    ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    status=accepted
    ${cert}=           Get Cert From PKIMessage    ${response}
    Validate Migration Certificate KeyUsage   ${cert}
    Validate Migration Oid In Certificate     ${cert}   composite-sig-ml-dsa-44-rsa2048
    VAR    ${COMP_SIG_CERT}        ${cert}        scope=SUITE   # robocop: off=no-suite-variable
    VAR    ${COMP_SIG_KEY}         ${key}         scope=SUITE   # robocop: off=no-suite-variable
    VAR    ${COMP_SIG_CERT_CHAIN}  ${cert_chain}  scope=SUITE   # robocop: off=no-suite-variable

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
    ${response}=    Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}  ${COMPOSITE_URL_PREFIX}
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
    ${response}=    Exchange Migration PKIMessage    ${protected_kur}   ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
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
    ${response}=    Exchange Migration PKIMessage    ${ir}    ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
    ${cert}=   Confirm Certificate If Needed    ${response}
    ${cert_chain}=   Build Migration Cert Chain    ${cert}    ${response["extraCerts"]}
    ${rr}=   Build CMP Revoke Request    ${cert}    recipient=${RECIPIENT}   reason=keyCompromise
    ${protected_rr}=   Protect Hybrid PKIMessage    ${rr}   ${key}    cert=${cert}
    ${response}=   Exchange Migration PKIMessage    ${protected_rr}    ${CA_BASE_URL}    ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    rp
    PKIStatus Must Be    ${response}    accepted
    VAR    ${REVOKED_COMP_KEY}         ${key}         scope=SUITE    # robocop: off=no-suite-variable
    VAR    ${REVOKED_COMP_CERT}        ${cert}        scope=SUITE    # robocop: off=no-suite-variable
    VAR    ${REVOKED_COMP_CERT_CHAIN}  ${cert_chain}  scope=SUITE    # robocop: off=no-suite-variable
    Write Certs To Dir    ${cert_chain}

CA MUST Reject IR With Revoked Cert
    [Documentation]    According to RFC 9483 Section 4.1.1, the IR must be signed by a valid composite signature
    ...                certificate and corresponding key. We send a valid IR which is signed by a revoked composite
    ...                signature certificate. The CA MUST detect the revoked certificate and reject the request.
    [Tags]             negative   revocation
    ${result}=   Is Certificate And Key Set  ${REVOKED_COMP_CERT}  ${REVOKED_COMP_KEY}
    Skip If     not ${result}    The composite signature certificate and key are not set.
    ${key}=  Generate Default Key
    ${cm}=  Get Next Common Name
    ${ir}=  Build Ir From Key    ${key}   common_name=${cm}   recipient=${RECIPIENT}
    ...    exclude_fields=senderKID,sender
    ${protected_ir}=  Protect Hybrid PKIMessage    ${ir}    ${REVOKED_COMP_KEY}    cert=${REVOKED_COMP_CERT}
    #${protected_ir}=    Build Composite Signature Request   private_key=${REVOKED_COMP_KEY}   cert=${REVOKED_COMP_CERT}
    ${response}=    Exchange Migration PKIMessage    ${protected_ir}    ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}  signerNotTrusted



#### Composite Signature Mixed/Security Tests ####

CA MUST Reject Composite IR with invalid RSA key length
    [Documentation]    As defined in Composite Sig Draft CMS03, we send a valid IR with a POP for composite signature.
    ...                The traditional algorithm is RSA key with an invalid length (512-bits) and ML-DSA-44 as pq
    ...                algorithm. The CA MUST reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate` or `badRequest`.
    [Tags]             negative  rsa
    # generates a rsa key with length 512 bits.
    ${trad_key}=   Generate Key       algorithm=bad_rsa_key
    ${pq_key}=     Generate Key       algorithm=ml-dsa-44
    ${key}=            Generate Key    algorithm=composite-sig   trad_key=${trad_key}   pq_key=${pq_key}
    ${spki}=    Prepare SubjectPublicKeyInfo    ${key}
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   common_name=${cm}   spki=${spki}
    ...                            recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange Migration PKIMessage    ${protected_ir}  ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

#### Security Related #####

CA SHOULD Reject Issuing Already in use Traditional Key
    [Documentation]    As defined in Composite Sig Draft CMS03 Section 11.3, we generate a valid IR with a composite
    ...                signature algorithm. The traditional algorithm is already in use and a matching ML-DSA key is
    ...                generated. The CA SHOULD reject the request and MAY respond with the optional failInfo
    ...                `badCertTemplate` or `badRequest`.
    [Tags]             negative  security
    ${key}=            Generate Key    algorithm=composite-sig   trad_key=${ISSUED_KEY}
    ${cm}=             Get Next Common Name
    ${ir}=    Build Ir From Key    ${key}   ${cm}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange Migration PKIMessage    ${protected_ir}  ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

CA MUST Not Issue A Composite Sig Certificate with an Invalid KeyUsage Bit
    [Documentation]    As defined in Composite Sig Draft CMS03 Section 5.4, we generate a valid IR with a composite
    ...                signature algorithm. The traditional algorithm is RSA and the pq algorithm is ML-DSA-44. The
    ...                key usage bit inside the `CertTemplate` is set to an invalid value. The CA MUST reject the
    [Tags]             negative   robot:skip-on-failure   key-usage
    ${key}=            Generate Key    algorithm=composite-sig  trad_name=rsa   length=2048   pq_name=ml-dsa-44
    ${cm}=             Get Next Common Name
    ${extn}=    Prepare Extensions    key_usage=keyEncipherment,digitalSignature
    ${cert_template}=   Prepare CertTemplate    ${key}   subject=${cm}   extensions=${extn}
    ${ir}=    Build Ir From Key    ${key}  cert_template=${cert_template}
    ...                            recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=    Default Protect PKIMessage    ${ir}
    ${response}=       Exchange Migration PKIMessage    ${protected_ir}  ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Issue A Composite Sig Certificate with cRLSign KeyUsage Bit
    [Documentation]    According to Composite Sig Draft CMS03 Section 5.4, the `cRLSign` key usage bit is allowed for
    ...                composite signature certificates. We generate a valid IR with a composite signature algorithm.
    ...                The key usage bit inside the `CertTemplate` is set to `cRLSign`. The CA MUST process the valid
    ...                request and issue a valid certificate.
    [Tags]             positive   key-usage
    ${key}=            Generate Default Composite Sig Key
    ${cm}=             Get Next Common Name
    ${extn}=           Prepare Extensions    key_usage=cRLSign   is_ca=True
    ${cert_template}=   Prepare CertTemplate    ${key}   subject=${cm}   extensions=${extn}
    ${ir}=    Build Ir From Key    ${key}   cert_template=${cert_template}
    ...                            recipient=${RECIPIENT}   exclude_fields=senderKID,sender
    ${protected_ir}=  Default Protect PKIMessage    ${ir}
    ${response}=       Exchange Migration PKIMessage    ${protected_ir}   ${CA_BASE_URL}   ${COMPOSITE_URL_PREFIX}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
