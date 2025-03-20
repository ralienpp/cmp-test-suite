# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Contains Test cases which are more or less only relevant for CMP and not LwCMP.

Resource            ../resources/keywords.resource
Resource            ../config/${environment}.robot
Library             OperatingSystem
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/keyutils.py
Library             ../resources/cmputils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py
Library             ../resources/extra_issuing_logic.py
Library             ../resources/envdatautils.py

Suite Setup    Set Up CMP Test Cases
Test Tags           cmp   advanced   crr

*** Variables ***
 
${TRUSTED_CA_CERT}      ${None}
${TRUSTED_CA_KEY}       ${None}
${CA_CERT}              ${None}
${CA_KEY}               ${None}

*** Keywords ***
Set Up CMP Test Cases
    [Documentation]    Set up the test cases for the CMP test cases.
    Set Up Test Suite
    ${cert}    ${key}=    Issue New Cert For Testing
    VAR   ${TRUSTED_CA_CERT}    ${cert}  scope=Global
    VAR   ${TRUSTED_CA_KEY}     ${key}  scope=Global

Default Protect PKIMessage With Trusted Cert
    [Documentation]    Protects the PKIMessage with the trusted CA certificate.
    [Arguments]    ${pki_message}
    ${response}=  Protect PKIMessage    ${pki_message}    signature
    ...           private_key=${TRUSTED_CA_KEY}    cert=${TRUSTED_CA_CERT}
    RETURN    ${response}

*** Test Cases ***

# TODO fix citation if RFC defined!!!

CA MUST Accept Valid Cross Certification Request 
    [Documentation]   According to RFC4210bis-15 Section 5.3.11 and appendix D.6 We send a valid
    [Tags]      positive   robot:skip-on-failure
    ${result}=   Is Certificate And Key Set    ${TRUSTED_CA_CERT}     ${TRUSTED_CA_KEY}
    Skip If    not ${result}   Skipped because the `TRUSTED_CA_CERT` and `TRUSTED_CA_KEY` are not set.
    ${key}=   Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    # -1 day
    ${date}=   Get Current Date   UTC   increment=-86400
    ${date_after}=   Get Current Date  UTC  increment=10000000
    ${validity}=   Prepare Validity   ${date}   ${date_after}
    ${cert_template}=  Prepare CertTemplate   ${key}    validity=${validity}   subject=${SENDER}   issuer=${RECIPIENT}
    ...       sign_alg=${sig_alg}    version=v3  include_fields=subject,issuer,validity,publicKey,version,signingAlg
    ${crr}=     Build CCR From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted Cert   ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIMessage Body Type Must Be    ${response}    ccp
    PKIStatus Must Be    ${response}   accepted
    Validate Cross Certification Response  ${response}

CA MUST Reject Cross Certification Request with private key 
    [Documentation]    According to RFC4210bis-15 Section 
    [Tags]         negative  bad-behaviour
    Skip    NotImplemented yet.
    ${result}=   Is Certificate And Key Set    ${TRUSTED_CA_CERT}     ${TRUSTED_CA_KEY}
    Skip If    not ${result}   Skipped because the `TRUSTED_CA_CERT` and `TRUSTED_CA_KEY` are not set.
    ${cert_template}    ${key}=  Generate CertTemplate For Testing
    # ${data}=   Prepare Private Key For POP
    ${enc_key_id}=   Prepare EncKeyWithID    ${key}   sender=${SENDER}   use_string=False
    ${rid}=   Prepare Recipient Identifier    ${TRUSTED_CA_CERT}   
    ${popo}=   Prepare EncryptedKey For POPO    ${enc_key_id}   ${rid}   ${TRUSTED_CA_CERT}   for_agreement=False
    ${crr}=     Build CCR From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    popo=${popo}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_crr}=     Default Protect PKIMessage With Trusted Cert    ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badRequest, badCertTemplate

CA MUST Reject Cross Certification Request without POP
   [Documentation]    According to RFC4210bis-15 Section Section 5.3.11 the private key **MUST** not be
   ...                disclosed to the other CA. We send a Crr message without a key, basically asking the
   ...                CA to create a key for us. The CA MUST reject this request and may respond with the
   ...                optional failInfo `badRequest` , `badPOP`.
   [Tags]    crr     negative
   ${result}=   Is Certificate And Key Set    ${TRUSTED_CA_CERT}     ${TRUSTED_CA_KEY}
   Skip If    not ${result}   Skipped because the `TRUSTED_CA_CERT` and `TRUSTED_CA_KEY` are not set.
   ${cm}=   Get Next Common Name
   ${crr}=     Build CCR From Key
   ...    ${None}
   ...    common_name=${cm}
   ...    for_kga=True
   ...    recipient=${RECIPIENT}
   ...    implicit_confirm=${True}
   ${protected_crr}=     Default Protect PKIMessage With Trusted Cert    ${crr}
   ${response}=    Exchange PKIMessage    ${protected_crr}
   PKIMessage Body Type Must Be    ${response}    error
   PKIStatus Must Be    ${response}   rejection
   PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP,badRequest

CA MUST Reject Cross Certification Request With V2
    [Documentation]   According to RFC4210bis-18 Appendix D.6 the version field of the `CertTemplate` must be v3
    ...                v1. We send a valid cross certification with the version field set to v2. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    crr     negative   badCertTemplate
    ${key}=   Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=   Get Current Date   UTC   increment=-86400
    ${date_after}=   Get Current Date  UTC  increment=10000000
    ${validity}=   Prepare Validity   ${date}   ${date_after}
    ${cert_template}=  Prepare CertTemplate   ${key}    validity=${validity}   subject=${SENDER}   issuer=${RECIPIENT}
    ...     version=v2     sign_alg=${sig_alg}         include_fields=subject,issuer,validity,publicKey,version,signingAlg
    ${crr}=     Build CCR From Key   ${key}   cert_template=${cert_template}   recipient=${RECIPIENT}
    ...     exclude_fields=popo_structure
    ${protected_crr}=     Default Protect PKIMessage    ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate


#### Missing fields in CertTemplate

CA MUST Reject Cross Certification Request Missing Version Field
    [Documentation]    According to RFC4210bis-18 Appendix D.6, the version field of CertTemplate must be present.
    ...                We send a valid cross certification request without the version field. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    crr    negative    badCertTemplate
    ${key}=    Generate Default Key
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,issuer,validity,publicKey,signingAlg
    ${crr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted Cert    ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing Signing Algorithm
    [Documentation]    Signing algorithm in the CertTemplate must be present.
    ...                We send a valid cross certification request without signingAlg. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    crr    negative    badCertTemplate
    ${key}=    Generate Default Key
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}    subject=${SENDER}    issuer=${RECIPIENT}
    ...    version=v3    include_fields=subject,issuer,validity,publicKey,version
    ${crr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted Cert    ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing Validity
    [Documentation]    Validity field must be completely specified.
    ...                We send a valid cross certification request without validity. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    crr    negative    badCertTemplate
    ${key}=    Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${cert_template}=    Prepare CertTemplate    ${key}    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,issuer,publicKey,version,signingAlg    exclude_fields=validity
    ${crr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted Cert    ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing Issuer
    [Documentation]    Issuer field must be present in CertTemplate.
    ...                We send a valid cross certification request without issuer. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    crr    negative    badCertTemplate
    ${key}=    Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}    subject=${SENDER}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,validity,publicKey,version,signingAlg
    ${crr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ${protected_crr}=     Default Protect PKIMessage With Trusted Cert    ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing PublicKey
    [Documentation]    PublicKey field must be present in CertTemplate.
    ...                We send a valid cross certification request without publicKey. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    crr    negative    badCertTemplate
    ${key}=    Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,issuer,validity,version,signingAlg
    ${crr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_crr}=     Default Protect PKIMessage With Trusted Cert    ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cross Certification Request Missing POPOSigningKey
    [Documentation]    POPOSigningKey must be present as proof-of-possession.
    ...                We send a valid cross certification request without POPOSigningKey. The CA MUST reject
    ...                the request and may return a `badPOP` failInfo.
    [Tags]    crr    negative    badPOP
    ${key}=    Generate Default Key
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key}    validity=${validity}    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,issuer,validity,publicKey,version,signingAlg
    ${cert_req_msg}=   Prepare CertReqMsg    ${key}    cert_template=${cert_template}     exclude_popo=True
    ${crr}=    Build CCR From Key    ${key}    cert_req_msg=${cert_req_msg}    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_crr}=     Default Protect PKIMessage With Trusted Cert    ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP


CA MUST Reject Cross Certification Request Non-Signing Key
    [Documentation]    The key used in the CertTemplate must be a signing key.
    ...                We send a valid cross certification request with a non-signing key. The CA MUST reject
    ...                the request and may return a `badCertTemplate` failInfo.
    [Tags]    crr    negative    badCertTemplate   badAlg
    ${key}=    Generate Default Key
    ${key2}=    Generate Key  x25519
    ${sig_alg}=    Prepare Signature AlgorithmIdentifier     ${key}   hash_alg=sha256
    ${date}=    Get Current Date    UTC    increment=-86400
    ${date_after}=    Get Current Date    UTC    increment=10000000
    ${validity}=    Prepare Validity    ${date}    ${date_after}
    ${cert_template}=    Prepare CertTemplate    ${key2}    validity=${validity}    subject=${SENDER}    issuer=${RECIPIENT}
    ...    sign_alg=${sig_alg}   version=v3   include_fields=subject,issuer,validity,publicKey,version,signingAlg
    ${crr}=    Build CCR From Key    ${key}    cert_template=${cert_template}    recipient=${RECIPIENT}
    ...    exclude_fields=sender,senderKID
    ${protected_crr}=     Default Protect PKIMessage With Trusted Cert    ${crr}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badAlg
