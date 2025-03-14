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

Suite Setup    Set Up CMP Test Cases
Test Tags           cmp

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


*** Test Cases ***

# TODO fix citation if RFC defined!!!

CA MUST Accept Valid Cross Certification Request 
    [Documentation]   According to RFC4210bis-15 Section 5.3.11 and appendix D.6 We send a valid
    [Tags]    crr   positive   robot:skip-on-failure
    ${result}=   Is Certificate And Key Set    ${TRUSTED_CA_CERT}     ${TRUSTED_CA_KEY}
    Skip If    not ${result}   Skipped because the `TRUSTED_CA_CERT` and `TRUSTED_CA_KEY` are not set.
    ${key}=   Generate Default Key
    # -1 day
    ${date}=   Get Current Date   UTC   increment=-86400
    ${date_after}=   Get Current Date  UTC  increment=10000000
    ${validity}=   Prepare Validity   ${date}   ${date_after}
    ${cert_template}=  Prepare CertTemplate   ${key}    validity=${validity}   subject=${SENDER}   issuer=${RECIPIENT}
    ...                version=v3  include_fields=subject,issuer,validity,publicKey,version
    ${crr}=     Build CCR From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    recipient=${RECIPIENT}
    ${protected_crr}=     Protect PKIMessage
    ...    pki_message=${crr}
    ...    protection=signature
    ...    private_key=${TRUSTED_CA_KEY}
    ...    cert=${TRUSTED_CA_CERT}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIMessage Body Type Must Be    ${response}    ccp
    PKIStatus Must Be    ${response}   accepted
    Validate Cross Certification Response  ${response}

CA MUST Reject Cross Certification Request with private key 
    [Documentation]    According to RFC4210bis-15 Section 
    [Tags]    crr     negative  bad-behaviour
    Skip    Not Implemented Yet.
    ${result}=   Is Certificate And Key Set    ${TRUSTED_CA_CERT}     ${TRUSTED_CA_KEY}
    Skip If    not ${result}   Skipped because the `TRUSTED_CA_CERT` and `TRUSTED_CA_KEY` are not set.
    ${cert_template}    ${key}=  Generate CertTemplate For Testing
    # ${data}=   Prepare Private Key For POP
    #${popo}=    Prepare POPO Env Data  ${key}   sender=${SENDER}  password=${PASSWORD}   server_cert=${TRUSTED_CA_CERT}
    ${crr}=     Build CCR From Key
    ...    ${key}
    ...    cert_template=${cert_template}
    ...    popo_structure=${popo}
    ...    recipient=${RECIPIENT}
    ...    implicit_confirm=${True}
    ${protected_crr}=     Protect PKIMessage
    ...    pki_message=${crr}
    ...    protection=signature
    ...    private_key=${TRUSTED_CA_KEY}
    ...    cert=${TRUSTED_CA_CERT}
    ${response}=    Exchange PKIMessage    ${protected_crr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badRequest


    
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
   ${protected_crr}=     Protect PKIMessage
   ...    pki_message=${crr}
   ...    protection=signature
   ...    private_key=${TRUSTED_CA_KEY}
   ...    cert=${TRUSTED_CA_CERT}
   ${response}=    Exchange PKIMessage    ${protected_crr}
   PKIMessage Body Type Must Be    ${response}    error
   PKIStatus Must Be    ${response}   rejection
   PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP,badRequest

