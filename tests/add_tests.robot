# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       General tests for CMP Revocation and Revive Requests logic, not necessarily specific to the
...                 lightweight profile. Includes tests which are configuration-dependent, as some PKI policies may not
...                 allow certificate revocation or may allow revocation but not certificate revival.

Resource            ../resources/keywords.resource
Library             Collections
Library             OperatingSystem
Library             String
Library             ../resources/utils.py
Library             ../resources/asn1utils.py
Library             ../resources/cmputils.py
Library             ../resources/keyutils.py
Library             ../resources/certbuildutils.py
Library             ../resources/protectionutils.py
Library             ../resources/checkutils.py

Suite Setup    Set Up Test Suite


Test Tags           Add

*** Variables ***

${ALLOW_NOT_AUTHORIZED_SENDER}    ${None}
${NOT_AUTHORIZED_SENDER_CERT}    ${None}
${NOT_AUTHORIZED_SENDER_KEY}    ${None}

*** Test Cases ***

CA or RA MUST Reject Not Authorized Sender
    [Documentation]     According to RFC 9483 Section 3.5, the CA or RA must reject a PKIMessage if the sender is not
    ...    authorized to send the message. We send a PKIMessage with a sender that is not authorized to
    ...    send a message. The CA or RA MUST reject the request, and the response may include the failinfo
    ...    `notAuthorized`.
    [Tags]    negative    rfc9483-header    sender   notAuthorized
    Skip If    not ${ALLOW_NOT_AUTHORIZED_SENDER}    This test is skipped because not authorized sender is not allowed.
    ${cert_template}    ${key}=   Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key    ${key}    cert_template=${cert_template}   sender=${SENDER}    recipient=${RECIPIENT}
    # Can only be done if the check is done after the subject field of the certificate is checked.
    # Otherwise, the test will have to be done with a matching certificate or MAC protected.
    IF   '${NOT_AUTHORIZED_SENDER_CERT}' == '${None}'
        ${protected_ir}=   Default Protect PKIMessage  ${ir}  protection=mac
    ELSE
        ${protected_ir}=   Protect PKIMessage  ${ir}   protection=signature
        ...                private_key=${NOT_AUTHORIZED_SENDER_KEY}
        ...                cert=${NOT_AUTHORIZED_SENDER_CERT}
    END
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatusInfo Failinfo Bit Must Be    ${response}    notAuthorized    True

CA MUST Accept Cert with NULL-DN and SAN
    [Documentation]     According to RFC 9483 Section 4.1.1, the CA must accept a certificate request with a NULL-DN as
    ...    the subject and a SubjectAltName extension. We send a certificate request with a NULL-DN and a
    ...    SubjectAltName extension. The CA MUST accept the request and issue a certificate.
    [Tags]   positive    subject    null-dn    san
    ${key}=   Generate Default Key
    ${extn}=    Prepare Extensions    key=${key}    SubjectAltName=example.com
    ${ir}=    Build Ir From Key    ${key}    common_name=Null-DN   recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID   extensions=${extn}
    ${protected_ir}=   Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   accepted

CA MUST Reject Cert with NULL-DN and not SAN set
    [Documentation]     According to RFC 9483 Section 4.1.1, the CA must reject a certificate request without
    ...    a NULL-DN as the subject and a SubjectAltName extension which contains a directoryName choice inside
    ...    a GeneralName. We send a certificate request with a subject that is not NULL-DN and a SubjectAltName
    ...    extension that contains a directoryName choice inside a GeneralName. The CA MUST reject the request.
    ...   The response may include the failinfo `badCertTemplate`.
    [Tags]    negative    subject    null-dn
    ${key}=   Generate Default Key
    ${ir}=    Build Ir From Key    ${key}    common_name=Null-DN   recipient=${RECIPIENT}
    ...       exclude_fields=sender,senderKID
    ${protected_ir}=   Default Protect PKIMessage  ${ir}
    ${response}=    Exchange PKIMessage    ${protected_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}   rejection
    PKIStatusInfo Failinfo Bit Must Be     ${response}    badCertTemplate    True
