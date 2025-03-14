# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Test cases for the related certificate approach for hybrid certificates.

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
Library             ../pq_logic/hybrid_sig/cert_binding_for_multi_auth.py
Library             ../pq_logic/py_verify_logic.py
Library             ../pq_logic/pq_compute_utils.py


# Suite Setup         Set Up Related Tests
Test Tags           pqc  hybrid-sig

*** Variables ***

# New Tags: composite-sig, multiple-auth

${uri_multiple_auth}=   ${None}
${uri_multiple_auth_neg}=  ${None}

${RELATED_CERT}  ${None}
${RELATED_KEY}  ${None}

${REVOKED_CERT}  ${None}
${REVOKED_KEY}  ${None}

${CA_CERT}  ${None}
${CA_KEY}  ${None}
    
*** Test Cases ***


###########################################
# Cert-bindings-for-multiple-authentication
###########################################

##### positive tests #####

CA MUST Accept valid Request with CSR with related Cert
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, and an valid related certificate
    ...                from the same CA. The CA MUST accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive
    Skip if   not ${uri_multiple_auth}    The URI for multiple auth is not defined.
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}    
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    accepted
    ${cert}=    Get Cert From PKIMessage    ${response}
    Validate Related Cert Extension    ${cert}    ${ISSUED_CERT}
   

CA SHOULD Accept CSR with related cert from different CA
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an valid related certificate
    ...                from a different CA. The CA SHOULD accept the request and issue a valid certificate.
    [Tags]         multiple-auth   csr   positive   different-ca
    Skip if   not ${uri_multiple_auth}    The URI for multiple auth is not defined.
    # TODO uncomment, if needed.
    # get a new cert, if the CA requires to issue a related cert in time.
    # ${ir}=    Generate Default IR Sig Protected
    # ${response}=   Exchange PKIMessage    ${ir}
    # PKIMessage Body Type Must Be    ${response}    ip
    # PKIStatus Must Be    ${response}    accepted
    # ${new_cert}=   Get Cert From PKIMessage    ${response}
    # ${key}=    Get From List    ${burned_keys}    -1
    # must then change the variables.
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    cp
    PKIStatus Must Be    ${response}    accepted
 


# TODO decide how to handle the multiple auth in CertTemplate!
# Technically one to one for x509 inside the CertTemplate.
# But not defined, so either added in a experimental file or excluded.

##### negative tests #####

CA MUST Reject Invalid POP for Cert A
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an invalid POPO for the signature inside the
    ...                `RequesterCertificate` structure. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badPOP`.
    [Tags]         multiple-auth   csr   negative   popo
    Skip if   not ${uri_multiple_auth}    The URI for multiple auth is not defined.
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}   bad_pop=True
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}    exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badPOP
    
# TODO may change the failInfo to a more fitting one.
    
CA MUST Validate that the URI is reachable
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an 
    ...                unreachable URI for the related certificate. The CA MUST detect this error and reject
    ...                the request and MAY respond with the optional failInfo `badRequest`.
    [Tags]         multiple-auth   csr   negative   uri
    Skip if   not ${uri_multiple_auth_neg}    The Not reachable URI for multiple auth is not defined.
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth_neg}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badRequest

CA MUST Reject Cert B Request with invalid serialNumber
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an
    ...                invalid serialNumber for the related certificate. The CA MUST detect this error and reject
    ...                the request and MAY respond with the optional failInfo `badCertTemplate` or `badRequest`.
    [Tags]         multiple-auth   csr   negative   serialNumber
    # increments the serial number by one
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}
    ...            invalid_serial_number=True
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Reject Cert B Request with invalid issuer
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an
    ...                invalid issuer for the related certificate. The CA MUST detect this error and reject
    ...                the request and MAY respond with the optional failInfo `badCertTemplate` or `badRequest`.
    [Tags]         multiple-auth   csr   negative   issuer
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}   invalid_issuer=True
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate

CA MUST Check the Freshness of the BinaryTime
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid freshness
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badTime`.
    [Tags]         multiple-auth   csr   negative   freshness   policy-dependent
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}   freshness=${Allowed_freshness}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badTime

# As defined in Section 3.2
# maybe some parallel test should be implement, were two request are send.
# or send CertTemplate with a serialNumber set and this number is used for the second request.
RA MUST only allow Previously issued certificate to be a related one.
    [Documentation]  As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid related certificate
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badCertTemplate` or `badRequest`.
    [Tags]         multiple-auth   csr   negative   security   policy-dependent
    Skip     NOT-Implemented, user must defined what previous certificate means.
    #         Could either be up to a week or maybe just some time ago and valid at the time of the request.
    ${req_cert}=   Prepare Requester Certificate  cert_a=${ALREADY_ISSUED_CERT}    cert_a_key=${ALREADY_ISSUED_KEY}   uri=${uri_multiple_auth}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

CA MUST Check If The Related Certificate Is Not Revoked.
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid related certificate
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative   rr
    ${result}=   Is Certificate And Key Set    ${REVOKED_CERT}    ${REVOKED_KEY}
    Skip If    ${result}    The revoked certificate and key are not set.
    ${req_cert}=   Prepare Requester Certificate  cert_a=${REVOKED_CERT}    cert_a_key=${REVOKED_KEY}   uri=${uri_multiple_auth}   
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Protect PKIMessage
    ...                pki_message=${p10cr}
    ...                protection=signature
    ...                private_key=${ISSUED_KEY}
    ...                cert=${ISSUED_CERT}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,certRevoked
    Verify StatusString        ${response}    any_text=certificate, not valid  all_text=revoked

CA MUST Check If The Related Certificate Is Not Updated
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but an invalid related certificate
    ...                for the related certificate. The CA MUST detect this error and reject the request and MAY
    ...                respond with the optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative   rr
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${ISSUED_CERT}    cert_a_key=${ISSUED_KEY}   uri=${uri_multiple_auth}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,certRevoked
    Verify StatusString        ${response}    any_text=certificate, not valid, update, updated

CA MUST Reject Related Cert For Non-EE Cert
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but the Certificates is not for
    ...                an end entity. The CA MUST detect this error and reject the request and MAY respond with the
    ...                optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative
    ${result}=   Is Certificate And Key Set    ${CA_CERT}    ${CA_KEY}
    Skip If    not ${result}    The CA certificate and key are not set.
    ${req_cert}=   Prepare RequesterCertificate  cert_a=${CA_CERT}    cert_a_key=${CA_KEY}   uri=${uri_multiple_auth}
    ${pq_key}=    Generate Key    ${DEFAULT_ML_DSA_ALG}
    ${cm}=             Get Next Common Name
    ${extensions}=   Prepare Extensions    is_ca=True
    ${csr}=    Build CSR    ${pq_key}    ${cm}   exclude_signature=True   extensions=${extensions}
    ${req_cert}=    Add CSR RelatedCertRequest Attribute    ${csr}   ${req_cert}
    ${csr}=   Sign CSR    ${csr}   signing_key=${pq_key}
    ${p10cr}=   Build P10cr From CSR    ${csr}   recipient=${RECIPIENT}   exclude_fields=senderKID,sender   implicit_confirm=${True}
    ${protected_p10cr}=  Default Protect PKIMessage    ${p10cr}
    ${response}=  Exchange PKIMessage    ${protected_p10cr}
    PKIMessage Body Type Must Be    ${response}    error
    PKIStatus Must Be    ${response}    rejection
    PKIStatusInfo Failinfo Bit Must Be    ${response}    badCertTemplate,badRequest

CA MUST Reject Related Certificate from Non Trust anchor
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but the Certificates is not from
    ...                a trust anchor. The CA MUST detect this error and reject the request and MAY respond with the
    ...                optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative
    Skip    NOT-Implemented, to setup a Listener to send invalid data yet.

CA MUST Process the CRL within the Signed Data
    [Documentation]    As defined in Cert-binding-for-multiple-auth Section 3.2, we generate a CSR with the related
    ...                certificate attribute. We send a valid CSR, with an valid POP, but the Certificates is not from
    ...                a trust anchor. The CA MUST detect this error and reject the request and MAY respond with the
    ...                optional failInfo `badCertTemplate`.
    [Tags]         multiple-auth   csr   negative
    Skip    NOT-Implemented, to setup a Listener to send invalid data yet.


# CA SHOULD Reject Multi-Auth For Traditional Keys CERT B is meant to be a PQ Certificate.
# CA SHOULD Reject Related Cert with way to less validity time.

CA MUST Accept valid CompositeSig with Related Certificates
    [Documentation]    As defined in Cert-binding-for-multiple-auth we generate a CompositeSig with the related
    ...                certificate extension. We send a valid CompositeSig, with an `PKIMessage` protection an the
    ...                the valid related certificate inside the `extraCerts` field. The CA MUST accept the request
    ...                and issue a valid certificate.
    [Tags]         multi-auth   positive
    ${result}=   Is Certificate And Key Set    ${RELATED_CERT}    ${RELATED_KEY}
    Skip If    not ${result}    The related certificate and key are not set.
    ${cert_template}  ${key}=    Generate CertTemplate For Testing
    ${ir}=    Build Ir From Key   ${key}   cert_template=${cert_template}
    ${comp_key}=    Generate Key    composite-sig   trad_key=${ISSUED_KEY}   pq_key=${RELATED_KEY}
    ${protected_ir}=  Protect Hybrid PKIMessage  ${ir}    signature=composite-sig    ${comp_key}
    ${certs}=    Build Cert Chain From Dir    ${RELATED_CERT}    ./cert_logs
    ${certs_issued}=    Build Cert Chain From Dir    ${ISSUED_CERT}    ./cert_logs
    ${chain}=   Append To List    ${certs_issued}    ${certs}
    ${patched_ir}=   Patch ExtraCerts   ${protected_ir}    ${chain}
    ${response}=   Exchange PKIMessage    ${patched_ir}
    PKIMessage Body Type Must Be    ${response}    ip
    PKIStatus Must Be    ${response}    accepted
