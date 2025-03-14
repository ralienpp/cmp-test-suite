<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Mock CA

Note: This is a mock CA is just a simple tool to generate certificates for testing purposes. It is not a real CA and does 
not provide validations for the request unless they are 
related to the hybrid- and pq-logic.

## Overview
Mock CA is a simulated certificate authority designed for testing and
research purposes, particularly focusing on post-quantum (PQ) cryptography and hybrid certificate
issuance. The project enables the issuance, management, and revocation of certificates using a
combination of classical and PQ cryptographic mechanisms.

## About the Mock CA

The Mock-CA is currently only supported in 
the LwCMP fashion.


## Features
- **General Message Handling:** Supports CMP (Certificate Management Protocol) messages with functionalities like key updates, revocation passphrases, and encryption key pair type queries.
- **Certificate Request Processing:** Handles various certificate request types, including:
    - `ir` (initial registration)
    - `cr` (certificate request)
    - `p10cr` (PKCS#10 certificate request)
    - `kur` (key update request)
    - `ccr` (cross-certification request) Not Now!
- **Challenge-Response Mechanism:** Implements a challenge-response system for authentication before issuing certificates.
- **Hybrid Key and Certificate Support:** Enables the use of classical, post-quantum, and hybrid key mechanisms such as:
    - ECDH (Elliptic Curve Diffie-Hellman)
    - X25519/X448 key exchange
    - Hybrid KEMs (Key Encapsulation Mechanisms)
- **Nested and Batch Processing:** Supports nested PKI messages and batch processing for multiple certificate requests.
- **Certificate Revocation Handling:** Manages certificate revocation lists (CRLs) and supports passphrase-based revocation.
- **Added Protection Requests:** Implements LwCMP (Lightweight CMP) protection mechanisms, including password-based MAC and hybrid protection.

## Debug Error handler:

1. The `Exchange PKIMessage` contains a POST methode, there is the error message set.
Otherwise the error message is set in the `PKIMessage` itself, it is advised to use the 
`PKIStatus Must Be` keyword to see the logged PKIStatsInfo.
2. The Mock-CA runs in the `Debug` mode. But there are better not yet
implemented methods, which are better for logging or debugging.

## Start the CA
To start the CA, run the following command:
```sh
make start-mock-ca
```
To test the CMP test cases run the following command:
```sh
make mock-ca-tests
```

## Functionality of the CA

## Future Updates
- **Cross-Certification Requests:** Implement cross-certification requests for issuing certificates across different PKIs.
- 




