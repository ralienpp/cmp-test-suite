<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# TODOs

## About Test-Suite Config:
1. Allow non directoryName choice for MAC protection
or remove the option to disable it.


## About CMP:
1. Fix test cases for NULL-DN and SubjectAltName.
2. Add test cases for Section 5.2.1. Requested 
Certificate Contents.
3. Verify the Progress/Coverage for the RFCs.
3. Decide on the RF-Linter settings.
4. Finish/Fix the CCR test cases and Mock-CA logic.
5. Add the general message test cases.
6. Add the announcement test cases.
7. Add the control test cases.
8. Add CompositeSig04.
9. Update Logic for testing the Client Implementation
10. Add Semantic-Fuzz-testing.
11. Add clarity for better differentiation between LwCMP and CMP.
12. May integrate Polling test cases.
15. Create entrypoint for docker containers.
16. Add alternative certificate linters.
17. Restructure the test cases for better readability/identification.
18. Change test cases in composite-sig-tests to use RF templates.
19. Fix CompositeSig v3 and v4 names for the Test-Suite,
to refer to composite-sig as the latest version.

## About PQ:

- Add Test cases for FN-DSA, if standard is available.
- Add Stateful Hash-based signature algorithms (XMSS, LMS).


**Dependencies**

1. Remove `pycryptodome` and replace it with the `cryptography` version 0.45
which then supports `XOFHash`. 


## About Hybrid:

- Maybe check for currently unknown hybrid schemes.
- Keep checking hybrid scheme updates.


## Relevant Literature:


- PQ Certificates: 

1. https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/
2. https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/
3. https://datatracker.ietf.org/doc/draft-ietf-lamps-cms-sphincs-plus/

- Hybrid-KEMs:
1. https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
2. https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/
3. https://datatracker.ietf.org/doc/draft-josefsson-chempat/


- Stateful Hash:
1. https://www.rfc-editor.org/rfc/rfc9708.html
2. https://datatracker.ietf.org/doc/draft-ietf-lamps-x509-shbs/13/