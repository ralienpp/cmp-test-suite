<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Mock CA


Note: This is a mock CA is just a simple tool to generate certificates for testing purposes. It is not a real CA and does 
not provide validations for the request unless they are 
related to the hybrid- and pq-logic.

## Start the CA

To start the CA, run the following command:

```make start-mock-ca```

Then can you start the tests with the following command:

```make mock-ca-tests```

## Functionality of the CA




