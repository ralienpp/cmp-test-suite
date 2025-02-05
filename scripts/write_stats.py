# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import sys

sys.path.append("./")
sys.path.append("./resources")
sys.path.append("./pq_logic")
from tabulate import tabulate

import pandas as pd

df_pq = pd.DataFrame(columns=["name", "public_key_size", "private_key_size", "ct_length", "claimed_nist_level"])
df_hybrid = pd.DataFrame(columns=["name", "public_key_size", "private_key_size", "ct_length"])
"""
pq_data = []
from pq_logic.pq_key_factory import PQKeyFactory
for alg_name in PQKeyFactory.get_all_kem_alg():
    key = generate_key(algorithm=alg_name)
    pq_data.append(
        {
            "name": key.name,
            "public_key_size": key.public_key().key_size,
            "private_key_size": key.key_size,
            "ct_length": key.ct_length,
            "claimed_nist_level": key.claimed_nist_level,
        }
    )
pq_str = tabulate(pq_data, headers="keys", tablefmt="grid")
with open("./data/stats/pq_table.txt", "w") as f:
    f.write(pq_str)

df_pq = pd.DataFrame(pq_data).sort_values(by="claimed_nist_level")
"""


def _write_hybrids():
    from pq_logic.combined_factory import CombinedKeyFactory

    hybrid_kem_mapping = {}

    data = {}

    for alg_name, options in CombinedKeyFactory.get_all_kem_coms_as_dict().items():
        if alg_name not in data:
            data[alg_name] = []

        for method in options:
            key = CombinedKeyFactory.generate_key(algorithm=alg_name, **method)
            entry = {
                "Name": key.name,
                "Public Key Size": key.public_key().key_size,
                "Private Key Size": key.key_size,
                "CT Length": key.ct_length,
            }
            data[alg_name].append(entry)

    for alg_name, sublist in data.items():
        hybrid_str = tabulate(sublist, headers="keys", tablefmt="grid")
        print("Algorithm:", alg_name, "entries:", len(sublist))
        with open(f"./data/stats/hybrid_table_{alg_name}.txt", "w") as f:
            f.write(hybrid_str)


_write_hybrids()
