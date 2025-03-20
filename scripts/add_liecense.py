# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Add SPDX license identifier to all Python files that don't have it."""

import glob
import os.path

base_header = """# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""

md_header = """<!-- SPDX-FileCopyrightText: Copyright 2024 Siemens AG
SPDX-License-Identifier: Apache-2.0 -->
"""


def add_header_to_file(path: str, header: str = base_header):
    """Add header to file if it doesn't already have it.

    :param path: Path to the file
    :param header: Header to add
    """
    with open(path, "r", encoding="utf-8") as file:
        content = file.read()

    if "SPDX-License-Identifier:" not in content:
        with open(path, "w") as file:
            if os.path.basename(path) in ["__init__", "__init__.py"]:
                file.write("# noqa D104 Missing docstring in public package" + "\n")
            file.write(header + "\n" + content)

        print(f"Header added to {path}")


# Use glob to find all .py files recursively
for dir_path in ["./resources", "./pq_logic", "./unit_tests", "./scripts", "./mock_ca_ra_server"]:
    for file in glob.iglob(f"{dir_path}/**/*.py", recursive=True):
        add_header_to_file(file)

print("Python files done")
"""
for dir_path in ["./data", "./unit_tests"]:
    for file in glob.iglob(f"{dir_path}/**/*.pem", recursive=True):
        add_header_to_file(file)

print("PEM files done")

for dir_path in ["./data"]:
    for file in glob.iglob(f"{dir_path}/**/*.crl", recursive=True):
        add_header_to_file(file)
print("CRL files done")

for dir_path in ["./data"]:
    for file in glob.iglob(f"{dir_path}/**/*.csr", recursive=True):
        add_header_to_file(file)
"""
for dir_path in ["./"]:
    for file in glob.iglob(f"{dir_path}/**/*.robot", recursive=True):
        add_header_to_file(file)

print("Robot files done")

for dir_path in ["./"]:
    for file in glob.iglob(f"{dir_path}/**/*.resources", recursive=True):
        add_header_to_file(file)

print("Resource files done")