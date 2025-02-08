# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Look for improperly Capitalized words in the docstrings and comments."""

import argparse
import ast
import os
import re
from typing import Set


def load_exceptions(file_path: str) -> set:
    """Load od words which are allowed to be capitalized mid-sentence."""
    with open(file_path, "r", encoding="utf-8") as file:
        return {line.strip() for line in file if line.strip()}


def is_camel_case(word: str) -> bool:
    """Check if a word is in camel case."""
    # Regular expression to match camelCase words
    # This pattern looks for a lowercase letter followed by one or more uppercase letters and more lowercase letters
    camel_case_re = re.compile(r"^[a-z]+(?:[A-Z][a-z]+)+$")
    return bool(camel_case_re.match(word))


def check_capitalization(line: str, exceptions: Set[str]) -> list:
    """Check if a line contains improperly capitalized words.

    :param line: The line to check for improperly capitalized words.
    :param exceptions: A set of words which are allowed to be capitalized mid-sentence.
    """
    words = line.split()
    issues = []

    for word in words:
        # breakpoint()
        if word in exceptions or is_camel_case(word):
            continue
        if word[0].isupper() and not word.isupper():
            issues.append(word)

    return issues


def process_docstring(docstring: str, exceptions: Set[str], debug: bool=False):
    """Process a docstring and check for improperly capitalized words.

    Lines with the pipe symbol are skipped.

    :param docstring: The docstring to process.
    :param exceptions: The set of words which are allowed to be capitalized mid-sentence.
    :param debug: Whether to enable debug output. Defaults to `False`.
    :return: The list of lines containing improperly capitalized words.
    """
    results = []
    for line in docstring.splitlines():
        stripped_line = line.lstrip()

        if debug:
            print(f"Analyzing line: {stripped_line}")

        # Skip lines with the pipe symbol
        if "|" in stripped_line:
            if debug:
                print(f"Skipping line due to pipe character: {stripped_line}")
            continue

        if stripped_line.startswith((":param", ":return", ":rtype")):
            parts = stripped_line.split(" ", 1)
            if len(parts) > 1:
                line_to_check = parts[1]
            else:
                continue
        else:
            line_to_check = stripped_line

        issues = check_capitalization(line_to_check, exceptions)
        if issues:
            results.append((line, issues))

    return results


def find_incorrect_capitalization(file_path: str, exceptions: Set[str], debug: bool=False):
    """Find improperly capitalized words in a Python file.

     Lines with the pipe symbol are skipped.

    :param file_path: The path to the file to check.
    :param exceptions: The set of words which are allowed to be capitalized mid-sentence.
    :param debug: Whether to enable debug output. Defaults to `False`.
    """
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError as e:
        print(f"SyntaxError while parsing {file_path}: {e}")
        return

    for node in ast.walk(tree):
        # breakpoint()
        if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)):
            docstring = ast.get_docstring(node)
            if docstring:
                if debug:
                    print(f"Processing docstring in {file_path}:\n{docstring}\n---")
                results = process_docstring(docstring, exceptions, debug=debug)
                for line, issues in results:
                    print(f"In {file_path}: '{line.strip()}' contains capitalized mid-sentence words: {issues}")


def scan_directory_for_issues(directory: str, exceptions: Set[str], debug: bool=False):
    """Scan a directory for improperly capitalized words in docstrings.

    Lines with the pipe symbol are skipped.

    :param directory: The directory to scan.
    :param exceptions: The set of words which are allowed to be capitalized mid-sentence.
    :param debug: Whether to enable debug output. Defaults to `False`.
    """
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                find_incorrect_capitalization(os.path.join(root, file), exceptions, debug=debug)


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Check for unnecessary capitalized words mid-sentence in docstrings.")
    parser.add_argument(
        "directory", nargs="?", default="./resources", help="Directory to scan (default: current directory)"
    )
    parser.add_argument(
        "--exceptions",
        default="./scripts/exception-keywords.txt",
        help="Path to exceptions file (default: exceptions.txt)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    exceptions = load_exceptions(args.exceptions)
    scan_directory_for_issues(args.directory, exceptions, debug=args.debug)


if __name__ == "__main__":
    main()
