#!/usr/bin/env python3
"""Fail if a tracked file contains what looks like a real AWS account ID.

cloudlens is pointed at real company accounts; their IDs must never reach the public
repo. Only the documented fakes are allowed: a digit repeated twelve times
(111111111111 ... 999999999999, 000000000000) and moto's 123456789012.

Usage: check_account_ids.py [files...]   (default: every file `git ls-files` lists)
"""
from __future__ import annotations

import re
import subprocess
import sys

ID = re.compile(r"(?<![\d.])\d{12}(?![\d.])")
ALLOWED = {str(d) * 12 for d in range(10)} | {"123456789012"}
SKIP_SUFFIXES = (".png", ".jpg", ".ico", ".lock")


def main(argv: list[str]) -> int:
    files = argv or subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
    bad = []
    for path in files:
        if path.endswith(SKIP_SUFFIXES):
            continue
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for m in ID.findall(line):
                if m not in ALLOWED:
                    bad.append(f"{path}:{n}: {m}")
    if bad:
        print("Possible real AWS account IDs found - replace them with a fake like 111111111111:")
        print("\n".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
