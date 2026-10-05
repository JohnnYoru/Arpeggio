#!/usr/bin/env python3
"""Builds data/ieee-oui.tsv from the IEEE Registration Authority CSVs (MA-L, MA-M, MA-S).

Download them from https://standards-oui.ieee.org/ (oui/oui.csv, oui28/mam.csv and
oui36/oui36.csv), then run:

    python3 scripts/ieee-oui.py oui.csv mam.csv oui36.csv > data/ieee-oui.tsv
"""
import csv
import sys

vendors = {}
for path in sys.argv[1:]:
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            vendors[row["Assignment"].strip().upper()] = " ".join(row["Organization Name"].split())

print("# IEEE Registration Authority assignments (MA-L, MA-M, MA-S): <hex prefix>\\t<organization>")
for prefix in sorted(vendors):
    print(f"{prefix}\t{vendors[prefix]}")
