#!/usr/bin/env python3
"""Fail if the scanners stop detecting the deliberate flaws in tests/."""
import json, sys
web = json.load(open(sys.argv[1]))["findings"]
code = json.load(open(sys.argv[2]))["findings"]
def has(fs, cid, status="fail"):
    return any(f["catalog_id"] == cid and f["status"] == status for f in fs)
expect = [("web", web, c) for c in (3, 4, 7, 8, 14, 20, 23, 24)] + [("code", code, c) for c in (3, 8, 9, 11, 13, 15)]
bad = [(n, c) for n, fs, c in expect if not has(fs, c)]
if bad:
    sys.exit(f"MISSED detections: {bad}")
print(f"ok: {len(expect)} expected detections present")
