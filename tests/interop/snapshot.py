#!/usr/bin/env python3
"""Snapshot fixture names, ownership, modes, times, sizes, and file content.

Run as container root before and after scanning. Access time is excluded because
normal server lookups and this snapshot can update it. No files are modified.
"""

import hashlib
import json
import os
from pathlib import Path
import stat


root = Path("/shares")
if not root.is_dir():
    raise RuntimeError("fixture /shares directory is missing")


def traversal_error(error):
    raise error


records = {}
for directory, names, files in os.walk(root, followlinks=False, onerror=traversal_error):
    for entry in [Path(directory), *(Path(directory) / name for name in names + files)]:
        key = str(entry.relative_to(root))
        if key in records:
            continue
        info = entry.lstat()
        record = {
            "mode": info.st_mode,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "ctime_ns": info.st_ctime_ns,
        }
        if stat.S_ISREG(info.st_mode):
            with entry.open("rb") as stream:
                record["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            record["link"] = os.readlink(entry)
        records[key] = record
print(json.dumps(records, sort_keys=True, separators=(",", ":")))
