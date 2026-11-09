#!/usr/bin/env python3
"""Set one key in a JSON file in place.

A separate file rather than an inline heredoc: nesting a Python heredoc inside
a shell heredoc silently truncates the outer one at the first matching
delimiter, which is a confusing failure to debug.
"""

import json
import sys

if len(sys.argv) != 4:
    raise SystemExit("usage: set-json-key.py <file.json> <key> <value>")

path, key, value = sys.argv[1:4]
cfg = json.load(open(path))
cfg[key] = value
json.dump(cfg, open(path, "w"), indent=2)
