#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Print a whole-reactor test summary from the surefire/failsafe XML reports.

Maven prints per-module totals only and never says why a test was skipped, so
this lists every skipped test with its reason and ends with one grand total.
"""
import os
import sys
import xml.etree.ElementTree as ET

totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
skips = []
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
    if os.path.basename(root) not in ("surefire-reports", "failsafe-reports"):
        continue
    for name in sorted(files):
        if not (name.startswith("TEST-") and name.endswith(".xml")):
            continue
        path = os.path.join(root, name)
        suite = ET.parse(path).getroot()
        for key in totals:
            totals[key] += int(suite.get(key, "0") or 0)
        module = os.path.normpath(path).split(os.sep)
        module = "/".join(module[: module.index("target")]) if "target" in module else "."
        for case in suite.iter("testcase"):
            skipped = case.find("skipped")
            if skipped is None:
                continue
            msg = (skipped.get("message") or (skipped.text or "")).strip()
            if not msg:
                msg = "annotated @Ignore in the upstream test source (no message)"
            skips.append("SKIPPED [%s] %s.%s -- reason: %s" % (
                module, case.get("classname"), case.get("name"), msg))

print("=" * 72)
print("Skipped tests (%d):" % len(skips))
for line in skips:
    print("  " + line)
passed = totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"]
print("TOTAL (all modules, surefire + failsafe): tests run: %d, passed: %d, failures: %d, errors: %d, skipped: %d" % (
    totals["tests"], passed, totals["failures"], totals["errors"], totals["skipped"]))
print("=" * 72)
sys.exit(0)
