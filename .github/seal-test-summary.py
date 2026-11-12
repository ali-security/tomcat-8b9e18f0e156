#!/usr/bin/env python3

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Prints the JUnit results of `ant test-nio` to the job log: one line per
# suite, every failing test, every skipped test with the runner's skip message
# plus the Assume/@Ignore source lines of its suite, and the totals. Reads the
# plain-formatter reports output/build/logs/TEST-<class>.NIO.txt. Read-only:
# the job's pass/fail is decided by `ant test-status` in the test step.

import glob
import os
import re
import sys

LOG_DIR = sys.argv[1] if len(sys.argv) > 1 else "output/build/logs"
TEST_SRC = sys.argv[2] if len(sys.argv) > 2 else "test"

RE_COUNTS = re.compile(r"^Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)")
RE_CASE = re.compile(r"^Testcase: (.+?) took ")
RE_SKIP = re.compile(r"^\s+SKIPPED(?::\s*(.*))?$")
RE_FAIL = re.compile(r"^\s+(FAILED|Caused an ERROR)")
RE_GUARD = re.compile(r"\bAssume\.|\bassume(True|False|NotNull|That|NoException)\s*\(|@Ignore")


def suite_class(path):
    name = os.path.basename(path)[len("TEST-"):-len(".txt")]
    return re.sub(r"\.(NIO2?|APR)$", "", name)


def guard_lines(cls):
    src = os.path.join(TEST_SRC, cls.split("$")[0].replace(".", os.sep) + ".java")
    out = []
    try:
        with open(src, encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
    except OSError:
        return out
    for i, line in enumerate(lines):
        if RE_GUARD.search(line):
            stmt = line.strip()
            j = i
            while ";" not in lines[j] and not stmt.startswith("@") and j < i + 4 and j + 1 < len(lines):
                j += 1
                stmt += " " + lines[j].strip()
            out.append("%s:%d: %s" % (os.path.relpath(src, TEST_SRC), i + 1, stmt))
    return out


def main():
    files = sorted(glob.glob(os.path.join(LOG_DIR, "TEST-*.txt")))
    tot = {"suites": 0, "tests": 0, "fail": 0, "err": 0, "skip": 0}
    skips = []
    fails = []
    skipped_suites = []
    print("=" * 78)
    print("JUnit results from %s (%d report files)" % (LOG_DIR, len(files)))
    print("=" * 78)
    for path in files:
        cls = suite_class(path)
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
        counts = None
        for line in lines:
            m = RE_COUNTS.match(line)
            if m:
                counts = [int(x) for x in m.groups()]
                break
        if counts is None:
            print("SUITE %s: no 'Tests run' line (suite did not complete)" % cls)
            fails.append((cls, "<suite did not complete>"))
            continue
        t, fl, er, sk = counts
        tot["suites"] += 1
        tot["tests"] += t
        tot["fail"] += fl
        tot["err"] += er
        tot["skip"] += sk
        print("SUITE %s: run=%d passed=%d failures=%d errors=%d skipped=%d" % (
            cls, t, t - fl - er - sk, fl, er, sk))
        # Ant's plain formatter writes "Testcase: X took ..." then the
        # "\tSKIPPED: <message>" / "\tFAILED" line for that same test.
        current = None
        for line in lines:
            m = RE_CASE.match(line)
            if m:
                current = m.group(1)
                continue
            m = RE_SKIP.match(line)
            if m:
                skips.append((cls, current, (m.group(1) or "").strip() or "(runner gave no message)"))
                continue
            if RE_FAIL.match(line):
                fails.append((cls, current))
        if sk:
            skipped_suites.append(cls)
    print("")
    print("FAILED TESTS (%d):" % len(fails))
    for cls, name in fails:
        print("  FAILED %s.%s" % (cls, name))
    print("")
    print("SKIPPED TESTS (%d), each with the runner's skip message:" % len(skips))
    for cls, name, msg in skips:
        print("  SKIPPED %s.%s -- %s" % (cls, name, msg))
    groups = {}
    for cls, _name, msg in skips:
        groups[(cls, msg)] = groups.get((cls, msg), 0) + 1
    print("")
    print("SKIP GROUPS:")
    for (cls, msg), n in sorted(groups.items()):
        print("  SKIP-GROUP %d x %s -- %s" % (n, cls, msg))
    if skipped_suites:
        print("")
        print("Skip guards (Assume / @Ignore) in the source of each suite with skips:")
        for cls in skipped_suites:
            for g in guard_lines(cls):
                print("  " + g)
    print("")
    print("TOTALS: suites=%d tests=%d passed=%d failures=%d errors=%d skipped=%d" % (
        tot["suites"], tot["tests"], tot["tests"] - tot["fail"] - tot["err"] - tot["skip"],
        tot["fail"], tot["err"], tot["skip"]))


if __name__ == "__main__":
    main()
