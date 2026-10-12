#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Give every collected snapshot a provenance record, in one schema.

data/snapshot_index.json describes where a source tree came from - component,
version, tag, source URL, size. It had 160 entries against 267 collected
snapshots: the later collection paths dropped the tree on disk without writing
the record. The measurements were unaffected (the pipeline walks the directories
directly), but a reviewer asking "is this tree really glibc 2.17?" could only be
answered for 160 of them.

What this does NOT do is re-derive the 160 that already have a record. Those
carry provenance captured at DOWNLOAD time - the tag that was checked out, the
repository it came from, the byte count of what arrived. A directory name cannot
reproduce any of that, so regenerating them would replace recorded fact with
inference. Existing entries are left exactly as they are; only missing ones are
added.

For a missing entry the component and version come from the directory name,
which the collectors wrote as `<component>-<version>`. That is inference, so it
is labelled as such: `source` is "unrecorded" rather than a guessed URL, and
`version_basis` says the name is where the version came from. `bytes` is
measured from the tree, not guessed.

The parse is checked against the 160 known-good records before it is trusted
(`--check`), because a naming rule that works on the examples you looked at and
fails on the rest is the usual way this goes wrong.

Out: data/snapshot_index.json (in place, additions only)
"""
import argparse
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
IDX = os.path.join(BASE, "data", "snapshot_index.json")

# Directory names the collectors produce, and the component each maps to. The
# left side is matched against the start of the component-version directory;
# longest first so "sqlite-version" wins over "sqlite".
PREFIX = [
    ("openssh-portable", "openssh"), ("libssh2-libssh2", "libssh2"),
    ("sqlite-version", "sqlite"), ("glibc-glibc", "glibc"),
    ("curl-curl", "libcurl"), ("wpa_supplicant", "wpa_supplicant"),
    ("nginx-release", "nginx"), ("libexpat", "libexpat"),
    ("net-snmp", "net-snmp"), ("libpcap-libpcap", "libpcap"),
    ("u-boot", "u_boot"), ("u_boot", "u_boot"),
    ("libxml2", "libxml2"), ("busybox", "busybox"), ("openssl", "openssl"),
    ("dnsmasq", "dnsmasq"), ("openvpn", "openvpn"), ("zlib", "zlib"),
    ("linux", "linux-kernel"), ("spring", "spring"), ("sqlparse", "sqlparse"),
    ("libtiff", "libtiff"), ("libpng", "libpng"), ("dropbear", "dropbear"),
]


def parse_dirname(name):
    """('component', 'version') from a snapshot's component directory name."""
    low = name.lower()
    for pre, comp in sorted(PREFIX, key=lambda x: -len(x[0])):
        if low.startswith(pre.lower()):
            rest = name[len(pre):].lstrip("-_")
            # tags arrive as V_7_4_P1 / R_2_2_0 / 1_20_2 as well as 2.9.4
            ver = rest.lstrip("vV").lstrip("-_")
            ver = re.sub(r"^(release|version)[-_]?", "", ver, flags=re.I)
            return comp, (ver or None)
    # no known prefix: split at the first digit group
    m = re.match(r"^(.*?)[-_](v?\d[\w.\-_]*)$", name)
    if m:
        return m.group(1), m.group(2).lstrip("vV")
    return name, None


def tree_bytes(root):
    n = 0
    for dp, _dn, fns in os.walk(root):
        for f in fns:
            try:
                n += os.path.getsize(os.path.join(dp, f))
            except OSError:
                pass
    return n


def comp_dir(cve):
    d = os.path.join(SNAP, cve)
    subs = [s for s in sorted(os.listdir(d)) if os.path.isdir(os.path.join(d, s))]
    return subs[0] if subs else None


def check(idx):
    """Does the parse reproduce the component recorded for the known 160?"""
    ok = bad = skipped = 0
    misses = []
    for cve, rec in sorted(idx.items()):
        sub = comp_dir(cve) if os.path.isdir(os.path.join(SNAP, cve)) else None
        if not sub:
            skipped += 1
            continue
        comp, _ver = parse_dirname(sub)
        if comp == rec.get("component"):
            ok += 1
        else:
            bad += 1
            if len(misses) < 15:
                misses.append((cve, sub, comp, rec.get("component")))
    print("=== parse checked against the recorded entries ===")
    print("  component matches : %d" % ok)
    print("  mismatches        : %d" % bad)
    print("  no snapshot on disk: %d" % skipped)
    for cve, sub, got, want in misses:
        print("    %-16s %-28s parsed=%-14s recorded=%s" % (cve, sub, got, want))
    return bad == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="validate the parse against the existing records, write nothing")
    ap.add_argument("--force", action="store_true",
                    help="backfill even if the check fails (not recommended)")
    a = ap.parse_args()

    idx = json.load(open(IDX, encoding="utf-8"))
    clean = check(idx)
    if a.check:
        return 0 if clean else 1
    if not clean and not a.force:
        print("\nparse does not reproduce the known records; refusing to backfill.\n"
              "Fix PREFIX, or pass --force if the mismatches are understood.")
        return 1

    added = 0
    for cve in sorted(os.listdir(SNAP)):
        d = os.path.join(SNAP, cve)
        if not os.path.isdir(d) or cve in idx:
            continue
        sub = comp_dir(cve)
        if not sub:
            print("  %-16s empty snapshot, skipped" % cve)
            continue
        comp, ver = parse_dirname(sub)
        idx[cve] = {
            "component": comp,
            "version": ver,
            "tag": sub,
            # Never a guessed URL. The tree is here and its name is evidence of
            # what it is; where it was fetched from was not recorded, and
            # inventing a plausible repo would be worse than saying so.
            "source": "unrecorded",
            "bytes": tree_bytes(d),
            "version_basis": "snapshot directory name (provenance not recorded "
                             "at collection time; backfilled by "
                             "tools/backfill_snapshot_index.py)",
        }
        added += 1

    json.dump(idx, open(IDX, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("\nbackfilled %d entries -> %d total" % (added, len(idx)))
    print("->", os.path.relpath(IDX, BASE))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
