#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Make locally-collected (tarball) sources engine-buildable.

For CVEs whose source was collected but is not a GitHub .zip (so it never made it
into the engine cache), repackage the local snapshot into a .zip served over a local
HTTP endpoint and add a cache entry pointing at it. The engine then wget+unzips it
inside the container exactly like a GitHub archive.

Outputs:
  <engine>/webapp/data/localsrc/<CVE>.zip     repackaged source
  <engine>/webapp/data/icsvex_tierA.json       cache with appended entries (backed up)
  results/_group2_cves.txt                      list to build
Serve during build:  python -m http.server 8009  (run in the localsrc dir)
"""
import os, sys, json, zipfile, shutil, datetime

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ENGINE = os.environ.get("VERIFY_ENGINE_DIR", r"C:\Users\user\Desktop\cve-genie")
DATA = os.path.join(ENGINE, "webapp", "data")
LOCALSRC = os.path.join(DATA, "localsrc")
CACHE = os.path.join(DATA, "icsvex_tierA.json")
SNAP = os.path.join(BASE, "data", "source_snapshots")
NVD = json.load(open(os.path.join(BASE, "data", "nvd_cache.json"), encoding="utf-8"))
PORT = 8009

# buildable tarball-only CVEs (linux kernel excluded: build infeasible in sandbox)
CVES = [
    "CVE-2017-13077", "CVE-2017-13078", "CVE-2018-14526", "CVE-2022-23303",  # wpa_supplicant
    "CVE-2017-14491", "CVE-2020-25681", "CVE-2020-25684", "CVE-2023-28450",  # dnsmasq
]

def zip_dir(top_path, top_name, out_zip):
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(top_path):
            for f in files:
                fp = os.path.join(root, f)
                arc = os.path.join(top_name, os.path.relpath(fp, top_path))
                z.write(fp, arc)

def main():
    os.makedirs(LOCALSRC, exist_ok=True)
    cache = json.load(open(CACHE, encoding="utf-8"))
    shutil.copyfile(CACHE, CACHE + ".bak." + datetime.datetime.now().strftime("%Y%m%d%H%M%S"))
    done = []
    for cve in CVES:
        snap = os.path.join(SNAP, cve)
        if not os.path.isdir(snap):
            print("skip (no snapshot):", cve); continue
        tops = [d for d in os.listdir(snap) if os.path.isdir(os.path.join(snap, d))]
        if not tops:
            print("skip (empty snapshot):", cve); continue
        top = tops[0]
        # engine derives project_name = url.split("//")[1].split("/")[2], i.e. it assumes a
        # GitHub-style path .../<owner>/<repo>/...  -> mirror that depth so [2] = project.
        proj = top.rsplit("-", 1)[0]
        subdir = os.path.join(LOCALSRC, proj, proj)
        os.makedirs(subdir, exist_ok=True)
        out_zip = os.path.join(subdir, cve + ".zip")
        zip_dir(os.path.join(snap, top), top, out_zip)
        meta = NVD.get(cve, {})
        cache[cve] = {
            "description": meta.get("description", ""),
            "cwes": [{"id": c, "value": c} for c in meta.get("cwes", [])],
            "sw_version": top,
            "sw_version_wget": f"http://host.docker.internal:{PORT}/{proj}/{proj}/{cve}.zip",
            "patch_commits": [],
            "sec_adv": [],
        }
        done.append(cve)
        print("packaged:", cve, "->", os.path.basename(out_zip), f"({top})")
    json.dump(cache, open(CACHE, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    open(os.path.join(BASE, "results", "_group2_cves.txt"), "w").write("\n".join(done) + "\n")
    print(f"cache entries added: {len(done)}; serve dir: {LOCALSRC} (port {PORT})")

if __name__ == "__main__":
    main()
