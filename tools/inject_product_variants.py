#!/usr/bin/env python3
"""CISA CSAF 의 product_tree 를 역방향 SBOM 에 주입해 모델 변형 단위를 만든다.

배경 — 역방향 SBOM 은 ICSA 1건을 장비 1대로 뭉갠다. 그런데 CISA/벤더는 같은 ICSA
안에서 **모델별로** 판정을 가른다(ICSA-25-191-06: SIPROTEC 5 CP300 44개 affected /
CP200 20개 not_affected). 모델 변형 단위가 없으면 그 분기를 표현조차 할 수 없다.

이 도구는 CISA 원본 CSAF 의 product_tree 를 읽어
  - 모델마다 CycloneDX component(type=device) 를 추가하고
  - dependencies 로 최상위 장비에 매단 뒤
  - vulnerabilities[].affects 를 **영향받는 모델에만** 걸어준다.

주의 — 어느 모델이 affected 인지는 CISA product_status 에서 온다. 즉 주입된 SBOM 은
"상류가 알려준 사실"을 담고 있으며, 이를 근거로 낸 판정은 자체 유도가 아니다.
평가 시 반드시 provenance(`variant:source=cisa-csaf`)로 분리하라.

사용:
  python tools/inject_product_variants.py                      # data/gt_icsa 의 25건
  python tools/inject_product_variants.py --csaf-repo /path    # cisagov/CSAF 전량
"""
import argparse
import glob
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBOM = os.path.join(BASE, "reverse_sbom")


def slug(s):
    s = re.sub(r"[^0-9A-Za-z]+", "-", s or "").strip("-").lower()
    return re.sub(r"-{2,}", "-", s)[:80] or "x"


def csaf_sources(repo):
    """ICSA id -> CSAF 파일 경로."""
    out = {}
    pats = [os.path.join(BASE, "data", "gt_icsa", "*", "cisa_csaf", "*.json")]
    if repo:
        pats.insert(0, os.path.join(repo, "csaf_files", "OT", "**", "*.json"))
    for pat in pats:
        for f in glob.glob(pat, recursive=True):
            aid = os.path.basename(f)[:-5]
            if aid.startswith("icsa-"):
                out.setdefault(aid, f)
    return out


def variants_of(csaf):
    """product_tree -> {product_id: {name, cpe, models, hashes, skus, version_range}}

    The previous version returned only the flattened name, which threw away every
    structured identifier CISA does publish. Measured over the OT corpus
    (28,631 products): cpe 0.2%, purl 0%, but **model_numbers 28.1%** - Siemens
    MLFB order codes and their equivalents, 1,326 distinct strings. Those are the
    identifiers an ICS asset owner actually holds; CPE barely exists here because
    NVD's dictionary has no entry for most vendor firmware.

    The version range matters too: 84.6% of OT branches are
    `product_version_range`, and folding that expression into the name is what
    produced component names like "AVEVA Enterprise SCADA >=2024|<=2024_SP1_P01"
    that no matcher can do anything with."""
    out = {}

    def walk(bs, pref, vrange):
        for b in bs or []:
            nm = pref + [b.get("name", "")]
            vr = b.get("name") if b.get("category") == "product_version_range" else vrange
            if "product" in b:
                p = b["product"]
                pid = p.get("product_id")
                if pid:
                    h = p.get("product_identification_helper") or {}
                    out[pid] = {
                        "name": " ".join(n for n in nm if n).strip(),
                        "cpe": h.get("cpe"),
                        "models": list(h.get("model_numbers") or []),
                        "skus": list(h.get("skus") or []),
                        "hashes": list(h.get("hashes") or []),
                        "version_range": vr,
                    }
            walk(b.get("branches"), nm, vr)

    walk((csaf.get("product_tree") or {}).get("branches"), [], None)
    for fp in (csaf.get("product_tree") or {}).get("full_product_names") or []:
        pid = fp.get("product_id")
        if pid and pid not in out:
            h = fp.get("product_identification_helper") or {}
            out[pid] = {"name": fp.get("name", ""), "cpe": h.get("cpe"),
                        "models": list(h.get("model_numbers") or []),
                        "skus": list(h.get("skus") or []),
                        "hashes": list(h.get("hashes") or []),
                        "version_range": None}
    for r in (csaf.get("product_tree") or {}).get("relationships") or []:
        fp = r.get("full_product_name") or {}
        pid = fp.get("product_id")
        if pid and pid not in out:
            h = fp.get("product_identification_helper") or {}
            out[pid] = {"name": fp.get("name", ""), "cpe": h.get("cpe"),
                        "models": list(h.get("model_numbers") or []),
                        "skus": list(h.get("skus") or []),
                        "hashes": list(h.get("hashes") or []),
                        "version_range": None}
    return out


def inject(sbom_path, csaf_path):
    sbom = json.load(open(sbom_path, encoding="utf-8"))
    csaf = json.load(open(csaf_path, encoding="utf-8"))
    names = variants_of(csaf)
    if len(names) < 2:
        return None  # 모델이 하나뿐이면 변형 단위가 의미 없다

    top = ((sbom.get("metadata") or {}).get("component") or {})
    top_ref = top.get("bom-ref") or "device:unknown"

    # 모델별 component
    comps = sbom.setdefault("components", [])
    have = {c.get("bom-ref") for c in comps}
    vrefs = {}
    for pid, info in sorted(names.items()):
        nm = info["name"]
        ref = "variant:%s" % slug(nm or pid)
        vrefs[pid] = ref
        props = [{"name": "variant:csaf-product-id", "value": pid},
                 {"name": "variant:source", "value": "cisa-csaf"}]
        # A model number is an exact string an asset owner can read off the
        # device (Siemens MLFB "6GK7342-5DA02-0XE0"). Matching on it needs no
        # similarity metric at all, so it cannot mis-fire the way a name can.
        for m in info["models"]:
            props.append({"name": "ics:model-number", "value": m})
        for k in info["skus"]:
            props.append({"name": "ics:sku", "value": k})
        if info["version_range"]:
            props.append({"name": "ics:version-range", "value": info["version_range"]})
        comp = {
            "type": "device", "bom-ref": ref, "name": nm or pid,
            "version": "NOASSERTION", "scope": "required",
            "description": "Product variant enumerated by the source CSAF product_tree.",
            "properties": props,
        }
        if info["cpe"]:
            comp["cpe"] = info["cpe"]          # CycloneDX has a first-class field
        if info["hashes"]:
            hs = []
            for h in info["hashes"]:
                for fh in (h.get("file_hashes") or []):
                    if fh.get("algorithm") and fh.get("value"):
                        hs.append({"alg": fh["algorithm"].upper(), "content": fh["value"]})
            if hs:
                comp["hashes"] = hs
        # Enrich in place when the variant already exists: skipping it is why an
        # earlier run left every device component without its model number.
        prev = next((c for c in comps if c.get("bom-ref") == ref), None)
        if prev is None:
            comps.append(comp)
            have.add(ref)
        else:
            keep = [x for x in (prev.get("properties") or [])
                    if not x.get("name", "").startswith(("ics:", "variant:"))]
            prev["properties"] = keep + props
            if info["cpe"]:
                prev["cpe"] = info["cpe"]
            if comp.get("hashes"):
                prev["hashes"] = comp["hashes"]

    # dependencies: 최상위 장비가 모델들을 포함
    deps = sbom.setdefault("dependencies", [])
    dep = next((d for d in deps if d.get("ref") == top_ref), None)
    if dep is None:
        dep = {"ref": top_ref, "dependsOn": []}
        deps.append(dep)
    for r in vrefs.values():
        if r not in dep["dependsOn"]:
            dep["dependsOn"].append(r)

    # CVE 를 영향받는 모델에만 건다
    status = {}
    for v in csaf.get("vulnerabilities") or []:
        cve = v.get("cve")
        if not cve:
            continue
        ps = v.get("product_status") or {}
        status[cve] = {
            "affected": [p for p in (ps.get("known_affected") or []) if p in vrefs],
            "not_affected": [p for p in (ps.get("known_not_affected") or []) if p in vrefs],
        }

    n_scoped = 0
    for v in sbom.get("vulnerabilities") or []:
        st = status.get(v.get("id"))
        if not st or not st["affected"]:
            continue
        v["affects"] = [{"ref": vrefs[p]} for p in st["affected"]]
        props = v.setdefault("properties", [])
        props.append({"name": "variant:affected-count", "value": str(len(st["affected"]))})
        props.append({"name": "variant:not-affected-count", "value": str(len(st["not_affected"]))})
        props.append({"name": "variant:source", "value": "cisa-csaf"})
        n_scoped += 1

    return sbom, len(names), n_scoped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csaf-repo", default=None)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    src = csaf_sources(a.csaf_repo)
    print("CSAF 원본 확보: %d ICSA" % len(src))
    n_done = n_var = n_scoped = 0
    for aid, cpath in sorted(src.items()):
        sp = os.path.join(SBOM, "%s_SBOM-CVE.json" % aid)
        if not os.path.exists(sp):
            continue
        r = inject(sp, cpath)
        if not r:
            continue
        sbom, nv, ns = r
        if not a.dry_run:
            json.dump(sbom, open(sp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        n_done += 1
        n_var += nv
        n_scoped += ns
    print("주입한 SBOM        : %d" % n_done)
    print("추가된 모델 변형   : %d" % n_var)
    print("모델로 좁힌 취약점 : %d" % n_scoped)
    if a.dry_run:
        print("(dry-run — 파일을 쓰지 않았다)")


if __name__ == "__main__":
    main()
