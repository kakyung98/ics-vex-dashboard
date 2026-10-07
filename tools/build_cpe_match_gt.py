#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""시험항목 #3 — SBOM 기반 공개 취약점 식별 정밀도의 평가용 Ground Truth 생성.

GT must not be derivable from the thing it scores. `sbom_match` / `cpe_match_l0l3`
decide identity from data/cpe_index.json, so that index is off limits here. The two
authorities used instead are the ones the test spec names
(evidence_source: NVD | CISA | Vendor Advisory):

  CISA  reverse_sbom/*.json  vulnerabilities[].affects[].ref -> components[].bom-ref
        A CSAF product_tree assertion that THIS component is affected by THIS CVE.
        65,238 such pairs exist in the corpus.
  NVD   data/nvd_cpe_detail.json  per-CVE [{vendor, product, version, range}]
        The applicability statement saying which vendor:product the CVE applies to.
        54,497 of the pairs cross-reference into it.

The corpus splits into two layers, and they are NOT scorable the same way:

  Layer A  vendor-anchored (58.1%, 6,034 CVEs)
           The ICS product itself is in NVD: "Siemens Scalance X414-3E"
           -> cpe:2.3:o:siemens:scalance_x414-3e_firmware. The matcher's job is
           name -> CPE product, and the correct answer exists. Scorable.
  Layer B  embedded third-party only (41.9%, 4,279 CVEs)
           CISA says "Schneider ProLeiT is affected by CVE-2025-46817"; NVD's CPE
           for it is `redis:redis`. The ICS name appears nowhere in NVD, so no
           name-based matcher can reach the answer. Counting these as misses scores
           a structural impossibility; dropping them silently inflates the result.

Only Layer A is emitted as scorable GT. Layer B is written to a separate file so the
exclusion is auditable rather than hidden.

Out: data/cpe_match_eval.jsonl        scorable GT (HWP 평가용 Ground Truth schema)
     data/cpe_match_eval_layerB.jsonl excluded embedded-layer pairs, with reason
"""
import argparse
import collections
import glob
import json
import os
import random
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "src"))
from sbom_match import cmp_ver            # version arithmetic only, never identity

CORPUS = os.path.join(BASE, "reverse_sbom")
NVD_DETAIL = os.path.join(BASE, "data", "nvd_cpe_detail.json")
OUT = os.path.join(BASE, "data", "cpe_match_eval.jsonl")
OUT_B = os.path.join(BASE, "data", "cpe_match_eval_layerB.jsonl")
MANIFEST = os.path.join(BASE, "data", "cpe_match_eval_manifest.json")

ADVISORY_URL = "https://www.cisa.gov/news-events/ics-advisories/%s"
NVD_URL = "https://nvd.nist.gov/vuln/detail/%s"
UNPINNED = {"", "noassertion", "unknown", "none", "n/a", "*"}
# asset_id -> normalized names of every component the SBOM declares (filled by harvest)
ASSET_DECLARED = {}
# CSAF carries an affected RANGE, not a pinned version, in VERS form:
#   "Siemens RUGGEDCOM i800 vers:intdot/<4.3.4"            upper bound   (5,113)
#   "Hitachi Energy Relion 670 vers:Relion_670/>=2.2.2.0|<2.2.2.6"  closed interval
#   "Cisco Richards-Zeta Mediator 2500 vers:all/*"         all affected  (6,420)
#   "Sielco WinLog Lite <2.07.00"                          bare bound    (4,000)
VERS_RE = re.compile(r"vers:[^/\s]*/(\S+)")
BARE_RE = re.compile(r"([<>]=?)\s*v?([0-9][\w.\-]*)")
CONSTRAINT_RE = re.compile(r"([<>]=?)\s*_?v?([0-9][\w.\-]*)", re.I)


def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def extract_range(component):
    """Parse the CISA-asserted affected range out of the component name.

    Never read the bom-ref: it is prefixed with the advisory id, so "icsa-24-270-01"
    yielded the phantom version 24.270. Returns (range_dict, source) where
    range_dict uses the same bound names as the NVD entries, or ({}, 'vers:all')
    when every version is affected.
    """
    name = component.get("name") or ""
    v = (component.get("version") or "").strip()
    if v.lower() not in UNPINNED:
        return {"version": v}, "component.version"

    m = VERS_RE.search(name)
    expr = m.group(1) if m else None
    if expr == "*":
        return {}, "csaf_vers_all"
    if expr is None:
        parts = BARE_RE.findall(name)
        if not parts:
            return None, None
        source = "csaf_bare_bound"
    else:
        parts = CONSTRAINT_RE.findall(expr)
        if not parts:
            return None, None
        source = "csaf_vers_range"

    rng = {}
    for op, ver in parts:
        key = {"<": "endExcl", "<=": "endIncl", ">": "startExcl", ">=": "startIncl"}[op]
        rng[key] = ver
    return (rng, source) if rng else (None, None)


def representative_version(rng):
    """A version the range asserts as affected, for the SBOM the SUT is fed.

    Only ever returns a version CISA's own bound puts inside the range — the lower
    bound when there is one (`>=2.2.2.0` -> 2.2.2.0, inclusive, affected). An
    upper-bound-only range (`<4.3.4`) has no authoritative in-range point, so it
    returns None rather than inventing one.
    """
    if rng is None:
        return None
    if rng.get("version"):
        return rng["version"]
    return rng.get("startIncl")


def anchored_cpes(publisher, nvd_entries):
    """EVERY NVD CPE whose vendor is the component's own publisher.

    A CVE routinely carries several disjoint ranges for one product — VxWorks is
    listed as 6.5-6.6, 6.7-6.7.1.1, 6.8-6.8.3, 6.9-6.9.4.4 — and NVD applicability
    is an OR over them, so reading only the first wrongly rejects 6.8. An empty
    list means Layer B (embedded third-party only).
    """
    pub = norm(publisher)
    if not pub:
        return []
    out = []
    for e in nvd_entries:
        nv = norm(e.get("vendor"))
        if nv and (pub in nv or nv in pub):
            out.append(e)
    return out


def _in_entry(ver, entry):
    """True / False / None(undecidable) for one NVD applicability entry."""
    exact = entry.get("version")
    if exact:
        c = cmp_ver(ver, exact)
        return None if c is None else c == 0
    bounds = ((entry.get("startIncl"), lambda c: c < 0),
              (entry.get("startExcl"), lambda c: c <= 0),
              (entry.get("endIncl"), lambda c: c > 0),
              (entry.get("endExcl"), lambda c: c >= 0))
    if not any(b for b, _ in bounds):
        return None
    for bound, violates in bounds:
        if bound:
            c = cmp_ver(ver, bound)
            if c is None:
                return None
            if violates(c):
                return False
    return True


def version_match(ver, entries):
    """OR over the vendor's applicability entries. None is never read as False —
    an unknown version is not evidence of a mismatch."""
    if not ver:
        return None
    verdicts = [_in_entry(ver, e) for e in entries]
    if True in verdicts:
        return True
    if None in verdicts:
        return None
    return False if verdicts else None


def harvest():
    """Walk the corpus and split every CISA-asserted pair into Layer A / Layer B.

    Also records, per asset, the normalized names of every component the SBOM
    declares. build_negatives() needs it: a co-listed vendor is only a sound
    negative when the asset does not actually ship that component.
    """
    detail = json.load(open(NVD_DETAIL, encoding="utf-8"))
    layer_a, layer_b = [], []
    for path in sorted(glob.glob(os.path.join(CORPUS, "*.json"))):
        try:
            sbom = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        asset_id = os.path.basename(path).split("_")[0]
        comps = {c.get("bom-ref"): c for c in sbom.get("components") or []}
        ASSET_DECLARED[asset_id] = {norm(c.get("name")) for c in comps.values()
                                    if c.get("name")}
        for vuln in sbom.get("vulnerabilities") or []:
            cve = vuln.get("id")
            nvd = detail.get(cve)
            if not nvd:
                continue
            for aff in vuln.get("affects") or []:
                ref = aff.get("ref")
                comp = comps.get(ref)
                if not comp:
                    continue
                rec = {"asset_id": asset_id, "bom_ref": ref, "cve_id": cve,
                       "name": comp.get("name"), "publisher": comp.get("publisher")}
                entries = anchored_cpes(comp.get("publisher"), nvd)
                if not entries:
                    rec["reason"] = "embedded-third-party: no NVD CPE under this vendor"
                    rec["nvd_vendors"] = sorted({e["vendor"] for e in nvd if e.get("vendor")})[:8]
                    layer_b.append(rec)
                else:
                    rng, src = extract_range(comp)
                    rec.update({"entries": entries, "cisa_range": rng,
                                "range_source": src,
                                "version": representative_version(rng)})
                    layer_a.append(rec)
    return layer_a, layer_b


def to_gt(rec, idx):
    """Layer A pair -> HWP 평가용 Ground Truth record (applicable=true).

    `review_status` is "verified" only when CISA and NVD agree. When the CISA
    product_tree range puts the component inside the affected set but NVD's
    applicability puts it outside (0.6% of pairs — CVE-2024-22771 is CISA 1.02-4.02
    vs NVD 1.03-4.03), the record is marked "conflict" so the eval can hold it out.
    Labelling a two-authority disagreement "verified" would bake one side's error
    into the benchmark.
    """
    e = rec["entries"][0]
    vm = version_match(rec["version"], rec["entries"])
    return {
        "test_case_id": "SBOM-TC-%04d" % idx,
        "component_id": rec["bom_ref"],
        "component": {"vendor": e["vendor"], "product": e["product"],
                      "version": rec["version"]},
        "cve_id": rec["cve_id"],
        "applicable": True,
        "evidence": {
            "vendor_match": True,
            "product_match": True,
            "version_match": vm,
            "evidence_source": "CISA" if vm is None else "CISA+NVD",
            "evidence_reference": ADVISORY_URL % rec["asset_id"],
            "nvd_reference": NVD_URL % rec["cve_id"],
        },
        "review_status": "conflict" if vm is False else "verified",
        # not part of the submitted schema — kept so the eval can feed the SUT the
        # same messy string a real SBOM carries, and so layers stay auditable
        "_sut_input": {"name": rec["name"], "version": rec["version"],
                       "asset_id": rec["asset_id"], "publisher": rec["publisher"]},
        "_cisa_range": rec.get("cisa_range"),
        "_range_source": rec.get("range_source"),
        "_layer": "A",
    }


def stratify(rows, per_vendor, seed):
    """Siemens alone is 58% of the corpus (38,099 pairs). Cap per vendor so the
    benchmark does not become a Siemens-naming benchmark."""
    rnd = random.Random(seed)
    by = collections.defaultdict(list)
    for r in rows:
        by[norm(r.get("publisher")) or "?"].append(r)
    out = []
    for vendor in sorted(by):
        group = by[vendor]
        rnd.shuffle(group)
        out.extend(group[:per_vendor])
    rnd.shuffle(out)
    return out


def _bump(ver):
    """Smallest version strictly above `ver`, by incrementing its last numeric
    segment: 11.1.07 -> 11.1.8. Used only for an inclusive upper bound, and the
    result is still cross-checked against NVD before it becomes a negative."""
    toks = re.split(r"([.\-])", ver)
    for i in range(len(toks) - 1, -1, -1):
        if toks[i].isdigit():
            toks[i] = str(int(toks[i]) + 1)
            return "".join(toks)
    return None


def _negative(rec, vendor, product, version, axis, flags, source, reference, note):
    """An applicable=false GT record.

    `axis` names the family so the eval can attribute an FP to version vs identity
    confusion; `flags` carries the three match booleans explicitly rather than
    deriving them from the axis. A co-listed negative has BOTH vendor and product
    wrong — `fedoraproject:fedora` is neither the vendor nor the product of a
    Siemens SIMATIC component — and deriving product_match from the axis alone
    would have claimed the product was correct.
    """
    ev = dict(flags)
    ev.update({"evidence_source": source, "evidence_reference": reference,
               "nvd_reference": NVD_URL % rec["cve_id"]})
    return {
        "component_id": rec["bom_ref"],
        "component": {"vendor": vendor, "product": product, "version": version},
        "cve_id": rec["cve_id"],
        "applicable": False,
        "evidence": ev,
        "review_status": "verified",
        "_sut_input": {"name": rec["name"], "version": version,
                       "asset_id": rec["asset_id"], "publisher": rec["publisher"]},
        "_cisa_range": rec.get("cisa_range"),
        "_negative_family": axis,
        "_note": note,
        "_layer": "A",
    }


def version_overrun_negatives(layer_a):
    """Family 1 — a version at or past CISA's own fixed boundary.

    CISA asserting "affected: <4.3.4" is simultaneously an assertion that 4.3.4 is
    NOT affected, so the negative needs no synthesis: the bound itself is the
    version. An inclusive bound (<=11.1.07) has no such free point, so it is
    bumped one segment and only kept if NVD independently agrees it is outside.
    Emitted only when NVD returns a definite False — never on None(undecidable),
    because a CVE's other disjoint range may still cover the version.
    """
    out = []
    for rec in layer_a:
        rng = rec.get("cisa_range") or {}
        if rng.get("endExcl"):
            ver, why = rng["endExcl"], "CISA fixed boundary (exclusive upper bound)"
        elif rng.get("endIncl"):
            ver = _bump(rng["endIncl"])
            why = "one release above CISA inclusive upper bound %s" % rng["endIncl"]
        else:
            continue
        if not ver or version_match(ver, rec["entries"]) is not False:
            continue                       # NVD does not confirm it is outside
        e = rec["entries"][0]
        out.append(_negative(
            rec, e["vendor"], e["product"], ver, "version",
            {"vendor_match": True, "product_match": True, "version_match": False},
            "CISA+NVD", ADVISORY_URL % rec["asset_id"], why))
    return out


def colisted_vendor_negatives(layer_a, detail, seed, per_positive=1):
    """Family 2 — a co-listed vendor's product from the same CVE.

    When vulnerable code lives in shared OSS, NVD attaches one CPE per vendor that
    ships it, so a zlib CVE carries zlib:zlib AND oracle:* AND apple:* AND
    canonical:*. Attributing this asset's component to one of those foreign
    vendor:product pairs is the "잘못된 제품 매핑" FP that `cpe_match_l0l3.vendor_ok()`
    exists to block, so it is the FP mode worth scoring.

    Skipped when the asset's own SBOM declares that component by name — there the
    co-listing may be a genuine embedded dependency rather than a mapping error.
    """
    rnd = random.Random(seed + 1)
    out = []
    for rec in layer_a:
        pub = norm(rec.get("publisher"))
        declared = ASSET_DECLARED.get(rec["asset_id"], set())
        foreign = []
        for e in detail.get(rec["cve_id"]) or []:
            nv, np_ = norm(e.get("vendor")), norm(e.get("product"))
            if not nv or not np_:
                continue
            if pub and (pub in nv or nv in pub):
                continue                   # the asset's own vendor: that is the positive
            if any(np_ in d or nv in d for d in declared):
                continue                   # asset really ships it; not a mapping error
            foreign.append(e)
        if not foreign:
            continue
        rnd.shuffle(foreign)
        for e in foreign[:per_positive]:
            out.append(_negative(
                rec, e["vendor"], e["product"], rec.get("version"), "vendor",
                {"vendor_match": False, "product_match": False,
                 "version_match": None},
                "NVD", NVD_URL % rec["cve_id"],
                "co-listed vendor on a shared-code CVE; asset vendor is %s"
                % (rec.get("publisher") or "?")))
    return out


# ---------------------------------------------------------------------------
# negative cases — applicable=false
#
# CISA publishes only what IS affected, so the harvested pairs are all positives and
# precision = TP/(TP+FP) could never charge the matcher for a wrong mapping. Two
# negative families are built, both from authority data — no synthetic name
# collisions, so every record traces to a CISA bound or an NVD applicability entry:
#
#   version : a version at or past CISA's own fixed boundary, NVD-confirmed outside
#   vendor  : a co-listed vendor's product from the same shared-code CVE
#
# `ratio` caps negatives at that multiple of the positives, keeping the mix
# reproducible — precision gets harsher as the negative share rises, so the ratio
# is part of what the 80% acceptance criterion means and is recorded in the output.
def build_negatives(layer_a, detail, seed, ratio=1.0):
    rnd = random.Random(seed + 2)
    families = [version_overrun_negatives(layer_a),
                colisted_vendor_negatives(layer_a, detail, seed)]
    budget = int(len(layer_a) * ratio)
    # draw evenly from the families so the smaller one is not swamped
    pool, per = [], max(1, budget // len(families))
    for fam in families:
        rnd.shuffle(fam)
        pool.extend(fam[:per])
    leftover = budget - len(pool)
    if leftover > 0:
        taken = {id(r) for r in pool}
        rest = [r for fam in families for r in fam if id(r) not in taken]
        rnd.shuffle(rest)
        pool.extend(rest[:leftover])
    rnd.shuffle(pool)
    return pool[:budget]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-vendor", type=int, default=40,
                    help="max positive pairs per vendor (anti-skew cap)")
    ap.add_argument("--seed", type=int, default=20261007)
    ap.add_argument("--neg-ratio", type=float, default=1.0,
                    help="negatives per positive (raises/lowers how harsh precision is)")
    ap.add_argument("--no-negatives", action="store_true",
                    help="emit positives only (GT is then not FP-scorable)")
    a = ap.parse_args()

    detail = json.load(open(NVD_DETAIL, encoding="utf-8"))
    layer_a, layer_b = harvest()
    print("harvested  Layer A (vendor-anchored) : %d pairs" % len(layer_a))
    print("           Layer B (embedded only)   : %d pairs  -> excluded, logged" % len(layer_b))

    sampled = stratify(layer_a, a.per_vendor, a.seed)
    gt = [to_gt(r, i + 1) for i, r in enumerate(sampled)]
    print("sampled    positives (<=%d/vendor)    : %d" % (a.per_vendor, len(gt)))

    if not a.no_negatives:
        negs = build_negatives(sampled, detail, a.seed, a.neg_ratio)
        for i, n in enumerate(negs):
            n.setdefault("test_case_id", "SBOM-TC-N%04d" % (i + 1))
        gt.extend(negs)
        want = int(len(sampled) * a.neg_ratio)
        print("           negatives                 : %d%s" % (
            len(negs), "" if len(negs) >= want
            else "   (families exhausted; %d requested)" % want))

    with open(OUT, "w", encoding="utf-8") as f:
        for r in gt:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(OUT_B, "w", encoding="utf-8") as f:
        for r in layer_b:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    vm = collections.Counter(r["evidence"]["version_match"] for r in gt)
    fam = collections.Counter(r.get("_negative_family") for r in gt if not r["applicable"])
    rs = collections.Counter(r["review_status"] for r in gt)
    n_pos = sum(1 for r in gt if r["applicable"])

    # the manifest is what makes the figure reproducible: it records the sampling
    # knobs and, just as importantly, what was EXCLUDED and why
    manifest = {
        "test": "SBOM CVE-identification precision (시험항목 #3) — ground truth",
        "generated_from": {"corpus": "reverse_sbom/ (CISA CSAF)",
                           "applicability": "data/nvd_cpe_detail.json (NVD)"},
        "evidence_sources": ["CISA", "NVD"],
        "seed": a.seed, "per_vendor_cap": a.per_vendor,
        "neg_ratio_requested": a.neg_ratio,
        "neg_ratio_achieved": round((len(gt) - n_pos) / n_pos, 3) if n_pos else 0.0,
        "counts": {"total": len(gt), "applicable_true": n_pos,
                   "applicable_false": len(gt) - n_pos,
                   "negative_families": dict(fam)},
        "version_match": {"true": vm[True], "false": vm[False], "undecidable": vm[None]},
        "review_status": dict(rs),
        "exclusions": {
            "layer_b_embedded_only": len(layer_b),
            "layer_b_reason": "CISA asserts the ICS product is affected but NVD's CPE "
                              "is a third-party component (e.g. Schneider ProLeiT -> "
                              "redis:redis); the ICS name is absent from NVD, so no "
                              "name-based matcher can reach the answer",
            "cisa_nvd_conflict": rs.get("conflict", 0),
            "conflict_reason": "CISA range says affected, NVD applicability says not "
                               "(e.g. CVE-2024-22771: CISA 1.02-4.02 vs NVD 1.03-4.03); "
                               "held out rather than labelled verified",
        },
        "scoring_note": "version_match=None means undecidable (CISA publishes upper "
                        "bounds like '<4.3.4', which pin no affected version). It must "
                        "never be read as False.",
    }
    json.dump(manifest, open(MANIFEST, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    print("\napplicable    : true=%d  false=%d" % (n_pos, len(gt) - n_pos))
    print("neg families  : %s" % dict(fam))
    print("version_match : true=%d false=%d undecidable=%d" % (vm[True], vm[False], vm[None]))
    print("review_status : %s" % dict(rs))
    print("->", OUT)
    print("->", OUT_B)
    print("->", MANIFEST)


if __name__ == "__main__":
    main()
