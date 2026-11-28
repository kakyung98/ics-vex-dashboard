"""Resume interrupted stages and publish the 18 workbooks after full validation."""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/item4_source_condition_question_links"
TOOLS = Path(__file__).resolve().parent
LOGS = ROOT / "logs"


def status(phase, **fields):
    path = OUT / "delivery_status.json"
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(dict(phase=phase, updated=time.time(), **fields),
                               ensure_ascii=False, indent=2), encoding="utf8")
    temp.replace(path)


def run(name, args):
    status(name)
    log = LOGS / ("item4-delivery-" + name + ".log")
    with log.open("ab") as stream:
        result = subprocess.run(args, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                env={**os.environ, "PYTHONUTF8": "1"})
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, name)


def ready(marker):
    if not marker.is_file():
        return False
    try:
        return bool(json.loads(marker.read_bytes()))
    except ValueError:
        return False


def finish(args):
    if args.wait_pid:
        try:
            process = psutil.Process(args.wait_pid)
            if "item4-fresh-source-resume.log" in " ".join(process.cmdline()):
                status("running_original_chain", pid=process.pid)
                process.wait()
        except psutil.NoSuchProcess:
            pass
    stages = [
        ("extraction", "extract_source_conditions_for_question_links.py", [], "extracted_source_conditions.json"),
        ("normalization", "prepare_full_source_question_proposals.py", [], "proposals.json"),
        ("mapping", "link_conditions_to_asset_questions.py", [OUT / "proposals.json"], "linked_proposals.json"),
        ("review", "publish_condition_question_links.py", [OUT], "summary.json"),
    ]
    for name, script, extra, marker in stages:
        if ready(OUT / marker):
            continue
        for attempt in range(5):
            try:
                run(name, [sys.executable, TOOLS / script, *extra])
                if not ready(OUT / marker):
                    raise RuntimeError("Missing completed stage: " + name)
                break
            except subprocess.CalledProcessError:
                log = (LOGS / ("item4-delivery-" + name + ".log")).read_bytes()[-12000:]
                transient = any(word in log for word in (b"Connection", b"Timeout", b"RemoteDisconnected", b"503", b"502"))
                if not transient or attempt == 4:
                    raise
                status("retrying", stage=name, attempt=attempt + 1)
                time.sleep(30 * (attempt + 1))
    for index in range(1, 19):
        asset = f"A{index:04d}"
        run(asset, [args.node, "--max-old-space-size=8192", args.stage / "export-condition-links.mjs", asset])
    run("verify_workbooks", [sys.executable, TOOLS / "verify_source_question_workbooks.py", args.stage])
    report = json.loads((OUT / "verification.json").read_bytes())
    status("verified", **report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait-pid", type=int)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    try:
        finish(parser.parse_args())
    except Exception as error:
        status("failed", reason=str(error))
        raise
