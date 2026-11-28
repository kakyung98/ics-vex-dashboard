"""Build a new CPE-backed corpus without overwriting the active source."""
from pathlib import Path
import argparse
import json
import sys
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tools.item3.rebuild_icsa_cpe_source import rebuild
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    backup=ROOT/'benchmark/icsa-cpe-synthetic sbom-v2-backup-20261125'
    parser.add_argument('--source',type=Path,default=backup if backup.exists() else ROOT/'benchmark/icsa-cpe-synthetic sbom')
    parser.add_argument('--output',type=Path,required=True,help='Fresh versioned output directory')
    parser.add_argument('--cve-source',type=Path,default=ROOT/'data/item3_identification_sources_v11/cves.jsonl')
    a=parser.parse_args();print(json.dumps(rebuild(a.source,a.output,a.cve_source),ensure_ascii=False,indent=2))
