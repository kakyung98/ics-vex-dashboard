"""Compare two independently collected, pre-adjudication JSONL rating files."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.reviewer_agreement import agreement_report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--a', type=Path, required=True)
    p.add_argument('--b', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--bootstrap', type=int, default=1000)
    p.add_argument('--seed', type=int, default=42)
    a = p.parse_args()
    def read(path):
        return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
    result = agreement_report(read(a.a), read(a.b), bootstrap=a.bootstrap, seed=a.seed)
    result['inputs'] = {k: {'path': str(path.resolve()), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                        for k, path in [('a', a.a), ('b', a.b)]}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
