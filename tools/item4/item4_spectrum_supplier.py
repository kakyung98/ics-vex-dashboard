"""Replay the reviewed Siemens source for CVE-2019-6579 from its frozen PDF."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import hashlib
import io
import json
from pathlib import Path
import unicodedata

from pypdf import PdfReader


ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = Path("research_records/item4_spectrum_2019_6579/ssa-324467.pdf")
SHA256 = "3661bd8e9dcf9d4801968c0e84266c5ad31888c92011f6cdfb25bd19830f9d05"
SOURCE_URL = "https://cert-portal.siemens.com/productcert/pdf/ssa-324467.pdf"
FIX_ID = "bf-47456_PE_WOP_fix"


def supplier_evidence() -> dict:
    """Verify original bytes and page anchors, then return JSON-compatible evidence."""
    content = (ROOT / SNAPSHOT).read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if digest != SHA256:
        raise ValueError("SSA-324467 PDF does not match the reviewed SHA-256")

    reader = PdfReader(io.BytesIO(content))
    pages = []
    for page in reader.pages:
        text = unicodedata.normalize("NFKC", page.extract_text().replace("™", ""))
        pages.append(" ".join(text.split()))
    page_anchors = {
        1: [
            "Spectrum Power 4.7",
            "Publication Date: 2019-04-09",
            "Last Update: 2019-04-09",
            "Current Version: V1.0",
            "project enhancement (PE) Web Office Portal (WOP)",
            "Spectrum Power 4: with Web Office Portal",
            FIX_ID,
            "Siemens Energy Customer Support Center",
        ],
        2: ["Vulnerability CVE-2019-6579"],
    }
    for page_number, anchors in page_anchors.items():
        if not all(anchor in pages[page_number - 1] for anchor in anchors):
            raise ValueError(f"SSA-324467 PDF page {page_number} evidence check failed")

    return {
        "source_id": "SSA-324467",
        "url": SOURCE_URL,
        "publisher": "Siemens ProductCERT",
        "document_version": "V1.0",
        "published": "2019-04-09",
        "last_updated": "2019-04-09",
        "snapshot_path": SNAPSHOT.as_posix(),
        "sha256": digest,
        "byte_length": len(content),
        "acquired_at_utc": "2026-11-22T09:38:18Z",
        "cve_id": "CVE-2019-6579",
        "product": "Siemens Spectrum Power 4",
        "version_context": {
            "title_version": "4.7",
            "affected_table_product": "Spectrum Power™ 4",
            "affected_version_range": None,
            "fixed_release": None,
            "source_explicitly_equates_4_7_and_4_70": False,
        },
        "wop": {
            "name": "Web Office Portal",
            "abbreviation": "WOP",
            "condition": "uses_customer_specific_project_enhancement",
        },
        "remediation": {
            "fix_id": FIX_ID,
            "provided_by": "Siemens Energy Customer Support Center",
        },
        "observations": [
            {
                "id": "advisory_version",
                "page": 1,
                "locator": "Title and document metadata",
                "statement_ko": "권고문 제목에는 제품 버전 4.7이 쓰여 있다. 권고문 V1.0의 발행일과 최종 갱신일은 모두 2019-04-09이다.",
            },
            {
                "id": "affected_product",
                "page": 1,
                "locator": "Summary and Affected Products and Solution, product column",
                "statement_ko": "Siemens는 고객별 프로젝트 확장 기능인 WOP를 사용하는 Spectrum Power 4 구성을 영향 대상으로 지정한다. 표에는 구체적인 버전 범위가 없다.",
            },
            {
                "id": "wop_fix",
                "page": 1,
                "locator": "Affected Products and Solution, remediation column",
                "statement_ko": f"Siemens는 WOP 수정 패치 {FIX_ID} 적용을 안내한다. 고객은 Siemens Energy 고객지원센터에서 패치를 받을 수 있다.",
            },
            {
                "id": "cve_binding",
                "page": 2,
                "locator": "Vulnerability Classification, CVE subheading",
                "statement_ko": "권고문이 이 제품 및 조치와 연결하는 식별자는 CVE-2019-6579이다.",
            },
        ],
    }


if __name__ == "__main__":
    print(json.dumps(supplier_evidence(), ensure_ascii=True, indent=2))
