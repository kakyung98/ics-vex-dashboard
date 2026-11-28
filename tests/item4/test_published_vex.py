"""Published assertions remain readable without the optional advisory index."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.item4 import published_vex as published


class PublishedVex(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / 'icsa/csaf'
        self.folder.mkdir(parents=True)
        self.patch = patch.object(published, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        published._collect.cache_clear()
        self.addCleanup(published._collect.cache_clear)
        self.document = {
            'document': {'title': 'Fixture advisory', 'references': [
                {'url': 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-001-01'}]},
            'product_tree': {'branches': [{'category': 'vendor', 'name': 'Fixture vendor',
                'branches': [{'category': 'product_name', 'name': 'Fixture device',
                    'branches': [{'category': 'product_version', 'name': '1.0',
                        'product': {'product_id': 'p1', 'name': 'Fixture device 1.0'}}]}]}]},
            'vulnerabilities': [{'cve': 'CVE-2026-10001', 'flags': [
                {'label': 'component_not_present', 'product_ids': ['p1']},
                {'label': 'vulnerable_code_not_present', 'product_ids': ['p1']}]}],
        }
        self.path = self.folder / 'icsa-26-001-01.json'
        self.path.write_text(json.dumps(self.document), encoding='utf-8')

    def test_missing_index_uses_original_document_and_keeps_product_scope(self):
        result = published.collect()
        self.assertEqual((result['advisories'], result['pairs'], result['label_instances']), (1, 1, 2))
        row = result['rows'][0]
        self.assertEqual(row['vendor'], 'Fixture vendor')
        self.assertEqual(row['url'], self.document['document']['references'][0]['url'])
        self.assertEqual(row['products'][0]['version'], '1.0')
        self.assertEqual(row['source_sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(published.evidence(row['advisory']), self.document)

    def test_optional_index_metadata_is_preserved(self):
        index = self.root / 'data/cisa_advisories.json'
        index.parent.mkdir()
        index.write_text(json.dumps({'icsa-26-001-01': {
            'vendor': 'Indexed vendor', 'url': 'https://example.org/advisory'}}), encoding='utf-8')
        row = published.collect()['rows'][0]
        self.assertEqual(row['vendor'], 'Indexed vendor')
        self.assertEqual(row['url'], 'https://example.org/advisory')

    def test_unreadable_files_are_reported_without_inventing_flags(self):
        (self.folder / 'icsa-26-001-02.json').write_text('', encoding='utf-8')
        self.document['vulnerabilities'] = [{'cve': 'CVE-2026-10002',
            'product_status': {'known_affected': ['p1']}}]
        self.path.write_text(json.dumps(self.document), encoding='utf-8')
        result = published.collect()
        self.assertEqual(result['pairs'], 0)
        self.assertEqual(result['documents_scanned'], 1)
        self.assertEqual(len(result['collection_errors']), 1)


if __name__ == '__main__':
    unittest.main()
