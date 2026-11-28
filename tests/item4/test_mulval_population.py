from copy import deepcopy
from pathlib import Path
import tempfile,sqlite3,unittest
from src.item4.decision import batch_attack_graphs as B
from src.item4.decision import mulval_attack_graphs as M
from src.item4.decision import population_condition_rules as P
from src.item4.decision import attack_graph_builder as G


class PopulationGraphs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db=P.connection();ids=[r[0] for r in db.execute('SELECT cve FROM records ORDER BY cve LIMIT 4')];db.close()
        cls.records=[P.get(c) for c in ids];cls.contracts=[B.contract(r) for r in cls.records]
        cls.programs=[M.compile_program(c) for c in cls.contracts]
        cls.merged,cls.namespace=B.combine(cls.programs);cls.receipt=M.generate(cls.merged)
        cls.parts=B.partition(cls.programs,cls.merged,cls.namespace,cls.receipt)

    def test_every_cve_has_actual_mulval_nodes_and_unknown_operating_goal(self):
        for record,contract,program,part in zip(self.records,self.contracts,self.programs,self.parts):
            graph=M.import_graph(contract,program,part)
            self.assertEqual(graph['cve'],record['cve']);self.assertTrue(graph['nodes'])
            self.assertEqual(G.evaluate(graph,{})['value'],'unknown')
            self.assertFalse(graph['coverage_complete']);self.assertTrue(graph['assessment_binding_required'])
            self.assertEqual(graph['source_products'],record['products'])

    def test_cross_cve_edge_is_rejected(self):
        bad=deepcopy(self.receipt)
        import csv,io
        rows=list(csv.reader(io.StringIO(bad['files']['VERTICES.CSV'])))
        grouped={}
        import re
        for row in rows:
            symbol=re.search(r'\bn[a-f0-9]{28}\b',row[1])
            if symbol:grouped.setdefault(self.namespace['symbol_owners'][symbol[0]],row[0])
        ids=list(grouped.values());bad['files']['ARCS.CSV']+='\n'+ids[0]+','+ids[1]+',-1\n'
        with self.assertRaisesRegex(ValueError,'Cross-CVE'):B.partition(self.programs,self.merged,self.namespace,bad)

    def test_missing_source_still_generates_an_explicit_unknown_contract(self):
        record=dict(cve='CVE-2000-9999',compiled=dict(questions=[],paths=[],gaps=[]),sources=[],products=[],sha256='missing',source_backing='missing')
        contract=B.contract(record)
        self.assertTrue(contract['nodes']);self.assertTrue(contract['gaps'])
        self.assertFalse(contract['coverage_complete'])
        self.assertIn('fact:unresolved-source-prerequisites',{n['id'] for n in contract['nodes']})

    def test_compressed_storage_preserves_graph_identity_and_rejects_tampering(self):
        graph=M.import_graph(self.contracts[0],self.programs[0],self.parts[0])
        with tempfile.TemporaryDirectory() as folder:
            db=sqlite3.connect(Path(folder)/'graphs.sqlite3')
            db.execute('CREATE TABLE graphs(cve TEXT PRIMARY KEY,payload BLOB,sha256 TEXT,nodes INTEGER,edges INTEGER,gaps INTEGER)')
            B.store(db,self.records[0],graph);db.commit()
            self.assertEqual(B.get(graph['cve'],folder)['sha256'],graph['sha256'])
            db.execute('UPDATE graphs SET sha256=?',('forged',));db.commit()
            with self.assertRaises(ValueError):B.get(graph['cve'],folder)
            db.close()
