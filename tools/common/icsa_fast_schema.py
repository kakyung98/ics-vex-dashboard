"""Offline compiled validation of the pinned CycloneDX 1.7 schema."""
from pathlib import Path
import json
from functools import lru_cache
import fastjsonschema
from jsonschema import FormatChecker
ROOT=Path(__file__).resolve().parents[2]
class Validator:
    def __init__(self):
        home=ROOT/'data/standards/cyclonedx-1.7'
        store={key:json.loads(p.read_bytes()) for p in home.glob('*.json') for key in
            (p.name,'http://cyclonedx.org/schema/'+p.name,'https://cyclonedx.org/schema/'+p.name)}
        def load(uri):
            key=uri.split('#')[0]
            if key not in store:raise ValueError('Unexpected schema URI: '+uri)
            return store[key]
        checker=FormatChecker()
        @lru_cache(maxsize=65536)
        def conforms(name,value):return checker.conforms(value,name)
        self._validate=fastjsonschema.compile(store['bom-1.7.schema.json'],handlers={'http':load,'https':load},use_default=False,
            formats={name:(lambda value,name=name:conforms(name,value)) for name in checker.checkers})
    def validate(self,document):self._validate(document)