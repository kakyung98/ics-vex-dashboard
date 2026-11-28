"""Strict, serializable JSON Schemas for the stage-1 evidence contract."""
from functools import lru_cache
from jsonschema import Draft202012Validator


def obj(properties, required=None):
    return dict(type='object', properties=properties, required=list(properties) if required is None else required,
                additionalProperties=False)


def array(items):
    return dict(type='array', items=items)


STRING = dict(type='string')
NONEMPTY = dict(type='string', minLength=1)
HASH = dict(type='string', pattern='^[0-9a-f]{64}$')
NULLSTRING = dict(type=['string', 'null'])
STRINGS = array(NONEMPTY)
CVESTR = dict(type='string', pattern=r'^CVE-\d{4}-\d{4,}$')
REFERENCE = obj(dict(source_id=NONEMPTY, segment_id=NONEMPTY, start=dict(type='integer', minimum=0),
                     end=dict(type='integer', minimum=1), quote=NONEMPTY, segment_sha256=HASH))


@lru_cache(maxsize=1)
def schemas():
    from src.research.item4_stage1 import CHECKS, PREDICATES, ROLES
    from src.item4.analysis.advisory_source_bundles import VERSION
    segment = obj(dict(id=NONEMPTY, source_id=NONEMPTY, source_json_pointer=NONEMPTY,
                       text=NONEMPTY, text_sha256=HASH,
                       source_role=dict(enum=['cve_description', 'advisory_context', 'mitigation']),
                       cves=array(CVESTR), product_ids=STRINGS, binding_ids=STRINGS))
    product = obj(dict(id=NONEMPTY, native_id=NONEMPTY, name=STRING,
                       ancestry=array(obj(dict(category=STRING, name=STRING))),
                       source_id=NONEMPTY, source_json_pointer=NONEMPTY))
    document = obj(dict(id=NONEMPTY, document_sha256=HASH, filename=STRING,
                        kind=dict(enum=['ICSA_CSAF', 'CVE5', 'NVD_CVE']), advisory_id=STRING,
                        urls=STRINGS, cves=array(CVESTR)))
    binding = obj(dict(id=NONEMPTY, source_id=NONEMPTY, segment_id=NONEMPTY, cve=CVESTR,
                       product_id=NULLSTRING, source_json_pointer=STRING,
                       kind=dict(enum=['explicit_vulnerability_scope', 'advisory_membership_only'])))
    source_log = obj(dict(file=STRING, status=dict(enum=['prepared', 'duplicate_source', 'parse_failed', 'source_unavailable']),
                          source_id=NONEMPTY, document_sha256=HASH, error=STRING,
                          warnings=array(obj(dict(code=dict(const='unresolved_product_ref'), native_id=NONEMPTY)))),
                     required=['file', 'status'])
    bundle = obj(dict(contract_version=dict(const=VERSION), documents=array(document), products=array(product),
                      segments=array(segment), bindings=array(binding), source_ledger=array(source_log),
                      population=array(CVESTR), bundle_sha256=HASH,
                      cve_ledger=array(obj(dict(cve=CVESTR, status=dict(enum=['source_prepared', 'no_cve_specific_passage']),
                                                segment_ids=STRINGS)))))
    claim = obj(dict(id=NONEMPTY, bundle_sha256=HASH, evidence=array(REFERENCE), role=dict(enum=list(ROLES)),
                     statement=NONEMPTY, predicate=dict(enum=list(PREDICATES)), target=NULLSTRING,
                     required_value=NULLSTRING, necessity_scope=dict(const='described_path'),
                     cve=dict(anyOf=[CVESTR, dict(type='null')]), product_ids=STRINGS,
                     binding_ids=STRINGS, normalization_evidence=array(REFERENCE),
                     extractor=NONEMPTY, state=dict(const='candidate'), claim_sha256=HASH))
    processing = obj(dict(segment_id=NONEMPTY,
                          status=dict(enum=['processed_with_candidates', 'processed_no_candidate', 'inference_failed', 'partial']),
                          candidate_ids=STRINGS, full_segment_examined=dict(type='boolean'),
                          semantic_accuracy_verified=dict(const=False)))
    extraction = obj(dict(contract_version=dict(const=VERSION), bundle_sha256=HASH,
                           method=NONEMPTY, candidates=array(claim), processing_ledger=array(processing),
                           logic=dict(type='null'), coverage_complete=dict(const=False),
                           vex_eligible=dict(const=False), semantic_accuracy_verified=dict(const=False),
                           extraction_sha256=HASH))
    review = obj(dict(claim_id=NONEMPTY, claim_sha256=HASH, reviewer=STRING,
                      method=dict(enum=['human', 'model']), reviewed_at=NULLSTRING,
                      decision=dict(enum=['accepted', 'rejected', 'unresolved']),
                      checks=obj({k: dict(enum=['supported', 'unsupported', 'ambiguous']) for k in CHECKS}),
                      rationale=STRING, evidence=array(REFERENCE)))
    gold_claim = obj(dict(role=dict(enum=list(ROLES)), evidence=REFERENCE,
                          cve=dict(anyOf=[CVESTR, dict(type='null')]), product_ids=STRINGS))
    gold_segment = obj(dict(segment_id=NONEMPTY, annotation_complete=dict(const=True),
                            adjudication=dict(enum=['resolved', 'ambiguous']),
                            conditions=array(gold_claim), rationale=NONEMPTY))
    gold = obj(dict(contract_version=dict(const=VERSION), bundle_sha256=HASH,
                    provenance=dict(const='independent_human_annotation'),
                    reviewer_ids=dict(type='array', items=NONEMPTY, minItems=2, uniqueItems=True),
                    model_predictions_seen=dict(const=False), adjudication_note=NONEMPTY,
                    segments=array(gold_segment)))
    result = dict(bundle=bundle, claim=claim, extraction=extraction, review=review, gold=gold)
    for key, schema in result.items():
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        schema['title'] = f'{VERSION} {key}'
        Draft202012Validator.check_schema(schema)
    return result


def validate(kind, value):
    errors = sorted(Draft202012Validator(schemas()[kind]).iter_errors(value),
                    key=lambda e: str(list(e.path)))
    if errors:
        error = errors[0]
        raise ValueError(f'{kind} schema at {list(error.path)}: {error.message}')
