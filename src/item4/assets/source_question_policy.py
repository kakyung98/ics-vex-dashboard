"""Question admission is strict >80 self-reported points, never accuracy proof."""
import math

VERSION='item4-source-question-admission/3-condition-mapped'
THRESHOLD=80
POLICY=dict(version=VERSION,threshold=THRESHOLD,comparison='>',scale='0-100',
    confidence_kind='llm_reported_uncalibrated',missing_or_rejected='unknown',
    requires_source_quote=True,requires_condition_binding=True,
    question_selection='v2_extracted_conditions_only',
    asset_type_generates_questions=False,unmatched_catalogue_condition='keep_source_question',
    confidence_is_accuracy_probability=False,
    extraction_threshold=0.8,extraction_comparison='>',extraction_scale='0-1',
    missing_extraction_confidence='unknown_requires_reextraction')


def admitted(score):
    return type(score) is int and THRESHOLD<score<=100


def extraction_admitted(score):
    return type(score) in (int,float) and math.isfinite(score) and 0.8 < score <= 1
