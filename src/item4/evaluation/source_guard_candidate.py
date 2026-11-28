"""Experimental lexical guard repair, independent of any benchmark labels.

These patterns do not extract facts. Existing quote, scope, defect and polarity
validators remain mandatory. This candidate is not automatically deployed.
"""
import re

VERSION='source-requirement-language-candidate/2'


def explicit(original):
    return re.compile('(?:'+original.pattern+r')|\b(?:required|necessary)\b',re.I)


def nonrequirement(original):
    return re.compile('(?:'+original.pattern+r')|\bauthentication\s+(?:is|was)\s+not\s+(?:required|necessary)\b',re.I)


def polarity(original):
    def check(item):
        if re.search(r'\bit is not (?:the )?case that\b',item.get('operational_quote',''),re.I):
            # An inner enabled/disabled keyword alone cannot certify the scope
            # of structural negation. Preserve the LLM expression for semantic
            # evaluation instead of asserting an incorrect lexical polarity.
            return None
        return original(item)
    return check
