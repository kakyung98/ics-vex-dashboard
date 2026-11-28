"""Replacement Item 4 UI; no legacy cluster workbench or fixed-question widgets."""
from pathlib import Path


def widget_parts():
    root=Path(__file__).parent
    return (root/'scoped_vex_review.html').read_text(encoding='utf-8'), '<script>'+(root/'scoped_vex_review_ui.js').read_text(encoding='utf-8')+'</script>'
