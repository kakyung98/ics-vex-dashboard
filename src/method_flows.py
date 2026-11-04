"""Compact methodology maps; implementation detail lives in disclosures below."""
from html import escape

STYLE = '''<style>
.method-flow{container:methodFlow / inline-size;max-width:1120px;margin:24px 0 30px;font-family:var(--sans);color:var(--ink)}
.method-flow figcaption{margin-bottom:18px}.method-flow figcaption h2{font-size:22px;margin:0 0 8px}
.method-flow figcaption p{font-size:16px;line-height:1.5;color:var(--ink2);margin:0}
.method-flow .mf-key{display:flex;flex-wrap:wrap;align-items:center;gap:8px 20px;margin:16px 0 22px;font-size:14px;color:var(--ink2)}
.method-flow .mf-key b{color:var(--ink);font-weight:600}.method-flow .mf-key .mf-key-llm{color:var(--accent)}
.method-flow .mf-step{position:relative;display:flex;flex-direction:column;justify-content:center;gap:7px;min-width:0;min-height:108px;padding:16px 18px;border:1px solid var(--line);border-radius:9px;background:var(--card)}
.method-flow .mf-kind{display:block;font-size:12px;font-weight:700;line-height:1.3;color:var(--ink2);letter-spacing:.025em}
.method-flow .mf-title{display:block;font-size:18px;font-weight:600;line-height:1.3;color:var(--ink);overflow-wrap:anywhere}
.method-flow .mf-sub{display:block;font-size:14px;line-height:1.4;color:var(--ink2);overflow-wrap:anywhere}
.method-flow [data-role="llm"].mf-step{border-top:3px solid var(--accent);background:color-mix(in srgb,var(--accent) 5%,var(--card))}
.method-flow [data-role="llm"]>.mf-kind,.method-flow .mf-inline-llm{color:var(--accent)}
.method-flow [data-role="human"]>.mf-kind{color:var(--und)}
.method-flow .mf-rail{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:30px}
.method-flow .mf-rail>.mf-step:not(:last-child)::after{content:'→';position:absolute;right:-27px;top:50%;transform:translateY(-50%);font-size:22px;color:var(--ink3);width:24px;text-align:center}
.method-flow .mf-down{position:relative;width:1px;height:20px;margin:7px auto;background:var(--ink3)}
.method-flow .mf-down::after{content:'';position:absolute;bottom:-1px;left:-4px;border-left:4px solid transparent;border-right:4px solid transparent;border-top:6px solid var(--ink3)}
.method-flow .mf-entry{max-width:460px;margin:0 auto;text-align:center}
.method-flow .mf-fork-title{text-align:center;font-size:15px;font-weight:600;color:var(--ink);margin:16px 0 12px}
.method-flow .mf-lanes{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:28px;border-top:1px solid var(--line);padding-top:16px}
.method-flow .mf-lane{min-width:0}.method-flow .mf-lane h3{font-size:17px;color:var(--ink);margin:0 0 12px;line-height:1.4}
.method-flow .mf-lane h3 small{font-size:13px;color:var(--ink2);font-weight:400;margin-left:8px}
.method-flow .mf-lane .mf-step{min-height:100px}.method-flow .mf-lane .mf-down{height:14px;margin:5px auto}
.method-flow .mf-join{height:16px;width:50%;margin:12px auto 0;border:1px solid var(--line);border-top:0}
.method-flow .mf-gate{max-width:660px;margin:0 auto;padding:13px 18px;text-align:center;border:1px dashed var(--ink3);border-radius:8px}
.method-flow .mf-gate .mf-title{margin:5px 0}.method-flow .mf-gate .mf-sub{font-size:14px}
.method-flow .mf-side-note{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:7px 12px;margin:14px 0;font-size:14px;line-height:1.5;color:var(--ink2)}
.method-flow .mf-side-note strong{font-weight:600;color:var(--ink)}
.method-flow .mf-foot{display:flex;justify-content:space-between;align-items:start;gap:14px;flex-wrap:wrap;margin-top:20px;font-size:14px;line-height:1.5;color:var(--ink2)}
.method-flow .mf-foot p{margin:0;max-width:75ch}.method-flow .mf-foot a{white-space:normal}
.method-flow .mf-explanation{font-size:16px;line-height:1.6;color:var(--ink2);max-width:85ch;margin:14px 0}
.method-flow .mf-explanation summary{cursor:pointer;color:var(--accent);padding:6px 0}.method-flow .mf-explanation p{margin:8px 0}
.method-flow .mf-explanation code{color:var(--ink);font-size:14px}
details.method-details{max-width:1120px;margin:24px 0;border-top:1px solid var(--line)}
details.method-details>summary{cursor:pointer;padding:20px 0;font-size:17px;font-weight:600;color:var(--ink)}
details.method-details .method-detail-body{max-width:88ch}
details.method-details .card{background:transparent;border:0;border-top:1px solid var(--line);border-radius:0;padding:22px 0;margin:0}
details.method-details h2{font-size:21px;line-height:1.4;margin:0 0 10px}details.method-details h3{font-size:19px;margin:0 0 10px}
details.method-details p,details.method-details li{font-size:16px;line-height:1.7;color:var(--ink2)}
.method-notes{max-width:76ch;margin:36px 0;font-family:var(--sans)}
.method-notes h2{font-size:24px;margin:0 0 18px;line-height:1.35}.method-notes h3{font-size:21px;margin:0 0 14px;line-height:1.35}
.method-notes .method-topic{padding:26px 0;border-top:1px solid var(--line)}
.method-notes dl{display:grid;grid-template-columns:160px minmax(0,1fr);gap:12px 24px;margin:14px 0}
.method-notes dt{font-size:14px;font-weight:600;color:var(--ink2);line-height:1.6;overflow-wrap:anywhere}
.method-notes dd{font-size:17px;line-height:1.6;color:var(--ink);margin:0;overflow-wrap:anywhere}
.method-notes p,.method-notes li{font-size:16px;line-height:1.65;color:var(--ink2)}
.method-notes code{font-family:var(--mono);font-size:13px;overflow-wrap:anywhere;color:var(--ink)}
.method-notes .method-boundary{border-left:2px solid var(--line);padding-left:14px;margin:18px 0 0}
.method-notes .method-example{padding:12px 0;font-size:14px}.method-notes .method-example b{color:var(--accent)}.method-notes .method-example p{margin:6px 0}
.method-notes .method-extra{border-top:1px solid var(--line);padding:16px 0}.method-notes .method-extra summary{font-size:17px;font-weight:600;cursor:pointer;color:var(--ink)}
.method-notes .method-extra li{margin:10px 0}.method-notes .method-extra ul{padding-left:22px}
@media(max-width:580px){.method-notes dl{grid-template-columns:1fr;gap:5px}.method-notes dd{margin-bottom:12px}.method-notes h3{font-size:20px}}
@container methodFlow (max-width:640px){
 .method-flow .mf-rail,.method-flow .mf-lanes{grid-template-columns:1fr}
 .method-flow .mf-rail{gap:26px}.method-flow .mf-lanes{gap:24px}
 .method-flow .mf-rail>.mf-step:not(:last-child)::after{content:'↓';right:auto;left:50%;top:auto;bottom:-25px;transform:translateX(-50%)}
 .method-flow .mf-step{min-height:96px}.method-flow .mf-join{display:none}
}
@media(max-width:480px){.method-flow .mf-title{font-size:17px}.method-flow .mf-step{padding:14px}.method-flow .mf-foot{display:block}.method-flow .mf-foot a{display:inline-block;margin-top:10px}}
</style>'''


def node(title,subtitle='',role='code',label=None):
    from src.ui_theme import nav_icon
    label=label or {'code':'Evidence check','llm':'LLM assistance','human':'Your input','data':'Input / output'}[role]
    icon=nav_icon({'code':'vex-decision','llm':'analyzer','human':'ics-sbom','data':'dataset'}[role])
    return (f'<div class="mf-step" data-role="{escape(role)}"><span class="mf-kind">{icon}{escape(label)}</span>'
            f'<strong class="mf-title">{escape(title)}</strong>'
            +(f'<span class="mf-sub">{escape(subtitle)}</span>' if subtitle else '')+'</div>')


DOWN='<div class="mf-down" aria-hidden="true"></div>'


def chain(*steps):
    return DOWN.join(steps)


def rail(*steps):
    return '<div class="mf-rail">'+''.join(steps)+'</div>'


def lanes(left_title,left,right_title,right):
    return ('<div class="mf-lanes"><section class="mf-lane"><h3>'+left_title+'</h3>'+left
            +'</section><section class="mf-lane"><h3>'+right_title+'</h3>'+right
            +'</section></div><div class="mf-join" aria-hidden="true"></div>')


def header(identifier,title,subtitle):
    return (STYLE+f'<figure class="method-flow" id="{identifier}" aria-labelledby="{identifier}-title">'
            +f'<figcaption><h2 id="{identifier}-title">{title}</h2><p>{subtitle}</p></figcaption>'
            +'<div class="mf-key"><span><b class="mf-key-llm">LLM</b> model inference</span>'
            +'<span><b>Evidence checks</b> code-based validation</span><span><b>Your input</b> asset facts</span></div>')


def identification_flow():
    return header('sbom-cve-flow','How your SBOM becomes a CVE shortlist','Follow the product, version and identity checks. Open a stage below for the technical detail.')+(
        '<div class="mf-entry">'+node('SBOM','Original names, identifiers and versions','data','INPUT')+'</div>'+DOWN
        +rail(node('L2 · Find product candidates','Original names + dictionary retrieval','code','RULES'),
              node('L3 · Preserve the version','Source / revision / conflict checks','code','RULES'),
              node('L4 · Verify the product','Unique dictionary identity + original evidence','code','RULES'))
        +DOWN+'<div class="mf-gate"><span class="mf-kind">CODE · SHARED EVIDENCE GATES</span>'
        +'<strong class="mf-title">Require original evidence and a unique identity</strong>'
        +'<span class="mf-sub">Keep competing identities, version conflicts and unsupported claims unresolved.</span></div>'+DOWN
        +rail(node('Query NVD & CISA','Product-level candidates; version checks remain explicit'),
              node('Link CVEs to components','Retain case IDs and all stage checks'),
              node('Continue to VEX review','Candidate matches are not exploitability findings','data','HANDOFF'))
        +'<div class="mf-foot"><p>Identification uses deterministic rules. Only final VEX explanation writing uses an LLM.</p>'
        +'<a href="vex-decision.html#vex-review-flow">CVE → VEX workflow →</a></div></figure>')


def vex_flow():
    source=chain(
        node('Is the required source supplied?', 'No → under_investigation immediately'),
        node('Extract targets & inspect builds', 'Literal source spans + patch / build checks', 'code', 'RULES'),
        node('Clang / LLVM analysis', 'Target presence · CFG / call paths · scope blockers'))
    operational=chain(
        node('Extract supported conditions', 'Pattern matches with original source spans', 'code', 'RULES'),
        node('Common + specific questions', 'CWE-specific source-linked templates', 'code', 'RULE TEMPLATES'),
        node('Answers & assessment', 'Operator facts + deterministic evidence gates', 'human', 'USER + RULES'))
    return header('vex-review-flow','From a candidate to a VEX assessment','Five workflows share one CVE review. Source and operating evidence can be required together.')+(
        rail(node('CVE cases', 'Component-linked candidates', 'data', 'INPUT'),
             node('Resolve CWE → Pillars', 'Pinned official hierarchy; keep every path'),
             node('Determine analysis need', 'Specific CWE + CVE / advisory evidence'))
        +'<aside class="mf-side-note"><strong>Unresolved routing → under_investigation.</strong>'
        +'<span>Project policy predictions; independent adjudication pending.</span></aside>'
        +'<div class="mf-fork-title">Which evidence is required?</div>'
        +lanes('Yes <small>Source required</small>',source,'No <small>Operator review</small>',operational)
        +'<div class="mf-explanation"><ol><li><strong>Source only:</strong> supplied source → build / path analysis.</li>'
        +'<li><strong>Source → operating context:</strong> source analysis → required exposure, authentication or configuration records.</li>'
        +'<li><strong>Required source missing:</strong> under_investigation; operator reports cannot bypass the requirement.</li>'
        +'<li><strong>Operating context → source:</strong> reported custom implementation → required source analysis.</li>'
        +'<li><strong>Operating context only:</strong> supported rule questions → operating and installed-build records.</li></ol>'
        +'<p>Both evidence branches retain the same case ID. A missing required branch or conflicting conclusions keeps the case under investigation. The writer runs after evidence collection; identical evidence is not authored again.</p></div>'
        +DOWN+'<div class="mf-gate"><span class="mf-kind">CODE · EVIDENCE GATES</span>'
        +'<strong class="mf-title">Lock status, evidence &amp; scope</strong>'
        +'<span class="mf-sub">Source-required cases cannot bypass missing source through operator answers.</span></div>'+DOWN
        +rail(node('Write the explanation', 'After evidence analysis; keep assigned status', 'llm', 'LLM · TUNED'),
              node('Validate the draft', 'JSON · IDs · citations · repetition'),
              node('Merge & export', 'Original SBOM + VEX · OpenVEX · CSAF', 'data', 'OUTPUT'))
        +'<details class="mf-explanation"><summary>What happens when evidence is missing?</summary>'
        +'<p>Initially missing required source or unresolved routing produces a code-only under_investigation statement. If an operating review later discovers a source requirement, its existing answers are retained while the case waits for source. Source-required cases that also need operating context enter the questionnaire after source analysis. Unknown answers remain unknown; completing a form does not prove exploitability.</p></details>'
        +'<div class="mf-foot"><p>Code assigns the standard status. LLM output remains a review draft. A rejected explanation does not erase the evidence.</p>'
        +'<a href="sbom-to-cve.html#sbom-cve-flow">← SBOM → CVE workflow</a></div></figure>')
