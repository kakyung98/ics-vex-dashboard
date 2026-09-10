# Joern pilot — what a CPG buys Q2/Q3, and what it does not

> Run 2026-09-10 against `data/source_snapshots/CVE-2016-9840/zlib-1.2.8`.
> Joern 4.0.625, Temurin JDK 17 (portable, no admin install).

## Why Joern rather than clang/CodeQL/SVF

This corpus **cannot be built**. The execution-verification runners were removed
in `b4fc1bc8`, so there is no way to produce a `compile_commands.json`, and every
clang-based analyser needs one. Joern's `c2cpg` parses source directly, which is
the only shape of input this repository still has: 104 source trees.

## What it produced

| | |
|---|---|
| CPG build (61 files) | **4.4 s**, 1.4 MB |
| Query run | 10–12 s (JVM warm-up dominates) |
| Methods | 1,185 — 632 defined, 553 external |
| Calls | 32,724 |
| Call resolution | **0.533** |

At this speed all 104 snapshots are practical: the existing tree-sitter pass
already costs tens of seconds per snapshot.

## The one clear win: parsing

```
HAS_inflate            = 1
HAS_inflate_table      = 1
CALLERS_inflate_table  = inflateBack | inflate
```

tree-sitter emits **89 ERROR nodes** on zlib's `inflate.c` because zlib 1.2.8
uses K&R definitions, and loses `inflate` entirely — which made its callees look
unreachable and nearly produced a false `not_affected`. The current pipeline
works around that with a regex scanner (`_scan_regex` in
`tools/callgraph_reach.py`). Joern's Eclipse CDT front end parses K&R natively,
so that workaround becomes unnecessary.

## The thing that does **not** improve: resolution

```
tree-sitter  call_resolution  median 0.67   (gate for a clearance: >= 0.50)
Joern        RESOLUTION       0.533         (zlib)
```

553 of 1,185 methods are external — calls whose definition was never found
because no build supplied the headers. Joern logs the same class of failure
directly:

```
Could not create edge. Destination lookup failed.
  dstFullName = zlib_filefunc_def*.zerror_file
```

**Parsing accuracy and resolution completeness are different axes.** Joern fixes
the first. The second is dominated by the absence of a build, and no front end
recovers it. Macros and conditional compilation stay invisible either way. This
matters because resolution is what gates a clearance: the pilot gives **no
grounds to relax the conservative guards**.

## Q3 as a data-flow question — and its failure mode

Reachability asks "can control get here". CISA's
`vulnerable_code_cannot_be_controlled_by_adversary` asks whether the adversary
**controls** the vulnerable code, which is a taint flow. Joern can express that
(`sink.reachableByFlows(source)`), and the current pipeline cannot.

Run against `inflate_table`:

```
CALLERS          = inflateBack | inflate        <- the call path plainly exists
SINK_PARAMS      = type|lens|codes|table|bits|work
FLOWS_FROM_IO    = 0
FLOWS_FROM_API   = 0
```

The call path exists and the data flow does not. zlib passes the caller's buffer
as `z_streamp strm`, stores it in `strm->state`, and `inflate_table` receives
fields of that struct (`state->lens`, `state->codes`). The flow travels **through
struct members**, and the OSS data-flow engine's field sensitivity does not
follow it — the same limitation the `Destination lookup failed` lines report.

**CVE-2016-9840 is a real, exploitable zlib flaw.** So `FLOWS_FROM_API = 0` does
not mean "the adversary cannot control this". It means the engine found no flow.

### The rule this forces

| Joern flow result | What it licenses |
|---|---|
| flows found (`> 0`) | **positive evidence** — keeps the CVE an `affected` candidate; trustworthy |
| no flows (`= 0`) | **no evidence** — may never justify `not_affected`; stays `under_investigation` |

Joern data flow is usable **asymmetrically only**. It does not replace the
tree-sitter reachability pass, which earns its place by over-approximating and
so refusing clearances; it adds a source of confident positives beside it.

## Reproduce

```powershell
$env:JAVA_HOME="C:\Users\user\Desktop\jvm\jdk-17.0.20.1+1"
$env:PATH="$env:JAVA_HOME\bin;$env:PATH"
cd C:\Users\user\Desktop\jvm\joern-cli
.\c2cpg.bat --output ..\zlib.cpg.bin `
  C:\Users\user\Desktop\ICS-VEX\data\source_snapshots\CVE-2016-9840\zlib-1.2.8
.\joern.bat --script ..\q3flow.sc
```

Two platform notes, both cost a run each: the bundled `joern.sh` fails on Windows
with `ClassNotFoundException: ReplBridge` (its classpath assumes a POSIX layout —
use `joern.bat`), and PowerShell splits `--param key=value` on the `=`, so put
the CPG path inside the script instead of passing it as a parameter.

## Verdict

Adopt Joern for what it actually improves:

1. **Replace the K&R/macro regex workaround** with CDT parsing — a correctness
   win in the exact place a false clearance almost occurred.
2. **Add Q3 taint flows as positive evidence**, never as grounds for clearing.

Do not adopt it as a reason to loosen `call_resolution` or any other guard. The
binding limitation is that this corpus has no build, and a better front end does
not change that.
