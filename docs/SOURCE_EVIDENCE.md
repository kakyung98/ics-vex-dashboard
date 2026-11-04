# Source evidence in ICS-VEXForge

The source path is part of the shared pipeline:

`Description extraction -> compiler-backed evidence -> rule decision -> VEX authoring -> output checks`.

The same condition/function extractor and VEX writer also serve the operational-context
path. Each case has one ID, input hashes, raw model outputs, validation checks and a
writer evidence packet. Model output is not a ground-truth label.

Source evidence includes cached patch-hunk observations, declared build metadata,
Clang/LLVM CFG and direct call paths, source/IR hashes, target locations, scope and
analysis blockers. [Compiler scope and limitations](CLANG_SOURCE_REVIEW.md) documents
the implementation. The historical AST backend remains an explicit comparison mode.

An accepted Description quote is still a condition/function candidate. LLM-only
function candidates cannot authorize a negative VEX decision. Compiler failures,
incomplete scope and unresolved calls remain explicit. Reachability alone does not
establish attacker control or actual exploitation.

The rule engine assigns the VEX status. The writer receives that exact decision and
identified evidence. JSON/identifier/decision/citation checks reject invalid output;
semantic correctness still requires review. Failed generation is shown as failed and
is not presented as a successful generated explanation. VEX exports retain accepted
draft explanations and evidence IDs. No separate paper-specific intermediate document
or four-factor priority score is generated.

See [shared model connection](SHARED_VEX_PIPELINE.md) for schemas, safeguards and tests.
