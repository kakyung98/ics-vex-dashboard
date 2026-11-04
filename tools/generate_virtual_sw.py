"""Create 100 synthetic applications using unchanged, locally collected sources.

The oracle describes application structure, not unverified CVE exploitability.
No payloads or simulated dependency implementations are substituted for libraries.
"""
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evaluation/virtual_sw_100"
SCENARIOS = ("dependency_absent", "feature_disabled", "uncalled_handler", "reachable", "guarded")
PROFILES = ("PumpTelemetry", "ValveMonitor", "RTUCollector", "AlarmGateway", "SensorArchive",
            "MeterBridge", "PLCLogger", "FlowStation", "HVACReporter", "AssetCollector")
BINDINGS = (
    ("zlib", "1.2.8", "CVE-2016-9840"),
    ("zlib", "1.2.11", "CVE-2018-25032"),
    ("zlib", "1.2.12", "CVE-2022-37434"),
    ("libexpat", "2.2.0", "CVE-2018-20843"),
    ("libexpat", "2.2.10", "CVE-2022-22822"),
    ("libexpat", "2.4.1", "CVE-2022-25236"),
    ("libexpat", "2.5.0", "CVE-2023-52425"),
)


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def js(path, obj):
    write(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def vendor(index):
    records = []
    for family, version, cve in BINDINGS:
        parent = ROOT / "data/source_snapshots" / cve
        roots = [p for p in parent.iterdir() if p.is_dir()]
        if len(roots) != 1: raise ValueError(f"Ambiguous snapshot root: {cve}")
        source = roots[0] if family == "zlib" else roots[0] / "expat"
        code = source if family == "zlib" else source / "lib"
        key = family + "_" + version.replace(".", "_")
        dest = OUT / "vendor" / key
        copied = []
        for p in sorted(code.iterdir()):
            if p.is_file() and p.suffix in (".h", ".c"):
                target = dest / p.name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, target)
                copied.append({"source": p.relative_to(ROOT).as_posix(), "file": target.relative_to(OUT).as_posix(), "sha256": sha(p)})
        for name in ("LICENSE", "COPYING", "README", "README.md"):
            p = source / name
            if p.exists():
                shutil.copyfile(p, dest / name)
                copied.append({"source": p.relative_to(ROOT).as_posix(), "file": (dest/name).relative_to(OUT).as_posix(), "sha256": sha(p)})
        origin = index[cve]
        candidates = sorted(k for k, r in index.items()
                            if r["component"] == origin["component"] and r["version"] == origin["version"] and r.get("tag") == origin.get("tag"))
        records.append({"id": key, "component": family, "version": version,
                        "snapshot_cve": cve, "upstream": origin["source"], "tag": origin["tag"],
                        "cve_candidates": candidates, "files": copied,
                        "selection": "C/H files needed by the explicit static-library recipe; upstream build scripts/tests are not copied"})
    js(OUT / "provenance.json", records)
    return records


def cmake_libraries(deps):
    text = '''# Generated explicit library recipes; original third-party build scripts are not executed.
set(ZLIB_FILES adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c gzread.c gzwrite.c inflate.c infback.c inftrees.c inffast.c trees.c uncompr.c zutil.c)
if(NOT WIN32)
  message(FATAL_ERROR "This benchmark build profile is Windows/MSVC. Port and validate a separate profile for another platform.")
endif()
'''
    for d in deps:
        key = d["id"]
        text += f'set(DIR_{key} "${{CMAKE_CURRENT_LIST_DIR}}/../vendor/{key}")\n'
        if d["component"] == "zlib":
            sources = " ".join(f'"${{DIR_{key}}}/{p}"' for p in "adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c gzread.c gzwrite.c inflate.c infback.c inftrees.c inffast.c trees.c uncompr.c zutil.c".split())
        else:
            sources = " ".join(f'"${{DIR_{key}}}/{p}"' for p in ("xmlparse.c", "xmlrole.c", "xmltok.c"))
            config = f'''#ifndef EXPAT_CONFIG_H
#define EXPAT_CONFIG_H 1
#define BYTEORDER 1234
#define XML_NS 1
#define XML_DTD 1
#define XML_CONTEXT_BYTES 1024
#define HAVE_MEMMOVE 1
#define HAVE_STDINT_H 1
#define PACKAGE "expat"
#define PACKAGE_VERSION "{d['version']}"
#ifdef _MSC_VER
#define __func__ __FUNCTION__
#endif
#endif
'''
            write(OUT / "config" / key / "expat_config.h", config)
        text += f'add_library({key} STATIC EXCLUDE_FROM_ALL {sources})\n'
        text += f'target_include_directories({key} PUBLIC "${{DIR_{key}}}")\n'
        text += f'target_compile_definitions({key} PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)\n'
        if d["component"] == "libexpat":
            text += f'target_include_directories({key} PRIVATE "${{CMAKE_CURRENT_LIST_DIR}}/../config/{key}")\n'
            text += f'target_compile_definitions({key} PUBLIC XML_STATIC WIN32)\n'
    write(OUT / "cmake/dependencies.cmake", text)


def adapter(family):
    if family == "zlib":
        return '''#include "app.h"
#include <zlib.h>
int adapter_apply(const char *text) {
    unsigned char result[1024];
    uLongf capacity = sizeof(result);
    int status = compress2(result, &capacity, (const Bytef *)text, (uLong)strlen(text), Z_BEST_SPEED);
    printf("library=zlib status=%d bytes=%lu\\n", status, (unsigned long)capacity);
    return status == Z_OK ? 0 : 2;
}
'''
    return '''#include "app.h"
#include <expat.h>
int adapter_apply(const char *text) {
    XML_Parser parser = XML_ParserCreate(NULL);
    enum XML_Status status;
    if (!parser) return 3;
    status = XML_Parse(parser, text, (int)strlen(text), XML_TRUE);
    printf("library=libexpat status=%d\\n", (int)status);
    XML_ParserFree(parser);
    return status == XML_STATUS_OK ? 0 : 2;
}
'''


def generate_case(number, profile, shape, dep, scenario):
    case_id = f"SW{number:03d}"
    project = OUT / "projects" / case_id
    linked = scenario not in ("dependency_absent", "feature_disabled")
    feature = scenario != "feature_disabled"
    api = "compress2" if dep["component"] == "zlib" else "XML_Parse"
    sample = f"station={number};value={10+number};unit=kPa" if dep["component"] == "zlib" else f'<sensor station="{number}" value="{10+number}"/>'
    write(project / "sample.txt", sample + "\n")
    write(project / "app.h", '''#ifndef VIRTUAL_APP_H
#define VIRTUAL_APP_H
#include <stdio.h>
#include <string.h>
#include "app_config.h"
int handle_event(const char *text);
int adapter_apply(const char *text);
typedef int (*event_handler)(const char *);
#endif
''')
    write(project / "app_config.h", f'#define APP_FEATURE {int(feature)}\n#define APP_LIMIT {160 + number % 40}\n#define APP_STATION {number}\n')
    if scenario == "dependency_absent":
        handler = 'int handle_event(const char *text) { printf("local station=%d size=%lu\\n", APP_STATION, (unsigned long)strlen(text)); return 0; }\n'
    else:
        check = '    if (strlen(text) > APP_LIMIT) { puts("rejected"); return 4; }\n' if scenario == "guarded" else ''
        body = 'return adapter_apply(text);'
        prefix = ''
        if shape == 1:
            prefix = '#if APP_FEATURE\nstatic int service(const char *s) { return adapter_apply(s); }\nstatic int route(const char *s) { return service(s); }\n#endif\n'
            body = 'return route(text);'
        elif shape == 2:
            body = 'event_handler dispatch = adapter_apply; return dispatch(text);'
        elif shape == 3:
            body = 'event_handler handlers[2] = {adapter_apply, adapter_apply}; return handlers[APP_STATION % 2](text);'
        elif shape == 4:
            body = 'switch (APP_STATION % 3) { case 0: return adapter_apply(text); case 1: return adapter_apply(text); default: return adapter_apply(text); }'
        handler = prefix + 'int handle_event(const char *text) {\n#if APP_FEATURE\n' + check + '    ' + body + '\n#else\n    (void)text; puts("feature=disabled"); return 0;\n#endif\n}\n'
    write(project / "handler.c", '#include "app.h"\n' + handler)
    write(project / "adapter.c", adapter(dep["component"]))
    invocation = 'printf("idle station=%d size=%lu\\n", APP_STATION, (unsigned long)strlen(text)); return 0;' if scenario == "uncalled_handler" else 'return handle_event(text);'
    main = f'''#include "app.h"
int main(int argc, char **argv) {{
    const char *text = argc > 1 ? argv[1] : {json.dumps(sample)};
    printf("product={profile} id={case_id}\\n");
    if (strlen(text) > 256) return 5;
    {invocation}
}}
'''
    write(project / "main.c", main)
    sources = 'main.c handler.c adapter.c' if linked else 'main.c handler.c'
    cm = f'add_executable({case_id} {sources})\n'
    cm += f'target_include_directories({case_id} PRIVATE "${{CMAKE_CURRENT_SOURCE_DIR}}")\n'
    if linked: cm += f'target_link_libraries({case_id} PRIVATE {dep["id"]})\n'
    cm += f'''if(MSVC)
  target_compile_options({case_id} PRIVATE /Od /Ob0 /GL-)
  target_link_options({case_id} PRIVATE /OPT:NOREF /INCREMENTAL:NO "/MAP:${{CMAKE_BINARY_DIR}}/maps/{case_id}.map")
endif()
set_target_properties({case_id} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/bin")
add_test(NAME {case_id}_smoke COMMAND {case_id})
'''
    write(project / "CMakeLists.txt", cm)
    components = []
    if linked:
        components = [{"type": "library", "bom-ref": dep["id"], "name": "zlib" if dep["component"] == "zlib" else "expat", "version": dep["version"],
                       "purl": f'pkg:generic/{"zlib" if dep["component"] == "zlib" else "expat"}@{dep["version"]}'}]
    js(project / "sbom.json", {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                               "metadata": {"component": {"type": "application", "bom-ref": case_id, "name": profile+"-"+case_id, "version": "0.1.0-synthetic"}}, "components": components})
    # CVEs are candidate questions, not embedded VEX answers.
    js(project / "candidate_input.json", {"product": case_id, "dependency": {"name": dep["component"], "version": dep["version"]}, "cves": dep["cve_candidates"]})
    js(project / "build_context.json", {"profile": "windows-msvc-x64-static-debug", "feature": feature,
                                       "dependency_target": dep["id"], "dependency_linked": linked,
                                       "entry_points": ["main"], "network_services": False, "input": "argv[1] or embedded benign sample"})
    write(project / "README.md", f'# {profile} ({case_id})\n\nSynthetic local application. Build from the suite root with `cmake --build build --target {case_id}`.\nInputs: argv[1], or the embedded benign sample. No network listener.\nSee the suite provenance file for unchanged third-party source origin and license.\n')
    return {"id": case_id, "profile": profile, "component": dep["component"], "version": dep["version"],
            "dependency_id": dep["id"], "scenario": scenario, "call_shape": ("direct", "multi_hop", "function_pointer", "dispatch_table", "switch")[shape],
            "source_path": f"projects/{case_id}", "candidate_cves": dep["cve_candidates"],
            "application_api": api, "api_reachable_from_main": linked and scenario != "uncalled_handler",
            "dependency_linked": linked,
            "guard_present": scenario == "guarded", "guard_is_cve_mitigation_proof": False,
            "cve_oracle": {"status": "not_affected", "justification": "component_not_present", "basis": "controlled synthetic executable has no selected library linked"} if not linked else None,
            "cve_exploitability_asserted": False, "input_path": f"projects/{case_id}", "oracle_must_not_be_analyser_input": True}


def main():
    if OUT.exists(): raise SystemExit(f"Refusing to overwrite existing suite: {OUT}")
    index = json.loads((ROOT / "data/snapshot_index.json").read_text(encoding="utf-8"))
    deps = vendor(index)
    cmake_libraries(deps)
    rows = []
    for family in ("zlib", "libexpat"):
        choices = [d for d in deps if d["component"] == family]
        for i, profile in enumerate(PROFILES):
            dep = choices[i % len(choices)]
            for scenario in SCENARIOS:
                rows.append(generate_case(len(rows)+1, profile, i % 5, dep, scenario))
    cmake = '''cmake_minimum_required(VERSION 3.20)
project(ICSVEX_Virtual_SW_100 C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/maps")
enable_testing()
include(cmake/dependencies.cmake)
'''
    cmake += ''.join(f'add_subdirectory(projects/{r["id"]})\n' for r in rows)
    write(OUT / "CMakeLists.txt", cmake)
    js(OUT / "oracle/cases.json", rows)
    js(OUT / "manifest.json", {"schema": "ics-vex-virtual-sw/1", "synthetic": True, "program_count": len(rows),
                               "dependency_families": ["zlib", "libexpat"], "dependency_builds": len(deps),
                               "candidate_cves": sorted({c for d in deps for c in d["cve_candidates"]}),
                               "not_full_267_cve_coverage": True, "oracle": "oracle/cases.json",
                               "projects": [{"id":r["id"],"path":r["source_path"]} for r in rows],
                               "build_verified": False, "dependency_implementations_are_mocks": False})
    write(OUT / ".gitignore", 'build/\n')
    write(OUT / "README.md", '''# Virtual SW 100 — actual-source VEX fixtures

100 synthetic C applications: 10 product profiles × 2 dependency families × 5 scenarios.
The selected zlib/Expat implementations are copied unchanged from collected snapshots;
they are not stub functions. Seven local dependency builds cover 12 candidate CVEs,
not the complete 267-CVE collection. Original licenses and file hashes are retained.

## Contents

- `projects/SW001` … `SW100`: application sources, build options, benign inputs,
  runtime-dependency SBOM and candidate-CVE questions.
- `vendor/`, `provenance.json`: actual third-party C/H files, licenses and hashes.
- `oracle/cases.json`: structural answers; never feed this file to the analyser.
- `cmake/`, `config/`: explicit Windows/MSVC static-library build recipes.

## Build (Visual Studio x64 Native Tools prompt with CMake and Ninja)

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel 8
ctest --test-dir build --output-on-failure
```

Ninja exports `build/compile_commands.json`. MSVC link maps go under `build/maps/`.
This is a synthetic Windows build profile, not real ICS deployment firmware.
No network listener or CVE exploit payload is generated. Smoke inputs are benign.

## Oracle boundaries

Each scenario has 20 programs: dependency absent, feature disabled at build time,
linked but uncalled handler, reachable API, and reachable API with an input guard.
40 controls do not link the selected library; 60 actually link its collected code.
API reachability is a structural answer, not a claim that a particular vulnerable
operation is reachable. Guards are not assumed to fix the mapped CVEs. For linked
cases no final CVE status is asserted until the actual vulnerability sites and
conditions are independently checked. Candidate associations are corpus metadata,
not ground truth that the selected build is affected. These fixtures are evaluation
material and must not be included in model training as an independent test set.

The programs intentionally share templates and dependencies. They are 100 controlled
fixtures, not 100 independent real-world products. Split by product profile and
dependency version when evaluating; report template/dependency overlap explicitly.
''')
    print(f"Generated {len(rows)} applications at {OUT}")


if __name__ == "__main__": main()
