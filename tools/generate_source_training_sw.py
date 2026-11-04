"""Generate family-separated training/validation source fixtures; freeze test100."""
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/source_training_sw"
TEST = ROOT / "evaluation/virtual_sw_100"
SCENARIOS = ("dependency_absent", "feature_disabled", "uncalled_handler", "reachable", "guarded")


def put(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def dump(path, value):
    put(path, json.dumps(value, indent=2, ensure_ascii=False)+"\n")


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_inventory():
    return {p.relative_to(TEST).as_posix():checksum(p) for p in sorted(TEST.rglob('*')) if p.is_file() and 'build' not in p.relative_to(TEST).parts}


def dependency(cve, key, component, version):
    parent = ROOT / 'data/source_snapshots' / cve
    source = next(p for p in parent.iterdir() if p.is_dir())
    dest = OUT / 'vendor' / key
    shutil.copytree(source, dest, ignore=shutil.ignore_patterns('.git', '__pycache__', 'build'))
    files = [{'file':p.relative_to(OUT).as_posix(),'original':(source/p.relative_to(dest)).relative_to(ROOT).as_posix(),'sha256':checksum(p)} for p in sorted(dest.rglob('*')) if p.is_file()]
    return {'component':component,'version':version,'snapshot_cve':cve,'source_root':source.relative_to(ROOT).as_posix(),'vendor_root':dest.relative_to(OUT).as_posix(),'files':files}


def training_adapter():
    return '''#include "runtime.h"
#include <curl/curl.h>
int encode_record(const Record *record) {
    CURL *session = curl_easy_init();
    char *encoded;
    size_t size;
    if (!session) return 3;
    size = strlen(record->payload);
    encoded = curl_easy_escape(session, record->payload, (int)size);
    if (!encoded) { curl_easy_cleanup(session); return 3; }
    printf("library=libcurl encoded=%lu channel=%u\\n", (unsigned long)strlen(encoded), record->channel);
    curl_free(encoded);
    curl_easy_cleanup(session);
    return 0;
}
'''


def validation_adapter():
    return '''#include "frame.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
int decode_frame(const Frame *frame) {
    xmlDocPtr document = xmlReadMemory(frame->xml, (int)strlen(frame->xml), "memory.xml", NULL, XML_PARSE_NONET);
    xmlNodePtr root;
    if (!document) return 2;
    root = xmlDocGetRootElement(document);
    printf("library=libxml2 root=%s slot=%u\\n", root ? (const char *)root->name : "empty", frame->slot);
    xmlFreeDoc(document);
    return 0;
}
'''


def make_case(split, n, profile, style, scenario, dep):
    train = split == 'train'
    case = ('TR' if train else 'VA') + f'{n:04d}'
    path = OUT / split / 'projects' / case
    linked = scenario not in ('dependency_absent','feature_disabled')
    disabled = scenario == 'feature_disabled'
    feature = int(not disabled)
    if train:
        header, typename, field, api, hook = 'runtime.h','Record','payload','curl_easy_escape','encode_record'
        struct = 'typedef struct { unsigned channel; unsigned sequence; const char *payload; } Record;'
        put(path/header, '#ifndef TRAIN_RUNTIME_H\n#define TRAIN_RUNTIME_H\n#include <stdio.h>\n#include <string.h>\n#include "config.h"\n'+struct+'\nint dispatch_record(const Record *record);\nint encode_record(const Record *record);\nunsigned record_checksum(const Record *record);\n#endif\n')
        put(path/'record.c', '#include "runtime.h"\nunsigned record_checksum(const Record *record) {\n    unsigned value=record->channel + record->sequence;\n    const unsigned char *p=(const unsigned char *)record->payload;\n    while (*p) { value=(value << 1) ^ *p; ++p; }\n    return value;\n}\n')
        if scenario=='dependency_absent':
            pipeline='int dispatch_record(const Record *record) { printf("local checksum=%u\\n", record_checksum(record)); return 0; }\n'
        else:
            guard='    if (strlen(record->payload) > PAYLOAD_LIMIT) { puts("rejected"); return 4; }\n' if scenario=='guarded' else ''
            choices=[
                '    const Record *queue[2] = {record, record};\n    unsigned i; int status=0;\n    for (i=0;i<2 && status==0;++i) status=encode_record(queue[i]);\n    return status;\n',
                '    unsigned state=0; int result=0;\n    while (state<2) { switch(state) { case 0: state=1; break; default: result=encode_record(record); state=2; break; } }\n    return result;\n',
                '    int (*callback)(const Record *)=encode_record;\n    return callback(record);\n',
                '    if (record_checksum(record) % 2) return encode_record(record);\n    return encode_record(record);\n']
            pipeline='int dispatch_record(const Record *record) {\n#if FEATURE_ENCODER\n'+guard+choices[style]+'#else\n    (void)record; puts("feature=disabled"); return 0;\n#endif\n}\n'
        put(path/'pipeline.c','#include "runtime.h"\n'+pipeline)
        put(path/'library.c',training_adapter())
        sample=f'line={profile};state=normal;sample={n};mode=archive'
        invoke='printf("idle checksum=%u\\n",record_checksum(&record)); return 0;' if scenario=='uncalled_handler' else 'return dispatch_record(&record);'
        put(path/'main.c',f'''#include "runtime.h"
int main(int argc, char **argv) {{
    Record record;
    record.channel={profile}; record.sequence={n};
    record.payload=argc>1 ? argv[1] : {json.dumps(sample)};
    if(strlen(record.payload)>256) return 5;
    printf("case={case} channel=%u\\n",record.channel);
    {invoke}
}}
''')
        put(path/'config.h',f'#define FEATURE_ENCODER {feature}\n#define PAYLOAD_LIMIT {140+profile%40}\n')
        sources='main.c record.c pipeline.c' + (' library.c' if linked else '')
        target='CURL::libcurl'
        architecture=f'train-record-pipeline-{style}'
    else:
        header, typename, field, api, hook = 'frame.h','Frame','xml','xmlReadMemory','decode_frame'
        put(path/'frame.h','''#ifndef VALIDATION_FRAME_H
#define VALIDATION_FRAME_H
#include <stdio.h>
#include <string.h>
#include "config.h"
typedef struct { const char *xml; unsigned slot; int accepted; } Frame;
int process_frame(Frame *frame);
int decode_frame(const Frame *frame);
int check_frame(const Frame *frame);
#endif
''')
        put(path/'policy.c','''#include "frame.h"
int check_frame(const Frame *frame) {
    size_t count=strlen(frame->xml);
    if(count==0) return 0;
    return count<=FRAME_LIMIT;
}
''')
        if scenario=='dependency_absent':
            body='int process_frame(Frame *frame) { printf("local slot=%u\\n",frame->slot); return 0; }\n'
        else:
            guard='    if(!check_frame(frame)) { puts("rejected"); return 4; }\n' if scenario=='guarded' else ''
            body='int process_frame(Frame *frame) {\n#if FEATURE_DECODER\n'+guard+'    frame->accepted=1;\n    return decode_frame(frame);\n#else\n    (void)frame; puts("feature=disabled"); return 0;\n#endif\n}\n'
        put(path/'consumer.c','#include "frame.h"\n'+body)
        put(path/'library.c',validation_adapter())
        sample=f'<frame slot="{profile}" seq="{n}"><value>42</value></frame>'
        invocation='printf("idle slot=%u\\n",frame.slot); return 0;' if scenario=='uncalled_handler' else 'return process_frame(&frame);'
        put(path/'main.c',f'''#include "frame.h"
int main(int argc, char **argv) {{
    Frame frame={{0}};
    frame.slot={profile};
    frame.xml=argc>1 ? argv[1] : {json.dumps(sample)};
    if(strlen(frame.xml)>256) return 5;
    printf("case={case} slot=%u\\n",frame.slot);
    {invocation}
}}
''')
        put(path/'config.h',f'#define FEATURE_DECODER {feature}\n#define FRAME_LIMIT {140+profile%40}\n')
        sources='main.c policy.c consumer.c' + (' library.c' if linked else '')
        target='LibXml2::LibXml2'
        architecture='validation-dom-frame'
    cm=f'add_executable({case} {sources})\ntarget_include_directories({case} PRIVATE "${{CMAKE_CURRENT_SOURCE_DIR}}")\n'
    if linked:cm+=f'target_link_libraries({case} PRIVATE {target})\n'
    cm+=f'''if(MSVC)
  target_compile_options({case} PRIVATE /Od /Ob0 /GL-)
  target_link_options({case} PRIVATE /OPT:NOREF /INCREMENTAL:NO "/MAP:${{CMAKE_BINARY_DIR}}/maps/{case}.map")
endif()
set_target_properties({case} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/bin")
add_test(NAME {case}_smoke COMMAND {case})
'''
    put(path/'CMakeLists.txt',cm)
    put(path/'sample.txt',sample+'\n')
    dump(path/'sbom.json',{'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'metadata':{'component':{'type':'application','name':case,'version':'0.1.0-synthetic'}},'components':[{'type':'library','name':dep['component'],'version':dep['version'],'purl':f"pkg:generic/{dep['component']}@{dep['version']}"}] if linked else []})
    dump(path/'candidate_input.json',{'product':case,'cves':[dep['snapshot_cve']],'association':'snapshot metadata; affected state not asserted'})
    dump(path/'build_context.json',{'entry_points':['main'],'profile':'windows-msvc-x64-static-debug','build_recipe':'CMakeLists.txt','input':'argv[1] or embedded benign sample','network_requests':False})
    put(path/'README.md',f'# {case}\n\nGenerated local program. Build from the source_training_sw root.\nDefault input is benign; argv[1] can replace it. No network request is issued.\n')
    return {'id':case,'split':split,'source_path':path.relative_to(OUT).as_posix(),'profile':profile,'template_group':architecture,'scenario':scenario,'component':dep['component'],'version':dep['version'],'dependency_linked':linked,'application_api':api,'api_reachable_from_main':linked and scenario!='uncalled_handler','guard_present':scenario=='guarded','guard_is_cve_mitigation_proof':False,'cve_exploitability_asserted':False,'cve_oracle':{'status':'not_affected','justification':'component_not_present'} if not linked else None}


def main():
    if OUT.exists():raise SystemExit(f'Refusing overwrite: {OUT}')
    frozen=test_inventory()
    deps=[dependency('CVE-2023-27537','libcurl_7_88_0','libcurl','7.88.0'),dependency('CVE-2023-39615','libxml2_2_11_0','libxml2','2.11.0')]
    rows=[]
    for profile in range(1,41):
        for style in range(4):
            for scenario in SCENARIOS:rows.append(make_case('train',len(rows)+1,profile,style,scenario,deps[0]))
    for profile in range(1,21):
        for scenario in SCENARIOS:rows.append(make_case('validation',len(rows)-799,profile,0,scenario,deps[1]))
    # Disable optional dependencies so test-family code does not enter training.
    options=['BUILD_SHARED_LIBS','BUILD_CURL_EXE','BUILD_TESTING','CURL_ENABLE_SSL','CURL_USE_OPENSSL','CURL_USE_LIBSSH2','CURL_USE_LIBSSH','CURL_USE_LIBPSL','USE_LIBIDN2','CURL_BROTLI','CURL_ZSTD','BUILD_MISC_DOCS','BUILD_LIBCURL_DOCS','ENABLE_MANUAL','PICKY_COMPILER','LIBXML2_WITH_ICONV','LIBXML2_WITH_LZMA','LIBXML2_WITH_ZLIB','LIBXML2_WITH_PYTHON','LIBXML2_WITH_PROGRAMS','LIBXML2_WITH_TESTS','LIBXML2_WITH_HTTP','LIBXML2_WITH_FTP','LIBXML2_WITH_MODULES']
    cm='cmake_minimum_required(VERSION 3.20)\nproject(ICSVEX_Source_Training C)\nset(CMAKE_C_STANDARD 99)\nset(CMAKE_EXPORT_COMPILE_COMMANDS ON)\n'
    cm+=''.join(f'set({key} OFF CACHE BOOL "Controlled fixture build" FORCE)\n' for key in options)
    cm+='set(CMAKE_DISABLE_FIND_PACKAGE_ZLIB TRUE)\nset(CURL_DISABLE_LDAP ON CACHE BOOL "" FORCE)\nset(CURL_DISABLE_LDAPS ON CACHE BOOL "" FORCE)\n'
    cm+='add_subdirectory(vendor/libcurl_7_88_0 deps/libcurl EXCLUDE_FROM_ALL)\nadd_subdirectory(vendor/libxml2_2_11_0 deps/libxml2 EXCLUDE_FROM_ALL)\nenable_testing()\nfile(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/maps")\n'
    cm+=''.join(f'add_subdirectory({r["source_path"]})\n' for r in rows)
    put(OUT/'CMakeLists.txt',cm)
    put(OUT/'.gitignore','build/\n')
    dump(OUT/'provenance.json',deps)
    dump(OUT/'oracle/cases.json',rows)
    dump(OUT/'test100_frozen.json',{'root':TEST.relative_to(ROOT).as_posix(),'files':frozen})
    for split in ('train','validation'):
        examples=[]
        for r in rows:
            if r['split']!=split:continue
            examples.append({'id':r['id'],'split':split,'task':'application_source_evidence','input':{'source_path':r['source_path'],'files':[p.relative_to(OUT).as_posix() for p in sorted((OUT/r['source_path']).iterdir()) if p.suffix in ('.c','.h')],'sbom':r['source_path']+'/sbom.json','build_context':r['source_path']+'/build_context.json','build_recipe':r['source_path']+'/CMakeLists.txt'},'target':{'dependency_linked':r['dependency_linked'],'api':r['application_api'],'api_reachable_from_main':r['api_reachable_from_main'],'input_guard_present':r['guard_present']},'scope':'application structure, not CVE exploitability','group_id':f"{r['split']}:{r['profile']}:{r['template_group']}"})
        put(OUT/f'{split}.jsonl',''.join(json.dumps(e)+'\n' for e in examples))
    dump(OUT/'manifest.json',{'schema':'ics-vex-source-training/1','train':800,'validation':100,'test':100,'test_path':TEST.relative_to(ROOT).as_posix(),'ratio':'80:10:10','synthetic':True,'build_verified':False,'split_families':{'train':['libcurl'],'validation':['libxml2'],'test':['zlib','libexpat']},'test_unchanged':test_inventory()==frozen,'labels_are_not_cve_affected_ground_truth':True})
    put(OUT/'README.md','''# Source training fixtures: 800 train / 100 validation / frozen 100 test

Training projects: `train/projects/TR0001`–`TR0800` (libcurl 7.88.0).
Validation projects: `validation/projects/VA0001`–`VA0100` (libxml2 2.11.0).
The existing `evaluation/virtual_sw_100` test suite remains unchanged (zlib/Expat).
Upstream snapshots, original licenses and SHA-256 provenance are under `vendor/`
and `provenance.json`. Source copies are not fabricated dependency implementations.

Build with Windows x64 MSVC/CMake/Ninja from this root. Compile commands and link
maps are generated under `build/`. No application issues network requests.
From the repository root: `python tools/build_virtual_sw.py --suite
data/source_training_sw --expected 900 --log-name source_training_sw`.
Audit split integrity with `python tools/audit_source_training_sw.py`.
Optional zlib, SSL, compression and other third-party integrations are disabled so
the selected training build does not bring test dependency families into its link.

`train.jsonl` and `validation.jsonl` pair source paths with application-structure
targets: dependency linkage, API reachability and guard presence. They are not
ready-made CVE affected/not_affected labels. For linked programs CVE status is not
asserted. The guard does not prove mitigation. These source fixtures are for VEX
source-analysis work, not the L2/L3/L4 SBOM normalization agents' existing training.

There are five scenarios, balanced within each split: dependency absent, feature
disabled, uncalled handler, reachable API, and guarded API. There are four record
pipeline templates in training and a DOM-frame template in validation. They are
controlled synthetic variants, not 900 independently authored production systems.
Family separation and differing templates reduce overlap but do not prove the
absence of all near-duplicate patterns or establish real-world generalization.
Keep oracle/targets out of analyser inputs. Never select checkpoints on test100.
The test suite was already inspected during development, so describe it as a
frozen regression suite; a blind performance claim needs a new independent test.
''')
    assert test_inventory()==frozen
    print('Generated 800 train + 100 validation; frozen test100 unchanged.')


if __name__=='__main__':main()
