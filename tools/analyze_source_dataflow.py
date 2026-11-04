"""Compile one selected C/C++ unit to IR and retain bounded def-use evidence."""
import argparse,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.clang_source import compiler,inside,frontend_flags
from src.source_dataflow import analyze_ir


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--file',required=True)
    p.add_argument('--source',action='append',default=[],help='Declared input function:parameter-index')
    p.add_argument('--target',action='append',default=[]);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();root=a.root.resolve();source=(root/a.file).resolve();exe=compiler()
    if not inside(source,root) or not source.is_file():raise ValueError('Source must be inside the selected root.')
    if not exe:raise RuntimeError('Clang is unavailable')
    declared=[]
    for item in a.source:
        function,index=item.rsplit(':',1);declared.append({'function':function,'parameter':int(index),'provenance':'caller_declared_not_independently_verified'})
    config={'database':'compile_commands.json','file':a.file,'arguments':['clang','-I',str(root)]}
    flags,rejected=frontend_flags(root,config)
    with tempfile.TemporaryDirectory(prefix='icsvex-dataflow-') as temp:
        ir=Path(temp)/'unit.ll'
        command=[exe,'-S','-emit-llvm','-O0','-g','-fno-discard-value-names','-fno-modules','-fno-implicit-modules',*flags,str(source),'-o',str(ir)]
        run=subprocess.run(command,cwd=root,capture_output=True,timeout=30)
        if run.returncode:
            result={'status':'unknown','negative_proof_enabled':False,'blockers':['compiler_error'],
                    'diagnostics':run.stderr.decode('utf-8','replace')[:8000]}
        elif ir.stat().st_size>32*1024**2:result={'status':'unknown','negative_proof_enabled':False,'blockers':['ir_size_limit']}
        else:result=analyze_ir(ir.read_text(encoding='utf-8'),declared,a.target)
    result.update(source=str(source),compiler=exe,discovery_flags_not_actual_build=True,
                  program_executed=False,uploaded_build_commands_executed=False)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:result.get(k) for k in ['status','nodes','blockers','negative_proof_enabled']},indent=2))


if __name__=='__main__':main()
