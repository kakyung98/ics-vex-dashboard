"""Independent role-adapter selection; pending training is never labelled tuned."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parents[3]
CONFIG=ROOT/'data/prerequisite_adapter_roles.json'
ROLES={'exploitation-prerequisites','operating-record-review'}
_BASE_EVALUATION=ContextVar('item4_explicit_base_evaluation',default=False)


@contextmanager
def base_model_evaluation():
    """Explicit, task-local ablation; never edits deployed adapter selection."""
    token=_BASE_EVALUATION.set(True)
    try:yield
    finally:_BASE_EVALUATION.reset(token)


@lru_cache(maxsize=16)
def _hash(path,signature):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def configuration():
    value=json.loads(CONFIG.read_text(encoding='utf-8'))
    if set(value.get('roles',{}))!=ROLES:raise ValueError('Both prerequisite adapter roles must be declared')
    rows=value['roles']
    if any(r['alias']=='default' for r in rows.values()):raise ValueError('Role adapters cannot replace the identification default')
    if len({r['alias'] for r in rows.values()})!=2 or len({r['path'] for r in rows.values()})!=2:
        raise ValueError('Role adapters need distinct aliases and directories')
    return rows


def _evaluation(row, folder, marker, weights_sha):
    """Tie the installed quality gate and any exception to this checkpoint."""
    receipt_path = folder / 'import_receipt.json'
    receipt = json.loads(receipt_path.read_bytes()) if receipt_path.is_file() else {}
    passed = receipt.get('evaluation_passed')
    override = row.get('evaluation_gate_override')
    if ('evaluation_passed' not in receipt and 'evaluation_passed' not in row
            and not override and not marker.get('extraction_policy')):
        # Older research adapters have no pass/fail gate in their import receipt.
        return dict(evaluation_passed=None, evaluation_gate_override=None,
                    experimental_use_approved=False)

    if type(passed) is not bool or row.get('evaluation_passed') is not passed:
        raise ValueError('Adapter evaluation result differs from its import receipt')
    raw = (folder / 'evaluation.json').read_bytes()
    report = json.loads(raw)
    report_sha = hashlib.sha256(raw).hexdigest()
    if (receipt.get('adapter_sha256') != weights_sha or report.get('adapter_sha256') != weights_sha
            or receipt.get('evaluation_sha256') != report_sha or report.get('state') != 'complete'
            or (passed and report.get('passed') is not True)):
        raise ValueError('Evaluation report or evaluated checkpoint fingerprint differs')
    approved = (not passed and override == 'explicit_user_request'
                and receipt.get('user_requested_failed_evaluation_activation') is True)
    if not passed and not approved:
        raise ValueError('Failed adapter evaluation requires an explicit recorded experimental approval')
    if passed and override is not None:
        raise ValueError('Unexpected failed-evaluation override on a passed adapter')
    return dict(evaluation_passed=passed, evaluation_gate_override=override,
                experimental_use_approved=approved, evaluation_sha256=report_sha)


def selected(role):
    if role not in ROLES:raise ValueError('Unknown prerequisite adapter role')
    if role=='exploitation-prerequisites' and _BASE_EVALUATION.get():return None
    row=configuration()[role]
    if row.get('enabled') is not True:return None
    folder=(ROOT/row['path']).resolve()
    extra=json.loads(CONFIG.read_text(encoding='utf-8')).get('storage_roots',[])
    if not isinstance(extra,list) or any(not isinstance(p,str) or not Path(p).is_absolute() for p in extra):
        raise ValueError('Additional adapter storage roots must be explicit absolute paths')
    roots=[(ROOT/'models').resolve()]+[Path(p).resolve() for p in extra]
    if not any(folder.is_relative_to(root) for root in roots):raise ValueError('Adapter path escapes managed model storage')
    marker=json.loads((folder/'training_complete.json').read_text(encoding='utf-8'))
    adapter_config=json.loads((folder/'adapter_config.json').read_text(encoding='utf-8'))
    if Path(adapter_config['base_model_name_or_path']).resolve()!=Path(marker['base']).resolve():
        raise ValueError('Adapter config differs from its recorded base')
    if marker.get('role')!=role or marker.get('optimizer_updates',0)<1:
        raise ValueError('A separately trained role adapter is required')
    weights=folder/'adapter_model.safetensors';stat=weights.stat()
    sha=_hash(str(weights),(stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns))
    if sha!=marker.get('adapter_sha256'):raise ValueError('Role adapter fingerprint changed')
    if not marker.get('train_manifest_sha256'):raise ValueError('Role adapter lacks training-data provenance')
    return dict(role=role,alias=row['alias'],folder=str(folder),sha256=sha,base=marker['base'],
                train_manifest_sha256=marker['train_manifest_sha256'], training_completed=True,
                **_evaluation(row,folder,marker,sha))


def active_roles():
    rows={role:selected(role) for role in sorted(ROLES)}
    active=[r for r in rows.values() if r]
    if len(active)==2 and active[0]['sha256']==active[1]['sha256']:
        raise ValueError('The two roles cannot activate identical adapter weights')
    return rows


def status():
    result=[]
    for role,row in sorted(configuration().items()):
        try:
            spec=selected(role)
            state = row.get('state','disabled')
            if spec:
                state = ('enabled_by_user_request_evaluation_failed' if spec['evaluation_passed'] is False
                         else 'trained_adapter_configured')
            result.append(dict(role=role,enabled=bool(spec),alias=row['alias'],path=row['path'],
                state=state, training_completed=True if spec else None,
                evaluation_passed=spec['evaluation_passed'] if spec else row.get('evaluation_passed'),
                evaluation_gate_override=spec['evaluation_gate_override'] if spec else row.get('evaluation_gate_override'),
                experimental_use_approved=bool(spec and spec['experimental_use_approved']),
                weights_sha256=spec['sha256'] if spec else None))
        except (OSError,ValueError,KeyError) as exc:
            result.append(dict(role=role,enabled=False,state='invalid_adapter',error=str(exc)))
    return result


@contextmanager
def inference_context(runtime,role):
    """Caller owns the shared runtime lock for the entire context and generation."""
    if role in {'item4-questions','exploitation-coverage-review'}:
        # The old question adapter uses a different contract. V3 uses the
        # shared base explicitly, without borrowing the V2 extraction adapter.
        # The separately logged review checks an empty primary extraction;
        # it does not replace the configured primary adapter or its quality gate.
        with runtime.model.disable_adapter():yield None
        return
    spec=active_roles()[role]
    if spec is None:
        with runtime.model.disable_adapter():yield None
        return
    base=next(iter(runtime.model.peft_config.values())).base_model_name_or_path
    if Path(base).resolve()!=Path(spec['base']).resolve():raise ValueError('Role adapter base-model mismatch')
    alias=spec['alias'];previous=runtime.model.active_adapter
    if not isinstance(previous,str):raise ValueError('Expected one active shared adapter')
    if alias not in runtime.model.peft_config:
        runtime.model.load_adapter(spec['folder'],adapter_name=alias,is_trainable=False)
    loaded=getattr(runtime,'_prerequisite_adapter_hashes',{})
    if alias in loaded and loaded[alias]!=spec['sha256']:raise ValueError('Reload runtime after replacing role weights')
    loaded[alias]=spec['sha256'];runtime._prerequisite_adapter_hashes=loaded
    try:
        runtime.model.set_adapter(alias)
        runtime.model.eval()
        yield spec
    finally:
        runtime.model.set_adapter(previous)
