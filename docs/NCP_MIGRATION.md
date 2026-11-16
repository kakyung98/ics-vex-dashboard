# NCP ML expert Platform migration

The migrated working system lives in project `hysage`, Notebook `test`, Pod `test-0`, on `h200-04-w-bfb0`.
Its dedicated root is `/home/irteam/data-vol1/ics-vex-migration-20261116`:

JupyterLab's home file browser also contains `ICS-VEX-H200-20261116.ipynb` and the `ICS-VEX-NCP-20261116` project shortcut. Select the `ICS-VEX (H200)` kernel to use the isolated application environment.

- `project`: application code, all current project data, Gold labels, adapters, research and evaluation results.
- `base_model`: the pinned Qwen2.5-Coder-14B 4-bit Hugging Face snapshot.
- `venv`: isolated Python 3.11 / PyTorch 2.11 CUDA 12.8 application environment.
- `incoming`: hash-verified original transfer archives and the operational-tools image/root filesystem.
- `logs`: environment installation, evaluation recomputation and service logs.

The service binds to Pod loopback port 18100. On the local PC, `tools/connect_ncp.ps1` connects the existing project kubeconfig through `kubectl port-forward`. Then open <http://127.0.0.1:18100/precision.html>. The current task has already started this connection in the background. The previous local service on port 8100 remains available.

After a Notebook restart, run this in its Linux terminal:

```sh
/home/irteam/data-vol1/ics-vex-migration-20261116/venv/bin/python /home/irteam/data-vol1/ics-vex-migration-20261116/project/tools/ncp_service.py start
```

Project and workspace PVCs use the platform's `local-path` storage. They persist across this Notebook's restarts but are tied to the storage node. Node loss/migration needs recovery from a separately retained copy. The source PC and original migration archives have been retained.

The transfer inventory checks every included file. SQLite databases use consistent SQLite backups, so their logical contents are preserved while their physical file hashes can differ from the source. Git object history, Python caches, environment files and private key/kubeconfig files are excluded. Hugging Face cache links are dereferenced only into the pinned model's own blobs. Model weights, labels and sealed evaluation code are unchanged. Cloud-only model metadata changes record original Windows paths, new Linux paths and both hashes under `results/cloud_migration/relocation.json`; original metadata is saved separately. Original evaluation artifacts remain in the transfer archive. Recomputed reports are saved separately before restoring sealed files.

Stored #3 and #4 predictions were independently rescored on the cloud; this is not a full GPU inference rerun. Live HTTP acceptance runs the 14B model on six #4 conditional simulation cases and an SBOM through #3, checks their sealed outputs and verifies adapter restoration. Synthetic #4 performance does not establish actual installation impact precision; real-asset precision remains unmeasured.

The Notebook has no Docker daemon. `tools/ncp_operational_runtime.py` runs the same exported OpenSCAP/MulVAL/XSB filesystem using unprivileged PRoot. Each tool receives its own user/network namespace with loopback only, a 120-second deadline, two-CPU affinity, a 16-GiB virtual-address ceiling and an aggregate 2-GiB resident-memory watchdog. A process-local syscall compatibility fallback supports the pinned PRoot version. The cloud launcher installs this backend without editing frozen evaluation modules. Actual OVAL fixture evaluation and MulVAL graph generation were checked; this does not imply field or CVE-semantic validation.

No existing notebooks, GPU jobs, access rules or public endpoints were replaced. No training checkpoint was retrained or selected using evaluation labels.
