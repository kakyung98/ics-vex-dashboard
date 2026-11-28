"""Local development app with the current advisory SBOM dataset attached.

Run: python -m uvicorn tools.common.local_dataset_app:app --host 127.0.0.1 --port 8100
The analysis runtime and frozen evaluation inputs remain unchanged.
"""
import os
from pathlib import Path
os.environ.setdefault('HF_HOME',str(Path(__file__).resolve().parents[3]/'ICS-VEX-support/cache/huggingface'))
from src.common.api_server import app
from tools.item3.icsa_cpe_dataset_web import install

install(app)
