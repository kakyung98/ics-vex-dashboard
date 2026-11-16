"""Local development app with the current advisory SBOM dataset attached.

Run: python -m uvicorn tools.local_dataset_app:app --host 127.0.0.1 --port 8100
The analysis runtime and frozen evaluation inputs remain unchanged.
"""
from src.api_server import app
from tools.icsa_cpe_dataset_web import install

install(app)
