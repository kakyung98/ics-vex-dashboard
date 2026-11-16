"""Run the migrated service on a private Pod port, with the NCP tool backend."""
from pathlib import Path
import os
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
os.chdir(ROOT)
os.environ.setdefault('HF_HUB_OFFLINE','1')
os.environ.setdefault('TOKENIZERS_PARALLELISM','false')
from tools.ncp_operational_runtime import install
install()
import uvicorn
from src.api_server import app
from tools.ncp_evaluation_metrics import install as install_evaluation_metrics
install_evaluation_metrics(app)
uvicorn.run(app,host='127.0.0.1',port=18100)
