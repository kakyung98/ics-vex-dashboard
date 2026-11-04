"""CLI import bridge for the shared maintained-dataset resolver."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from src.dataset_paths import public_sbom_directory,public_sbom_file,new_public_sbom_directory
