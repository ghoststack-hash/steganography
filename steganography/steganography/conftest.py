import sys
from pathlib import Path

# Make the src-layout package importable without installing the project.
sys.path.insert(0, str(Path(__file__).parent / "src"))
