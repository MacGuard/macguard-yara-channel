#!/usr/bin/env python3
"""Entry point of the archive toolset: python3 scripts/archivectl.py <command> ... (see scripts/archive/cli.py)."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from archive.cli import main
if __name__ == '__main__': sys.exit(main())
