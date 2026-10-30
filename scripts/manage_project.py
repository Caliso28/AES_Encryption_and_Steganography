"""Install or uninstall this project from the current Python environment."""

import argparse
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_NAME = "chiffrement-aes-et-steganographie"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "uninstall"))
    action = parser.parse_args().action

    if action == "install":
        command = [sys.executable, "-m", "pip", "install", "-e", ".[dev]"]
    else:
        command = [sys.executable, "-m", "pip", "uninstall", "-y", PROJECT_NAME]

    return subprocess.run(command, cwd=PROJECT_ROOT, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
