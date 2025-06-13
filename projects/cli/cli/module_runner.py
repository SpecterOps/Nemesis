#!/usr/bin/env python3
import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


def install_poetry_dependencies(module_path: Path):
    """Install module dependencies if pyproject.toml exists."""
    pyproject_path = module_path / "pyproject.toml"

    if not pyproject_path.exists():
        logger.info("No pyproject.toml found, skipping dependency installation")
        return True

    logger.info("Installing dependencies with Poetry...")
    try:
        result = subprocess.run(
            ["poetry", "install", "--no-interaction"], cwd=module_path, capture_output=True, text=True
        )
        if result.returncode != 0:
            logger.error(f"Poetry install failed: {result.stderr}")
            return False
        logger.info("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running Poetry: {e}")
        return False


def run_analyzer(module_path: Path, target_file: Path, use_poetry: bool = True):
    """Run the analyzer with the target file."""
    try:
        command = ["poetry", "run", "python"] if use_poetry else ["python"]
        command.extend(["analyzer.py", str(target_file.absolute())])

        result = subprocess.run(command, cwd=module_path, capture_output=True, text=True)

        if result.returncode != 0:
            logger.error(f"Analyzer execution failed: {result.stderr}")
            return None

        # Try to parse the output as JSON
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error("Failed to parse analyzer output as JSON")
            logger.debug(f"Raw output: {result.stdout}")
            return None

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running analyzer: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Run enrichment module analyzer on a file")
    parser.add_argument(
        "module_path", type=str, help="Path to the module directory (e.g., ./enrichment_modules/dotnet_analyzer)"
    )
    parser.add_argument("target_file", type=str, help="Path to the file to analyze")
    parser.add_argument("--skip-deps", action="store_true", help="Skip Poetry dependency installation")
    parser.add_argument("--no-poetry", action="store_true", help="Run without Poetry (directly with Python)")
    args = parser.parse_args()

    # Convert paths to Path objects and verify they exist
    module_path = Path(args.module_path).resolve()
    target_file = Path(args.target_file).resolve()

    if not module_path.exists() or not module_path.is_dir():
        logger.error(f"Module path does not exist or is not a directory: {module_path}")
        sys.exit(1)

    if not target_file.exists() or not target_file.is_file():
        logger.error(f"Target file does not exist or is not a file: {target_file}")
        sys.exit(1)

    analyzer_path = module_path / "analyzer.py"
    if not analyzer_path.exists():
        logger.error(f"analyzer.py not found in module directory: {analyzer_path}")
        sys.exit(1)

    # Handle Poetry installation if needed
    if not args.no_poetry and not args.skip_deps:
        if not install_poetry_dependencies(module_path):
            logger.error("Failed to install dependencies")
            sys.exit(1)

    # Run the analyzer
    result = run_analyzer(module_path, target_file, use_poetry=not args.no_poetry)
    if result:
        print(json.dumps(result, indent=2))
    else:
        logger.error("Analysis failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
