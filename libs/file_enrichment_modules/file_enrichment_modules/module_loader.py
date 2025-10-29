import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Protocol, runtime_checkable

import asyncpg
from common.logger import get_logger
from common.models import EnrichmentResult

logger = get_logger(__name__)


@runtime_checkable
class EnrichmentModule(Protocol):
    """Protocol defining the interface for enrichment modules.

    All enrichment modules must implement this protocol with async methods.
    """

    name: str
    dependencies: list[str]
    asyncpg_pool: asyncpg.Pool | None  # Optional connection pool for database operations

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should process the given file.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            True if the module should process this file, False otherwise
        """
        ...

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process the file and return enrichment results.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails or is not applicable
        """
        ...


class ModuleLoader:
    def __init__(self, modules_dir: str | None = None):
        if modules_dir is None:
            self.modules_dir = Path(__file__).parent
        else:
            self.modules_dir = Path(modules_dir)
        self.modules: dict[str, EnrichmentModule] = {}

    async def _install_module_deps(self, module_path: Path):
        """Install module dependencies using Poetry if pyproject.toml exists."""
        if (module_path / "pyproject.toml").exists():
            logger.info("Installing dependencies for module", module_path=module_path)
            process = await asyncio.create_subprocess_exec(
                "poetry",
                "install",
                "--no-interaction",
                cwd=module_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error("Failed to install dependencies", stderr=stderr.decode())
                raise RuntimeError(f"Dependency installation failed: {stderr.decode()}")

            logger.info("Successfully installed dependencies", module_path=module_path)

    async def _load_module(self, module_dir: Path):
        """Load a single module and its dependencies."""
        module_path = module_dir / "analyzer.py"
        if not module_path.exists():
            return

        # logger.info("Loading enrichment module", path=module_path)
        # print just the path
        logger.info("Loading enrichment module", path=module_path.as_posix())

        # Install dependencies if needed
        await self._install_module_deps(module_dir)

        # Load the module
        try:
            spec = importlib.util.spec_from_file_location(f"{__package__}.{module_dir.name}", module_path)
            module = importlib.util.module_from_spec(spec)

            # Add module directory to Python path if it's not already there
            if str(module_dir.parent) not in sys.path:
                sys.path.insert(0, str(module_dir.parent))

            spec.loader.exec_module(module)

            # Initialize the enrichment module
            if hasattr(module, "create_enrichment_module"):
                self.modules[module_dir.name] = module.create_enrichment_module()
                logger.info("Successfully loaded module", module_name=module_dir.name)
            else:
                logger.warning("Module does not have create_enrichment_module()", module=module_dir.name)
        except Exception:
            logger.exception(message="Failed to load module", module_name=module_dir.name)
            raise

    async def load_modules(self):
        """Dynamically load all enrichment modules."""
        logger.info(
            "Starting module loading process",
            modules_dir=self.modules_dir.absolute().as_posix(),
        )
        for module_dir in self.modules_dir.iterdir():
            if not module_dir.is_dir():
                continue

            await self._load_module(module_dir)

        logger.info(f"Loaded {len(self.modules)} modules successfully")
