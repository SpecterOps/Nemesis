import hashlib
import json
from pathlib import Path


def collector_state_path(root: Path | str, framework: str, url: str, project: str, agent_id: str) -> Path:
    """Return a stable, filesystem-safe database path for one collector instance."""
    identity = json.dumps([framework, url.rstrip("/"), project, agent_id], ensure_ascii=True).encode()
    directory = Path(root) / f"{framework}-{hashlib.sha256(identity).hexdigest()}"
    directory.parent.mkdir(parents=True, exist_ok=True)
    return directory
