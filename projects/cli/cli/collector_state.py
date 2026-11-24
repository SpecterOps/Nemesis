import hashlib
import json
from pathlib import Path


def collector_state_path(root: Path | str, framework: str, url: str, project: str, agent_id: str) -> Path:
    """Return a stable, filesystem-safe database path for one collector instance."""
    identity = json.dumps([framework, url.rstrip("/"), project, agent_id], ensure_ascii=True).encode()
    root = Path(root)
    directory = root / f"{framework}-{hashlib.sha256(identity).hexdigest()}"
    if not root.exists():
        # Connector state holds C2 download records; keep a newly created root private to this user.
        root.mkdir(parents=True, mode=0o700)
    return directory
