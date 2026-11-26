"""Decide from `docker compose ps --all --format json` whether a deployment has finished starting.

`docker compose up --wait` can't be used: it fails as soon as any container exits, even a one-shot
init container (scheduler-init, seaweedfs-init) that exited 0 as intended.
"""

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Container:
    service: str
    state: str  # running, exited, restarting, created, paused, dead, ...
    health: str  # healthy, starting, unhealthy, or "" without a healthcheck
    exit_code: int


@dataclass
class Readiness:
    ready: list[str] = field(default_factory=list)
    # service -> why it isn't ready yet (starting, unhealthy, restarting, created, ...)
    pending: dict[str, str] = field(default_factory=dict)
    # service -> why it failed (exited 1, dead)
    failed: dict[str, str] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.ready) + len(self.pending) + len(self.failed)

    @property
    def done(self) -> bool:
        return not self.pending and not self.failed


def parse_ps(output: str) -> list[Container]:
    """Parse `ps --format json`: one object per line (Compose >= 2.21) or a single JSON array (older)."""
    text = output.strip()
    if not text:
        return []
    if text.startswith("["):
        records = json.loads(text)
    else:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [
        Container(
            service=str(r.get("Service") or r.get("Name") or "?"),
            state=str(r.get("State") or "").lower(),
            health=str(r.get("Health") or "").lower(),
            exit_code=int(r.get("ExitCode") or 0),
        )
        for r in records
    ]


def classify(containers: list[Container]) -> Readiness:
    result = Readiness()
    for c in sorted(containers, key=lambda c: c.service):
        if c.state == "running":
            if c.health in ("", "healthy"):
                result.ready.append(c.service)
            else:
                # "unhealthy" can still recover (e.g. a dependency came up late), so keep waiting
                result.pending[c.service] = c.health
        elif c.state == "exited":
            if c.exit_code == 0:
                result.ready.append(c.service)  # a one-shot container that finished
            else:
                result.failed[c.service] = f"exited {c.exit_code}"
        elif c.state == "dead":
            result.failed[c.service] = "dead"
        else:
            result.pending[c.service] = c.state or "unknown"
    return result


def summarize(r: Readiness, limit: int = 8) -> str:
    """One progress line, e.g. "24/31 ready; waiting on: web-api (starting), ..."."""
    items = [f"{name} ({why})" for name, why in r.pending.items()]
    shown = ", ".join(items[:limit]) + (f", +{len(items) - limit} more" if len(items) > limit else "")
    return f"{len(r.ready)}/{r.total} ready" + (f"; waiting on: {shown}" if items else "")
