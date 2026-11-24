"""Base model whose dumps are JSON-safe by default.

Object IDs are ``uuid.UUID`` and times are aware ``datetime``s on the models; anything that serializes a model for
Dapr, HTTP or pub/sub needs JSON-safe values. Defaulting ``model_dump`` to ``mode="json"`` handles that in one place
instead of at every call site. Ask for ``mode="python"`` explicitly to get the Python objects back.
"""

from typing import Any, Literal

from pydantic import BaseModel


class NemesisModel(BaseModel):
    def model_dump(self, *, mode: Literal["json", "python"] | str = "json", **kwargs: Any) -> dict[str, Any]:  # pyright: ignore[reportIncompatibleMethodOverride]
        return super().model_dump(mode=mode, **kwargs)
