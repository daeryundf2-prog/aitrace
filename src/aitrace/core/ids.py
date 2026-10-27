from __future__ import annotations

import uuid

NAMESPACE = uuid.UUID("7f6c2a52-6a0e-4c1b-9a51-2b5f5e0f9a11")


def make_id(*parts: object) -> str:
    return uuid.uuid5(NAMESPACE, "\x1f".join(str(p) for p in parts)).hex
