from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Protocol

from aitrace.core.model import Attribution, Finding

if TYPE_CHECKING:
    from aitrace.db.store import CaseStore


class Analyzer(Protocol):
    name: str
    version: str

    def run(self, store: CaseStore, tz: str) -> Iterator[Finding | Attribution]: ...
