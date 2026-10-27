from __future__ import annotations

import csv
import json
from collections.abc import Sequence
from pathlib import Path

from aitrace.export.exporter import ExportEntry

MANIFEST_COLUMNS: tuple[str, ...] = (
    "export_path",
    "sha256",
    "size",
    "source_volume",
    "source_path",
    "inode",
    "artifact_ids",
    "deleted",
    "note",
)


def write_manifest(entries: Sequence[ExportEntry], out_dir: Path) -> list[Path]:
    rows = sorted(entries, key=lambda entry: entry.export_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "manifest.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(MANIFEST_COLUMNS)
        for entry in rows:
            writer.writerow(
                [
                    entry.export_path,
                    entry.sha256,
                    entry.size,
                    entry.source_volume,
                    entry.source_path,
                    "" if entry.inode is None else entry.inode,
                    ";".join(entry.artifact_ids),
                    "true" if entry.deleted else "false",
                    entry.note,
                ]
            )
    json_path = out_dir / "manifest.json"
    json_path.write_text(
        json.dumps([entry.to_dict() for entry in rows], ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return [csv_path, json_path]
