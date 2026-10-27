"""Download the dissect.target sample files listed in plan Appendix F and write SHA256SUMS."""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

COMMIT = "b983c57245d9e5c09822a59ebe29f0311827205d"
URL_BASE = f"https://media.githubusercontent.com/media/fox-it/dissect.target/{COMMIT}/tests/_data/"
ROOT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "files" / "third_party" / "dissect"

SAMPLES = [
    "plugins/filesystem/ntfs/mft/mft.raw",
    "plugins/filesystem/ntfs/usnjrnl/usnjrnl.bin",
    "plugins/os/windows/log/evtx/Security.evtx",
    "plugins/os/windows/prefetch/MPCMDRUN.EXE-962E6200.pf",
    "plugins/os/windows/sru/SRUDB.dat",
    "plugins/os/windows/amcache/amcache-new.hve",
    "plugins/os/windows/lnk/pestudio.lnk",
    "plugins/os/windows/jumplist/5f7b5f1e01b83767.automaticDestinations-ms",
    "plugins/os/windows/jumplist/590aee7bdd69b59b.customDestinations-ms",
    "plugins/os/windows/powershell/ConsoleHost_history.txt",
    "plugins/apps/browser/chrome/generic/History",
    "plugins/apps/browser/firefox/generic/places.sqlite",
    "plugins/apps/browser/safari/generic/History.db",
    "plugins/apps/remoteaccess/anydesk/file_transfer_trace.txt",
    "plugins/apps/remoteaccess/anydesk/TestAnydesk.trace",
    "plugins/apps/remoteaccess/teamviewer/TestTeamviewer.log",
    "plugins/os/unix/log/journal/system.journal",
]

LFS_POINTER_PREFIX = b"version https://git-lfs"


def main() -> int:
    sums: list[str] = []
    for rel in SAMPLES:
        with urllib.request.urlopen(URL_BASE + rel, timeout=120) as resp:
            data = resp.read()
        if data.startswith(LFS_POINTER_PREFIX):
            print(f"LFS pointer returned instead of content: {rel}", file=sys.stderr)
            return 1
        dest = ROOT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        sums.append(f"{hashlib.sha256(data).hexdigest()}  {rel}")
        print(f"{len(data):>12}  {rel}")
    (ROOT / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print(f"wrote {len(sums)} entries to {ROOT / 'SHA256SUMS'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
