# windows.E01

Synthetic Windows NTFS image for scenario C.1 (user `kim`, volume label `WINFIX`, case `AITRACE-WIN`, evidence `WIN-001`).
`secret_plan.txt` was created and then deleted, so a deleted MFT record remains.

Rebuild (needs docker with a running daemon, and `ewfacquire`; exits 2 with a message otherwise):

```
.venv/bin/python tools/fixtures/build_windows.py
```

The builder stages the tree, then runs:

```
docker run --rm --privileged -v <stage_parent>:/w debian:bookworm-slim bash -c "apt-get -qq update && apt-get -qq install -y ntfs-3g >/dev/null && truncate -s 48M /w/windows.raw && mkntfs -q -F -f -L WINFIX /w/windows.raw && mkdir /mnt/n && ntfs-3g /w/windows.raw /mnt/n && cp -a /w/stage/. /mnt/n/ && rm /mnt/n/Users/kim/Documents/secret_plan.txt && umount /mnt/n"
ewfacquire -u -t tests/fixtures/images/windows -f encase6 -c deflate:fast -C AITRACE-WIN -D "aitrace windows fixture" -E WIN-001 -e aitrace -N fixture -d sha256 -q windows.raw
```

sha256 of `windows.E01`: `0e4842d655f58fa29143933b22d79d70ee5a8ff1fa874a8643d094abcb902272`

The E01 embeds the acquisition time, so a rebuild changes this hash; the planted-file set stays identical.
