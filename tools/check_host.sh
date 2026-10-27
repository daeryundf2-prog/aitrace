#!/usr/bin/env bash
# Print the path and version of each host tool aitrace needs; exit 1 if any is missing.
set -u

status=0
for tool in mke2fs ewfacquire docker hdiutil git gh; do
  if path=$(command -v "$tool"); then
    case "$tool" in
      ewfacquire) version=$(ewfacquire -V 2>&1 | head -n 1) ;;
      hdiutil) version="macOS $(sw_vers -productVersion 2>/dev/null)" ;;
      *) version=$("$tool" --version 2>&1 | head -n 1) ;;
    esac
    echo "$tool: $path"
    echo "  version: $version"
  else
    echo "$tool: MISSING"
    status=1
  fi
done
exit "$status"
