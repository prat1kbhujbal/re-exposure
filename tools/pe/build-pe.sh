#!/usr/bin/env bash
# Build a Windows PE32+ from C on Linux, no gcc-mingw-w64 needed: clang + the
# mingw sysroot (/usr/x86_64-w64-mingw32) + a tiny __chkstk_ms stub. Run the
# result with:  wine64 <out.exe>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sysroot=/usr/x86_64-w64-mingw32
stub="$here/stub"; mkdir -p "$stub"
if [ ! -f "$stub/libgcc.a" ]; then
  clang --target=x86_64-w64-windows-gnu -c "$here/chkstk.s" -o "$stub/chkstk.o"
  ar rcs "$stub/libgcc.a" "$stub/chkstk.o"; ar rcs "$stub/libgcc_eh.a"
fi
clang --target=x86_64-w64-windows-gnu --sysroot="$sysroot" -L "$stub" -o "$2" "$1"
file "$2"
