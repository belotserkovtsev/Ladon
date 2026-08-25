#!/bin/sh
# Build the Ladon Unbound dynlib (.so) against the unbound running on THIS box.
# The .so is ABI-bound to the unbound version, so we build it here rather than
# shipping a prebuilt one — this is what makes the port survive unbound bumps.
# Idempotent: skips the rebuild only when the .so already matches BOTH the running
# unbound version AND the current module source, so a changed ladon-unbound.c (a
# new release) forces a rebuild even when unbound's version is unchanged.
#
# Usage: build_unbound_module.sh [src.c] [out.so]
set -e

SRC_C="${1:-/usr/local/share/ladon/ladon-unbound.c}"
OUT_SO="${2:-/usr/local/lib/ladon_unbound.so}"
WORK="${TMPDIR:-/tmp}/ladon-unbound-build"
STAMP="${OUT_SO}.unbound-version"   # running unbound version (doctor reads this too)
SRCSTAMP="${OUT_SO}.src-sha"        # sha256 of the source compiled into this .so

[ -f "$SRC_C" ] || { echo "ladon: missing module source $SRC_C" >&2; exit 1; }
command -v cc >/dev/null 2>&1 || { echo "ladon: cc not found (install the base compiler)" >&2; exit 1; }

SRC_HASH=$(sha256 -q "$SRC_C" 2>/dev/null || sha256sum "$SRC_C" 2>/dev/null | awk '{print $1}')

UVER=$(unbound -V 2>&1 | awk '/^Version/{print $2; exit}')
[ -n "$UVER" ] || { echo "ladon: cannot determine unbound version" >&2; exit 1; }

if [ -f "$OUT_SO" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$UVER" ] \
   && [ "$(cat "$SRCSTAMP" 2>/dev/null)" = "$SRC_HASH" ]; then
    echo "ladon: $OUT_SO already built for unbound $UVER (source unchanged)"
    exit 0
fi

echo "ladon: building Unbound dynlib for unbound $UVER ..."
rm -rf "$WORK"; mkdir -p "$WORK"
TARBALL="$WORK/unbound-$UVER.tar.gz"
fetch -o "$TARBALL" "https://nlnetlabs.nl/downloads/unbound/unbound-$UVER.tar.gz" >/dev/null 2>&1 \
    || { echo "ladon: failed to fetch unbound $UVER source" >&2; exit 1; }
tar -C "$WORK" -xzf "$TARBALL"
USRC="$WORK/unbound-$UVER"

# Reuse the installed unbound's own configure flags so the .so matches its ABI;
# drop build-host artifacts and python/swig (swig isn't shipped on the box, and
# the module only touches core structs unaffected by it).
CFG=$(unbound -V 2>&1 | sed -n 's/^Configure line: //p' \
    | tr ' ' '\n' \
    | grep -vE '^--build=|^ac_cv_path_SWIG=|^--with-pythonmodule|^--with-pyunbound|^--mandir=|^--infodir=' \
    | tr '\n' ' ')
echo "$CFG" | grep -q -- '--with-dynlibmodule' || CFG="$CFG --with-dynlibmodule"

( cd "$USRC" && ./configure $CFG >/dev/null 2>&1 ) \
    || { echo "ladon: unbound ./configure failed" >&2; exit 1; }

cp "$SRC_C" "$USRC/dynlibmod/examples/ladon.c"
( cd "$USRC/dynlibmod/examples" && cc -I../.. -shared -Wall -fpic -o "$OUT_SO" ladon.c ) \
    || { echo "ladon: cc build of dynlib failed" >&2; exit 1; }

echo "$UVER" > "$STAMP"
echo "$SRC_HASH" > "$SRCSTAMP"
rm -rf "$WORK"
echo "ladon: built $OUT_SO for unbound $UVER"
