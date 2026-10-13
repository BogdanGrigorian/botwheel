#!/usr/bin/env bash
# ============================================================================
#  gen-key.sh - generate a fresh 32-byte at-rest key for the embedded vault
#               database (the AtRestCrypto "SRV1." row wrapper).
#
#  Linux twin of gen-key.cmd - same CLI, same exit codes, same safeguards.
#
#  Usage:  ./gen-key.sh [key-file] [--force] [--print]
#
#    key-file   file to write the base64 key to
#               (default: java/botwheel-db.key next to this script - the path
#               the bot picks up when run with "./mvnw exec:java" from java/)
#    --force    overwrite an existing key (old one is kept as <key-file>.bak)
#    --print    also echo the key to the console - it then lives in terminal
#               scrollback and any captured log. Prefer reading the file.
#
#  The key is 32 bytes from a CSPRNG, base64 encoded (44 chars). It is NOT a
#  passphrase you can invent: AtRestCrypto rejects anything that does not
#  base64-decode to exactly 32 bytes.
#
#  WARNING: swapping the key makes every existing "SRV1." row unreadable (the
#  GCM tag check fails). Users must re-upload their vault from the Mini App,
#  or a migration must re-wrap each row with the new key.
#
#  Needs openssl or /dev/urandom + base64. No Node.js.
#
#  Exit codes: 0 ok, 2 bad usage, 3 tooling problem,
#              4 key file exists without --force, 5 verification failed.
# ============================================================================

set -u

usage() {
    cat <<'EOF'
Usage:  ./gen-key.sh [key-file] [--force] [--print]

  key-file   where to write the base64 key
             (default: java/botwheel-db.key next to this script)
  --force    overwrite an existing key, keeping it as <key-file>.bak
  --print    also echo the key to the console

The key is 32 CSPRNG bytes, base64 encoded. Swapping it makes existing
SRV1. rows unreadable - users must re-upload their vault from the Mini App.
EOF
}

badarg() {
    echo "ERROR: unexpected argument \"$1\"" >&2
    echo >&2
    usage >&2
    exit 2
}

# --- locate ourselves so the default target is stable -----------------------
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 3
# ROOT is the repo root (java/ is a sibling of script/, not a child of it).
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd) || exit 3
KEYFILE="$ROOT/java/botwheel-db.key"
KEYSET=
FORCE=
PRINT=

# --- parse arguments --------------------------------------------------------
while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -f|--force)
            FORCE=1
            ;;
        -p|--print)
            PRINT=1
            ;;
        --)
            shift
            while [ "$#" -gt 0 ]; do
                if [ -n "$KEYSET" ]; then
                    badarg "$1"
                fi
                KEYFILE=$1
                KEYSET=1
                shift
            done
            break
            ;;
        -*)
            badarg "$1"
            ;;
        *)
            if [ -n "$KEYSET" ]; then
                badarg "$1"
            fi
            KEYFILE=$1
            KEYSET=1
            ;;
    esac
    shift
done

if [ -z "$KEYFILE" ]; then
    echo "ERROR: key file path is empty." >&2
    exit 2
fi

# --- absolutize, then prepare the target directory --------------------------
case "$KEYFILE" in
    /*) ;;
    *) KEYFILE="$PWD/$KEYFILE" ;;
esac
KEYDIR=${KEYFILE%/*}
[ -n "$KEYDIR" ] || KEYDIR=/

if [ ! -d "$KEYDIR" ]; then
    mkdir -p -- "$KEYDIR" 2>/dev/null
fi
if [ ! -d "$KEYDIR" ]; then
    echo "ERROR: cannot create directory \"$KEYDIR\"" >&2
    exit 3
fi

# --- never silently clobber an existing key --------------------------------
if [ -e "$KEYFILE" ] || [ -L "$KEYFILE" ]; then
    if [ -z "$FORCE" ]; then
        echo "ERROR: key file already exists: \"$KEYFILE\"" >&2
        echo "  Refusing to overwrite - every existing SRV1. row is wrapped with this key." >&2
        echo "  Re-run with --force to replace it (the old key is saved as .bak first)." >&2
        exit 4
    fi
    if ! cp -p -- "$KEYFILE" "$KEYFILE.bak" 2>/dev/null; then
        echo "ERROR: could not back up the existing key to \"$KEYFILE.bak\"" >&2
        exit 3
    fi
    echo "Existing key kept as \"$KEYFILE.bak\""
fi

# --- generate: 32 random bytes from the OS CSPRNG, base64, no trailing newline
#     umask + chmod keep the file 0600 - the key protects every stored vault row.
umask 077
if command -v openssl >/dev/null 2>&1; then
    KEY=$(openssl rand -base64 32 2>/dev/null | tr -d '\r\n')
else
    if [ ! -r /dev/urandom ]; then
        echo "ERROR: neither openssl nor a readable /dev/urandom - cannot generate a key." >&2
        echo "  Nothing was written to \"$KEYFILE\"." >&2
        exit 3
    fi
    KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\r\n')
fi
if [ -z "$KEY" ]; then
    echo "ERROR: failed to generate key material." >&2
    exit 3
fi
if ! printf '%s' "$KEY" > "$KEYFILE" 2>/dev/null; then
    echo "ERROR: failed to write the key file: \"$KEYFILE\"" >&2
    exit 3
fi
# umask is the portable way, but set the mode explicitly too: an existing file
# keeps its old mode, and some shells/paths do not apply umask to redirections.
chmod 600 -- "$KEYFILE" 2>/dev/null || true

# --- verify what actually landed on disk ------------------------------------
decode_bytes() {
    if command -v openssl >/dev/null 2>&1; then
        openssl base64 -d -A 2>/dev/null | wc -c
    else
        base64 -d 2>/dev/null | wc -c
    fi
}

READBACK=
SIZE=
if [ -f "$KEYFILE" ]; then
    READBACK=$(cat -- "$KEYFILE" 2>/dev/null) || READBACK=
    SIZE=$(wc -c < "$KEYFILE" 2>/dev/null | tr -d ' \r\n')
fi
BYTES=$(printf '%s' "$READBACK" | decode_bytes | tr -d ' \r\n')
# "${#READBACK}" vs the on-disk size also proves there is no trailing newline.
if [ "$BYTES" != "32" ] || [ "$SIZE" != "${#READBACK}" ]; then
    echo "ERROR: verification failed - \"$KEYFILE\" is not base64 for exactly 32 bytes." >&2
    rm -f -- "$KEYFILE"
    echo "  The unusable file was deleted. Check that openssl/base64 work, then re-run." >&2
    exit 5
fi

if [ -n "$PRINT" ]; then
    echo
    echo "KEY: $READBACK"
    echo "  (this is now in your terminal history - clear it if that matters)"
fi

echo
echo "Generated at-rest key: \"$KEYFILE\""
echo "  32 random bytes, base64 (44 chars), no trailing newline."
echo
echo "Next steps:"
echo "  - keep this file OFF the database volume and OUT of git"
echo "    (the repo .gitignore already covers botwheel-db*.key)"
echo "  - the bot picks it up via telegram.db.key.file / TELEGRAM_DB_KEY_FILE,"
echo "    or paste the value into telegram.db.key / TELEGRAM_DB_KEY"
echo "  - restart the bot, then have users re-upload their vault from the Mini App"
exit 0
