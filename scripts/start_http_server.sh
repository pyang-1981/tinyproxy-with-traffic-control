#!/usr/bin/env bash
# Start a simple HTTP server that serves a large file for testing.
# Usage: ./scripts/start_http_server.sh [PORT] [FILE_PATH] [SIZE]
#   PORT      - TCP port to listen on (default: 8000)
#   FILE_PATH - path to the file to serve (default: ./serve/largefile.bin)
#   SIZE      - size for the file (supports K, M, G suffix). Default: 1G

set -euo pipefail

PORT=${1:-8000}
FILE_PATH=${2:-"$(pwd)/serve/largefile.bin"}
SIZE=${3:-1G}

# Ensure directory exists
mkdir -p "$(dirname "$FILE_PATH")"

# Create file if missing. Try fallocate, then truncate, then dd as a last resort.
if [ ! -f "$FILE_PATH" ]; then
  echo "Creating $FILE_PATH ($SIZE) ..."
  if command -v fallocate >/dev/null 2>&1; then
    fallocate -l "$SIZE" "$FILE_PATH" || true
  fi
  if [ ! -s "$FILE_PATH" ]; then
    # Try truncate (sparse file)
    truncate -s "$SIZE" "$FILE_PATH" || true
  fi
  if [ ! -s "$FILE_PATH" ]; then
    # Last resort: dd (this will write real data and may take time)
    echo "fall back to dd (this may take a while)..."
    # Convert SIZE to megabytes for dd count when possible (support only G/M)
    case "$SIZE" in
      *G|*g)
        COUNT=$(( ${SIZE%[Gg]} * 1024 ))
        dd if=/dev/zero of="$FILE_PATH" bs=1M count="$COUNT" status=progress
        ;;
      *M|*m)
        COUNT=${SIZE%[Mm]}
        dd if=/dev/zero of="$FILE_PATH" bs=1M count="$COUNT" status=progress
        ;;
      *)
        # unknown size suffix, try dd with 1024M
        dd if=/dev/zero of="$FILE_PATH" bs=1M count=1024 status=progress
        ;;
    esac
  fi
  echo "Created $FILE_PATH"
else
  echo "$FILE_PATH already exists, skipping creation"
fi

# Start the HTTP server
echo "Starting Python HTTP server on port $PORT, serving $(dirname "$FILE_PATH")"
cd "$(dirname "$FILE_PATH")"
python3 -m http.server "$PORT" --bind 0.0.0.0
