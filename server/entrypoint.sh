#!/usr/bin/env bash

set -e  # Exit on error

echo "============================================"
echo "Tatou Server Startup"
echo "============================================"

# --- Check FLAG_2 ---
if [[ -z "${FLAG_2:-}" ]]; then
  echo "⚠️  WARNING: FLAG_2 is not set"
fi

# --- Replace placeholder in /app/flag ---
if [[ -f "/app/flag" ]]; then
  if grep -q "REPLACE_THIS_STRING_WITH_SERVER_FLAG" "/app/flag"; then
    echo "✅ Replacing placeholder in flag with FLAG_2"
    sed -i "s/REPLACE_THIS_STRING_WITH_SERVER_FLAG/${FLAG_2}/g" /app/flag
  else
    echo "ℹ️  Flag file already configured"
  fi
else
  echo "⚠️  WARNING: /app/flag not found"
fi

# --- Check RMAP Keys (NEW) ---
KEYS_DIR="${RMAP_KEYS_DIR:-/app/server/keys}"
SERVER_PUB="${KEYS_DIR}/server_public.asc"
SERVER_PRIV="${KEYS_DIR}/server_private.asc"
CLIENTS_DIR="${KEYS_DIR}/clients"

echo ""
echo "--- RMAP Configuration Check ---"

if [[ ! -d "$KEYS_DIR" ]]; then
  echo "⚠️  WARNING: RMAP keys directory not found: $KEYS_DIR"
  echo "   RMAP endpoints will be disabled"
elif [[ ! -f "$SERVER_PUB" ]] || [[ ! -f "$SERVER_PRIV" ]]; then
  echo "⚠️  WARNING: Server keypair missing in $KEYS_DIR"
  echo "   - server_public.asc: $([ -f "$SERVER_PUB" ] && echo "✅ Found" || echo "❌ Missing")"
  echo "   - server_private.asc: $([ -f "$SERVER_PRIV" ] && echo "✅ Found" || echo "❌ Missing")"
  echo "   RMAP endpoints will be disabled"
else
  echo "✅ Server keypair found"

  # Check permissions on private key
  PRIV_PERMS=$(stat -c "%a" "$SERVER_PRIV" 2>/dev/null || echo "???")
  if [[ "$PRIV_PERMS" != "600" ]] && [[ "$PRIV_PERMS" != "400" ]]; then
    echo "⚠️  WARNING: Private key has insecure permissions: $PRIV_PERMS"
    echo "   Recommended: chmod 600 $SERVER_PRIV"
  else
    echo "✅ Private key permissions OK: $PRIV_PERMS"
  fi

  # Count client keys
  if [[ -d "$CLIENTS_DIR" ]]; then
    CLIENT_COUNT=$(find "$CLIENTS_DIR" -name "*.asc" -type f | wc -l)
    echo "✅ Client keys directory found: $CLIENT_COUNT key(s)"

    if [[ $CLIENT_COUNT -eq 0 ]]; then
      echo "⚠️  WARNING: No client keys found in $CLIENTS_DIR"
      echo "   Other groups won't be able to authenticate"
    fi
  else
    echo "⚠️  WARNING: Client keys directory not found: $CLIENTS_DIR"
  fi
fi

# --- Check RMAP Base PDF (NEW) ---
BASE_PDF="${RMAP_BASE_PDF:-/app/storage/rmap/group_17_rmap.pdf}"
echo ""
echo "--- RMAP Base PDF Check ---"
if [[ -f "$BASE_PDF" ]]; then
  PDF_SIZE=$(stat -c "%s" "$BASE_PDF")
  echo "✅ Base PDF found: $BASE_PDF ($PDF_SIZE bytes)"
else
  echo "⚠️  WARNING: Base PDF not found: $BASE_PDF"
  echo "   RMAP will fail when generating watermarked PDFs"
  echo "   Create one with: docker-compose exec server bash -c 'python create_base_pdf.py'"
fi

echo ""
echo "============================================"
echo "Starting Gunicorn..."
echo "============================================"

# --- Start the server ---
exec gunicorn -b 0.0.0.0:5000 server:app