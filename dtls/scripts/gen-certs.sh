#!/usr/bin/env bash
# Self-signed ECDSA P-256 cert, test amaçlı. Production'da absolute KULLANMA.
set -euo pipefail
DIR="$(dirname "$0")/../certs"
mkdir -p "$DIR"
cd "$DIR"

if [[ ! -f server.key ]]; then
  echo "[gen-certs] generating ECDSA P-256 private key..."
  openssl ecparam -name prime256v1 -genkey -noout -out server.key
fi

if [[ ! -f server.pem ]]; then
  echo "[gen-certs] generating self-signed cert..."
  openssl req -new -x509 -key server.key -out server.pem -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

echo "[gen-certs] done:"
ls -la
echo
openssl x509 -in server.pem -noout -subject -issuer -dates
