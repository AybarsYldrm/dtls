#!/usr/bin/env bash
# Reference DTLS 1.3 server — OpenSSL 3.5+ gerektirir.
# Node client'tan gelen ClientHello'yu yanıtlar; -trace ile her field görünür.
set -euo pipefail

PORT="${PORT:-4444}"
DIR="$(dirname "$0")/.."

if ! openssl version | grep -qE 'OpenSSL 3\.(5|6|[7-9])'; then
  echo "WARN: OpenSSL 3.5+ DTLS 1.3 için gerekli. Yüklü sürüm:"
  openssl version
fi

exec openssl s_server \
  -dtls1_3 \
  -accept "$PORT" \
  -cert "$DIR/certs/server.pem" \
  -key  "$DIR/certs/server.key" \
  -msg -state -debug -trace \
  "$@"
