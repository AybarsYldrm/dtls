#!/usr/bin/env bash
# Reference DTLS 1.3 client — OpenSSL 3.5+ gerektirir.
# Node server'a ClientHello gönderir; -trace ile kendi çıkışını açıklar.
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-4444}"

if ! openssl version | grep -qE 'OpenSSL 3\.(5|6|[7-9])'; then
  echo "WARN: OpenSSL 3.5+ DTLS 1.3 için gerekli. Yüklü sürüm:"
  openssl version
fi

exec openssl s_client \
  -dtls1_3 \
  -connect "${HOST}:${PORT}" \
  -servername localhost \
  -msg -state -debug -trace \
  "$@"
