#!/bin/sh
set -e

if [ ! -x ./gen_cert ] || [ ! -x ./interop_server ] || [ ! -x ./interop_client ]; then
    echo "interop.sh: build targets missing (run 'make interop')" >&2
    exit 1
fi

./gen_cert >/dev/null

PORT=24431
RUN=""
if command -v timeout >/dev/null 2>&1; then RUN="timeout 30"; fi

for ver in tls1.3 tls1.2; do
    PORT=$((PORT + 1))
    $RUN ./interop_server "$PORT" "$ver" >/dev/null 2>&1 &
    SPID=$!
    sleep 0.3
    $RUN ./interop_client 127.0.0.1 "$PORT" "$ver" example.com >/dev/null 2>&1
    wait "$SPID"
    echo "interop $ver OK"
done

rm -f cert_0_0_0_0.der
echo "ALL INTEROP TESTS PASSED"
