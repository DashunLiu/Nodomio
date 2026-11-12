#!/bin/sh
set -eu
umask 077

fixtures=$(CDPATH= cd -P "$(dirname "$0")/fixtures" && pwd)
destination="$fixtures/tls"
if [ -e "$destination" ] || [ -L "$destination" ]; then
    echo "TLS fixture directory already exists: $destination" >&2
    exit 1
fi

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' 0
trap 'exit 1' HUP INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 7 \
    -subj '/CN=Nodomi loopback test CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -keyout "$temporary/ca.key" -out "$temporary/ca.pem"

openssl req -new -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' \
    -keyout "$temporary/server-key.pem" -out "$temporary/server.csr"

cat >"$temporary/server.ext" <<'EXTENSIONS'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXTENSIONS

openssl x509 -req -in "$temporary/server.csr" \
    -CA "$temporary/ca.pem" -CAkey "$temporary/ca.key" -CAcreateserial \
    -sha256 -days 7 -extfile "$temporary/server.ext" -out "$temporary/server.pem"
openssl verify -x509_strict -purpose sslserver -verify_hostname localhost \
    -CAfile "$temporary/ca.pem" "$temporary/server.pem"
if openssl verify -verify_ip 127.0.0.1 -CAfile "$temporary/ca.pem" \
    "$temporary/server.pem" >/dev/null 2>&1; then
    echo 'TLS fixture must reject numeric hostnames' >&2
    exit 1
fi

# This exclusive mkdir also resolves races between concurrent invocations.
mkdir -m 700 "$destination"
(
    set -C
    for fixture in ca.pem server.pem server-key.pem; do
        cat "$temporary/$fixture" >"$destination/$fixture"
    done
)
echo "Generated loopback TLS fixtures in $destination"
