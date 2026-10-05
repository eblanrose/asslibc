#!/bin/bash
set -eu
D=/home/nefish/Projects/asslibc/test/crl
mkdir -p "$D"
cd "$D"

cat > ca.cnf <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir              = .
database         = index.txt
new_certs_dir    = .
certificate      = ca.crt
private_key      = ca.key
serial           = serial
crlnumber        = crlnumber
default_md       = sha256
default_crl_days = 30
policy           = policy_any
[ policy_any ]
commonName = supplied
EOF

: > index.txt
echo 1000 > serial
echo 1000 > crlnumber

openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 -nodes \
    -subj "/CN=asslibc-test-ca" 2>/dev/null

openssl req -newkey rsa:2048 -keyout good.key -out good.csr -nodes \
    -subj "/CN=good.example.com" 2>/dev/null
openssl ca -batch -config ca.cnf -in good.csr -out good.crt \
    -notext -days 365 2>/dev/null

openssl req -newkey rsa:2048 -keyout bad.key -out bad.csr -nodes \
    -subj "/CN=revoked.example.com" 2>/dev/null
openssl ca -batch -config ca.cnf -in bad.csr -out bad.crt \
    -notext -days 365 2>/dev/null

openssl ca -batch -config ca.cnf -revoke bad.crt -crl_reason keyCompromise 2>/dev/null
openssl ca -batch -config ca.cnf -gencrl -out crl_revoked.pem 2>/dev/null
openssl crl -in crl_revoked.pem -outform DER -out crl_revoked.der

cp crl_revoked.pem crl_all.pem
: > index.txt
openssl ca -batch -config ca.cnf -gencrl -out crl_empty.pem 2>/dev/null
openssl crl -in crl_empty.pem -outform DER -out crl_empty.der

openssl req -x509 -newkey rsa:2048 -keyout other.key -out other.crt -days 3650 -nodes \
    -subj "/CN=asslibc-other-ca" 2>/dev/null
mkdir -p o && cp ca.cnf o/ && cd o
sed -i 's#dir *= *.#dir=./#; s#certificate *= *ca.crt#certificate=../other.crt#; s#private_key *= *ca.key#private_key=../other.key#' ca.cnf
: > index.txt; echo 2000 > serial; echo 2000 > crlnumber
openssl ca -batch -config ca.cnf -gencrl -out ../crl_other.pem 2>/dev/null
cd ..
openssl crl -in crl_other.pem -outform DER -out crl_other.der 2>/dev/null || true

mkdir -p e && cp ca.cnf e/ && cd e
: > index.txt; echo 3000 > serial; echo 3000 > crlnumber
openssl ca -batch -config ca.cnf -revoke ../bad.crt -crl_reason keyCompromise 2>/dev/null || true
openssl ca -batch -config ca.cnf -gencrl -crldays 1 -out ../crl_expired.pem 2>/dev/null || true
cd ..
openssl crl -in crl_expired.pem -outform DER -out crl_expired.der 2>/dev/null || true

for f in good bad; do openssl x509 -in $f.crt -outform DER -out $f.der; done
openssl x509 -in ca.crt -outform DER -out ca.der
ls -la *.der