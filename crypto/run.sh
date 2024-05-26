#!/bin/sh

make clean
make

AUTH_CERT="/home/cuongtc/linux-5.15.107/certs/signing_key.x509"
AUTH_KEY="/home/cuongtc/linux-5.15.107/certs/signing_key.pem"

echo "------------------------------------"

ARGV="sha256 ${AUTH_KEY} ${AUTH_CERT} data"
echo $ARGV
./sign_message $ARGV