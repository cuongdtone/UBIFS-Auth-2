#!/bin/sh

find . -maxdepth 1 -type f ! -name '*.sh' -exec rm -f {} +
find . -maxdepth 1 -type d ! -path '.' -exec rm -rf {} +

mkfsubifs='/home/cuongtc/mtd-utils/mkfs.ubifs'

sudo modprobe ubi
sudo modprobe ubifs

mkdir ubifs-root
echo $(date) > ubifs-root/date.txt

echo "[ubi_rfs]
mode=ubi
image=ubifs.img
vol_id=0
vol_type=dynamic
vol_name=ubi_rfs
vol_alignment=1
vol_flags=autoresize" > ubi.ini



# No sign
$mkfsubifs -m 2KiB -e 129024 -c 2048 -r ubifs-root -x zlib ubifs.img
ubinize -o my.ubi -p 128KiB -m 2KiB -O 512 ubi.ini


## Sign
PAGE_SIZE="2KiB"
LEB_SIZE=129024
MAX_LEB_COUNT=2048
ROOT_DIR="ubifs-root"
OUTPUT_IMAGE="ubifs-sign.img"
HASH_ALGO="sha256"
AUTH_CERT="/home/cuongtc/linux-5.15.107/certs/signing_key.x509"
AUTH_KEY="/home/cuongtc/linux-5.15.107/certs/signing_key.pem"

echo "[ubi_rfs]
mode=ubi
image=$OUTPUT_IMAGE
vol_id=0
vol_type=dynamic
vol_name=ubi_srfs
vol_alignment=1
vol_flags=autoresize" > ubi-sign.ini

$mkfsubifs -m "$PAGE_SIZE" \
           -e "$LEB_SIZE" \
           -c "$MAX_LEB_COUNT" \
           -r "$ROOT_DIR" \
           -x zlib \
           "$OUTPUT_IMAGE" \
           --hash-algo "$HASH_ALGO" \
           --auth-cert="$AUTH_CERT" \
           --auth-key="$AUTH_KEY"

ubinize -o my-sign.ubi -p 128KiB -m 2KiB -O 512 ubi-sign.ini


