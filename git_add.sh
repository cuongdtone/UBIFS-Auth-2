#!/bin/sh

cp -rf linux-5.15.107/drivers/exveri .
cp -rf linux-5.15.107/crypto/asymmetric_keys/public_key.c .
cp -rf mtd-utils/ubifs-utils/mkfs.ubifs/sign.c .

git add git_add.sh
git add exveri
git add public_key.c
git add sign.c
git add rsa-pss
git add crypto
git add ubifs-image