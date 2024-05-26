#!/bin/sh

echo "===========clean==============="
rmmod exveri.ko 
make clean
echo "===========build==============="
echo "==============================="
echo "==============================="
echo "==============================="


make
echo "===========load==============="
insmod exveri.ko

