sudo modprobe ubi
sudo modprobe ubifs

sudo modprobe nandsim first_id_byte=0x20 second_id_byte=0xaa third_id_byte=0x00 fourth_id_byte=0x15
sudo ubiformat /dev/mtd0 -f my-sign.ubi


sudo ubiattach -m 0
ubinfo -a

sudo mkdir -p /mnt/ubi_rootfs

cat ../linux-5.15.107/certs/signing_key.x509 | keyctl padd logon ubifs:root @s

sudo mount -t ubifs /dev/ubi0_0 /mnt/ubi_rootfs
sudo mount -t ubifs /dev/ubi0_0 /mnt/ubi_rootfs -o auth_hash_name=sha256,auth_key=ubifs:root

