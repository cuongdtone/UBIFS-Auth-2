/** 
 * @file    hello.c 
 * @author  Akshat Sinha 
 * @date    10 Sept 2016 
 * @version 0.1 
 * @brief  An introductory "Hello World!" loadable kernel 
 *  module (LKM) that can display a message in the /var/log/kern.log 
 *  file when the module is loaded and removed. The module can accept 
 *  an argument when it is loaded -- the name, which appears in the 
 *  kernel log files. 
*/
#include <linux/module.h>     /* Needed by all modules */ 
#include <linux/kernel.h>     /* Needed for KERN_INFO */ 
#include <linux/init.h>       /* Needed for the macros */
#include <linux/slab.h>

#include <linux/key.h>
#include <linux/err.h>
#include <linux/ratelimit.h>
#include <linux/key-type.h>
#include <crypto/hash_info.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <crypto/public_key.h>
#include <keys/encrypted-type.h>
#include <keys/trusted-type.h>
#include <keys/user-type.h>
#include <crypto/public_key.h>
#include <crypto/pkcs7.h>

#include "exveri.h"

#define KEY_TYPE "asymmetric"
#define KEY_LOOKUP_CREATE	0x01

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("Akshat Sinha"); 
MODULE_DESCRIPTION("A simple Hello world LKM!"); 
MODULE_VERSION("0.1"); 
#include <linux/key.h>


struct key *create_and_request_key(const char *key_type, const char *key_desc,
                           const void *key_payload, size_t key_len)
{
    key_ref_t keyring_ref, key_ref;
    struct key *tkey;
    int ret;

    // pr_info("-------create_and_request_key----------");
    // Lấy reference của keyring người dùng
    keyring_ref = lookup_user_key(KEY_SPEC_USER_KEYRING, KEY_LOOKUP_CREATE, KEY_NEED_WRITE);
    if (IS_ERR(keyring_ref)) {
        ret = PTR_ERR(keyring_ref);
        pr_err("Failed to lookup user keyring: %d\n", ret);
        return ret;
    }

    // Tạo hoặc cập nhật key
    key_ref = key_create_or_update(keyring_ref, key_type, key_desc,
                    key_payload, key_len, KEY_PERM_UNDEF,
                    KEY_ALLOC_IN_QUOTA);
    
    if (IS_ERR(key_ref)) {
        ret = PTR_ERR(key_ref);
        pr_err("Failed to create or update key: %d\n", ret);
        goto error_keyring;
    }

    // Giải phóng reference của key đã tạo
    key_ref_put(key_ref);

    tkey = key_ref_to_ptr(key_ref);
    // Yêu cầu key
    // tkey = request_key(&key_type_user, key_desc, NULL);
    if (IS_ERR(tkey)) {
        ret = PTR_ERR(tkey);
        pr_err("Failed to request key: %d\n", ret);
        goto error_keyring;
    }
    // pr_info("-----------------");

    // Xử lý thành công
    // pr_info("Key successfully requested: %s\n", key_desc);
    key_put(tkey);
    key_ref_put(keyring_ref);
    return tkey;

error_keyring:
    key_ref_put(keyring_ref);
    return ERR_PTR(ret);
}


int verify_pkcs1_message(const char *cert, int certlen, 
                         const char *sig, int siglen, 
                         const char *data, int datalen)
{
    struct public_key_signature pks;
    int ret;
    size_t desc_size;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    struct key *tkey;

    ret = 1;

    // // Fill in the public_key_signature structure
    memset(&pks, 0, sizeof(pks));
    pks.hash_algo = "sha256";
    pks.encoding = "pkcs1";
    pks.pkey_algo = "rsa";
    pks.data = data;
    pks.data_size = datalen;
    pks.s = (u8 *)sig;
    pks.s_size = siglen;
    pks.digest_size = 32;

    // // calc hash
    tfm = crypto_alloc_shash(pks.hash_algo, 0, 0);
    if (IS_ERR(tfm))
		return (PTR_ERR(tfm) == -ENOENT) ? -ENOPKG : PTR_ERR(tfm);
	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
    desc = kzalloc(desc_size, GFP_KERNEL);
    desc->tfm   = tfm;
    pks.digest = kmalloc(pks.digest_size, GFP_KERNEL);
	ret = crypto_shash_digest(desc, pks.data, pks.data_size, pks.digest);


    // // Verify the signature
    tkey = create_and_request_key(KEY_TYPE, "key_desc", cert, certlen);

    pr_info("Cuongtcpkcs1 MsgDigest     = [%*ph]\n", 8, pks.digest);
    pr_info("Cuongtcpkcs1 MsgDigestSize = %lu\n", pks.digest_size);
    if (IS_ERR(tkey))
		return 1;

    pr_info("Signature verifing ..............\n========================================\n");
    ret = verify_signature(tkey, &pks);
    if (ret)
        pr_err("Signature verification failed: %d\n", ret);
    else
        pr_info("Signature verified successfully\n");
    pr_info("Signature end ..............\n========================================\n");

    // // Cleanup
    return ret;

}
static int __init exveri_start(void) 
{ 

    printk(KERN_INFO "Loading hello module...\n"); 
    printk(KERN_INFO "Hello world\n"); 
    int err;
    unsigned char data[] = {0x61, 0x61, 0x61, 0x63, 0x75, 0x6f, 0x6e, 0x67, 0x74, 0x63, 0x33, 0x64, 0x66};

    /*int verify_pkcs1_message(const char *cert, const char *certlen, 
                         const char *sig, int siglen, 
                         const char *data, int datalen)*/

    verify_pkcs1_message(exveri_cert, le32_to_cpu(sizeof(exveri_cert)),
                        exveri_sign, le32_to_cpu(sizeof(exveri_sign)), 
                        data, sizeof(data));


    pr_info("Verify_pkcs7_signature verifing ..............\n========================================\n");
    err = verify_pkcs7_signature(data, sizeof(data),
				     exveri_sign, le32_to_cpu(sizeof(exveri_sign)),
				     NULL, VERIFYING_UNSPECIFIED_SIGNATURE,
				     NULL, NULL);
	if (err)
		pr_err("pkcs7 Failed to verify signature\n");
	else
		pr_info("pkcs7 Successfully verified\n");
    pr_info("Verify_pkcs7_signature end ..............\n========================================\n");

    return 0; 
}
  
static void __exit exveri_end(void) 
{ 
    printk(KERN_INFO "Goodbye Mr.\n"); 
} 
  
module_init(exveri_start); 
module_exit(exveri_end); 