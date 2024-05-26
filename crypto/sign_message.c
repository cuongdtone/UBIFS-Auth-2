/* Sign a module file using the given key.
 *
 * Copyright © 2014-2016 Red Hat, Inc. All Rights Reserved.
 * Copyright © 2015      Intel Corporation.
 * Copyright © 2016      Hewlett Packard Enterprise Development LP
 *
 * Authors: David Howells <dhowells@redhat.com>
 *          David Woodhouse <dwmw2@infradead.org>
 *          Juerg Haefliger <juerg.haefliger@hpe.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the licence, or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <err.h>
#include <arpa/inet.h>
#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>

/*
 * OpenSSL 3.0 deprecates the OpenSSL's ENGINE API.
 *
 * Remove this if/when that API is no longer used
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/*
 * Use CMS if we have openssl-1.0.0 or newer available - otherwise we have to
 * assume that it's not available and its header file is missing and that we
 * should use PKCS#7 instead.  Switching to the older PKCS#7 format restricts
 * the options we have on specifying the X.509 certificate we want.
 *
 * Further, older versions of OpenSSL don't support manually adding signers to
 * the PKCS#7 message so have to accept that we get a certificate included in
 * the signature message.  Nor do such older versions of OpenSSL support
 * signing with anything other than SHA1 - so we're stuck with that if such is
 * the case.
 */
#if defined(LIBRESSL_VERSION_NUMBER) || \
	OPENSSL_VERSION_NUMBER < 0x10000000L || \
	defined(OPENSSL_NO_CMS)
#define USE_PKCS7
#endif
#ifndef USE_PKCS7
#include <openssl/cms.h>
#else
#include <openssl/pkcs7.h>
#endif

struct module_signature {
	uint8_t		algo;		/* Public-key crypto algorithm [0] */
	uint8_t		hash;		/* Digest algorithm [0] */
	uint8_t		id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	uint8_t		signer_len;	/* Length of signer's name [0] */
	uint8_t		key_id_len;	/* Length of key identifier [0] */
	uint8_t		__pad[3];
	uint32_t	sig_len;	/* Length of signature data */
};

#define PKEY_ID_PKCS7 2

static char magic_number[] = "~Module signature appended~\n";

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr,
		"Usage: scripts/sign-file [-dp] <hash algo> <key> <x509> <module> [<dest>]\n");
	fprintf(stderr,
		"       scripts/sign-file -s <raw sig> <hash algo> <x509> <module> [<dest>]\n");
	exit(2);
}

static void display_openssl_errors(int l)
{
	const char *file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At main.c:%d:\n", l);

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

static void drain_openssl_errors(void)
{
	const char *file;
	int line;

	if (ERR_peek_error() == 0)
		return;
	while (ERR_get_error_line(&file, &line)) {}
}

#define ERR(cond, fmt, ...)				\
	do {						\
		bool __cond = (cond);			\
		display_openssl_errors(__LINE__);	\
		if (__cond) {				\
			err(1, fmt, ## __VA_ARGS__);	\
		}					\
	} while(0)

static const char *key_pass;

static int pem_pw_cb(char *buf, int len, int w, void *v)
{
	int pwlen;

	if (!key_pass)
		return -1;

	pwlen = strlen(key_pass);
	if (pwlen >= len)
		return -1;

	strcpy(buf, key_pass);

	/* If it's wrong, don't keep trying it. */
	key_pass = NULL;

	return pwlen;
}

static EVP_PKEY *read_private_key(const char *private_key_name)
{
	EVP_PKEY *private_key;

	if (!strncmp(private_key_name, "pkcs11:", 7)) {
		ENGINE *e;

		ENGINE_load_builtin_engines();
		drain_openssl_errors();
		e = ENGINE_by_id("pkcs11");
		ERR(!e, "Load PKCS#11 ENGINE");
		if (ENGINE_init(e))
			drain_openssl_errors();
		else
			ERR(1, "ENGINE_init");
		if (key_pass)
			ERR(!ENGINE_ctrl_cmd_string(e, "PIN", key_pass, 0),
			    "Set PKCS#11 PIN");
		private_key = ENGINE_load_private_key(e, private_key_name,
						      NULL, NULL);
		ERR(!private_key, "%s", private_key_name);
	} else {
		BIO *b;

		b = BIO_new_file(private_key_name, "rb");
		ERR(!b, "%s", private_key_name);
		private_key = PEM_read_bio_PrivateKey(b, NULL, pem_pw_cb,
						      NULL);
		ERR(!private_key, "%s", private_key_name);
		BIO_free(b);
	}

	return private_key;
}

static X509 *read_x509(const char *x509_name)
{
	unsigned char buf[2];
	X509 *x509;
	BIO *b;
	int n;

	b = BIO_new_file(x509_name, "rb");
	ERR(!b, "%s", x509_name);

	/* Look at the first two bytes of the file to determine the encoding */
	n = BIO_read(b, buf, 2);
	if (n != 2) {
		if (BIO_should_retry(b)) {
			fprintf(stderr, "%s: Read wanted retry\n", x509_name);
			exit(1);
		}
		if (n >= 0) {
			fprintf(stderr, "%s: Short read\n", x509_name);
			exit(1);
		}
		ERR(1, "%s", x509_name);
	}

	ERR(BIO_reset(b) != 0, "%s", x509_name);

	if (buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84)
		/* Assume raw DER encoded X.509 */
		x509 = d2i_X509_bio(b, NULL);
	else
		/* Assume PEM encoded X.509 */
		x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

	BIO_free(b);
	ERR(!x509, "%s", x509_name);

	return x509;
}



int main(int argc, char **argv) {
    char *private_key_name = NULL, *raw_sig_name = NULL;
    char *hash_algo = NULL;
    char *x509_name;
    char *module_name;
    unsigned char buf[4096];
    unsigned long sig_size;
    EVP_PKEY *private_key;
    const EVP_MD *digest_algo;
	unsigned int use_signed_attrs;
	int ret;

    // printf("PKCS#7 is used");
	X509_STORE* rootStore = X509_STORE_new();

	PKCS7 *pkcs7 = NULL;

	X509 *x509;
	BIO *bd, *bm;
	int opt, n;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();

    key_pass = getenv("KBUILD_SIGN_PIN");

	use_signed_attrs = PKCS7_NOATTR;

    hash_algo = argv[1];
    private_key_name = argv[2];
    x509_name = argv[3];
	module_name = argv[4];

    printf("hash_algo %s \n", hash_algo);
	printf("private_key %s \n", private_key_name);
	printf("x509 %s \n", x509_name);
	printf("module_name %s \n", module_name);

    /* Read cert*/
    private_key = read_private_key(private_key_name);
    x509 = read_x509(x509_name);

	/* Read file*/
    bm = BIO_new_file(module_name, "rb");
	ERR(!bm, "%s", module_name);

	/* Load hash*/
    OpenSSL_add_all_digests();
    display_openssl_errors(__LINE__);
    digest_algo = EVP_get_digestbyname(hash_algo);
    ERR(!digest_algo, "EVP_get_digestbyname");


    pkcs7 = PKCS7_sign(x509, private_key, NULL, bm,
                PKCS7_NOCERTS | PKCS7_BINARY |
                PKCS7_DETACHED | use_signed_attrs);
    ERR(!pkcs7, "PKCS7_sign");

    /* Save sign */
    char *sig_file_name;
    BIO *b;

    ERR(asprintf(&sig_file_name, "%s.p7s", module_name) < 0,
        "asprintf");
    b = BIO_new_file(sig_file_name, "wb");
    ERR(!b, "%s", sig_file_name);
	ERR(i2d_PKCS7_bio(b, pkcs7) < 0,
		"%s", sig_file_name);
	BIO_free(b);

}


	/* Print signature*/
	// if (PKCS7_final(pkcs7, bm, PKCS7_NOSIGS)) {
	// 	BIO *out_bio = BIO_new(BIO_s_mem());
	// 	if (out_bio) {
	// 		if (i2d_PKCS7_bio(out_bio, pkcs7)) {
	// 			BUF_MEM *bptr;
	// 			BIO_get_mem_ptr(out_bio, &bptr);
	// 			printf("Signature: %d\n", bptr->length);
	// 			for (int i = 0; i < bptr->length; i++) {
	// 				printf("0x%02x, ", (unsigned char)bptr->data[i]);
	// 			}
	// 			printf("\n");
	// 			BIO_free(out_bio);
	// 		} else {
	// 			fprintf(stderr, "Failed to write PKCS7 to BIO\n");
	// 		}
	// 	} else {
	// 		fprintf(stderr, "Failed to create BIO\n");
	// 	}
	// } else {
	// 	fprintf(stderr, "PKCS7_final failed\n");
	// }