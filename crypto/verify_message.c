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

char *print_x509(X509 *x509) {
    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (!bio_mem) {
        // Handle error
        return NULL;
    }

    // Write the certificate to a memory BIO
    if (!PEM_write_bio_X509(bio_mem, x509)) {
        BIO_free(bio_mem);
        // Handle error
        return NULL;
    }

    // Get the buffer containing the certificate
    char *cert_buf;
    long cert_len = BIO_get_mem_data(bio_mem, &cert_buf);
    if (cert_len <= 0) {
        BIO_free(bio_mem);
        // Handle error
        return NULL;
    }

    // Allocate memory for the null-terminated certificate string
    char *cert_str = malloc(cert_len + 1);
    if (!cert_str) {
        BIO_free(bio_mem);
        // Handle error
        return NULL;
    }

    // Copy the certificate buffer to the string
    memcpy(cert_str, cert_buf, cert_len);
    cert_str[cert_len] = '\0';

    BIO_free(bio_mem);
    return cert_str;
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

PKCS7 *load_sign(const char *filename) {
    PKCS7 *pkcs7 = NULL;
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    pkcs7 = d2i_PKCS7_fp(file, NULL);
    fclose(file);
    if (!pkcs7) {
        fprintf(stderr, "Error loading PKCS7 signature from file\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return pkcs7;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <x509_certificate>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    unsigned char data[] = {0x61, 0x61, 0x61, 0x63, 0x75, 0x6f, 0x6e, 0x67, 0x74, 0x63, 0x33, 0x64, 0x66};

    PKCS7 *pkcs7 = NULL;
    X509 *x509 = NULL;
    STACK_OF(X509) *certs = sk_X509_new_null();
    X509_STORE *store = X509_STORE_new();
    BIO *indata = NULL;
    int flags = PKCS7_NOVERIFY;  // We're not performing full verification here

    // Load PKCS7 signature from file
    pkcs7 = load_sign("data.p7s");

    BIO *out_bio = BIO_new(BIO_s_mem());
    if (out_bio) {
        if (i2d_PKCS7_bio(out_bio, pkcs7)) {
            BUF_MEM *bptr;
            BIO_get_mem_ptr(out_bio, &bptr);
            printf("Signature: %d\n", bptr->length);
            for (int i = 0; i < bptr->length; i++) {
                printf("0x%02x, ", (unsigned char)bptr->data[i]);
            }
            printf("\n");
            BIO_free(out_bio);
        } else {
            fprintf(stderr, "Failed to write PKCS7 to BIO\n");
        }
    }
    // Read X509 certificate from file
    x509 = read_x509(argv[1]);
    char *cert_str = print_x509(x509);
    if (cert_str) {
        printf("Certificate:\n%s\n", cert_str);
        free(cert_str);
    } else {
        // Handle error printing certificate
    }
    // Push the certificate onto the stack
    sk_X509_push(certs, x509);

    // Create a BIO object to hold the data
    indata = BIO_new_mem_buf(data, sizeof(data));

    // Perform PKCS7 signature verification
    int ret = PKCS7_verify(pkcs7, certs, store, indata, NULL, flags);
    if (ret != 1) {
        fprintf(stderr, "PKCS7 signature verification failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } else {
        printf("PKCS7 signature verification succeeded\n");
    }

    // Cleanup
    PKCS7_free(pkcs7);
    sk_X509_free(certs);
    X509_STORE_free(store);
    BIO_free(indata);

    return 0;
}
