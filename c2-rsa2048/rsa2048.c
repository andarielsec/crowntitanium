#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define ENCRYPT_FLAG "-e"
#define DECRYPT_FLAG "-d"
#define PRINT_KEYS
#define WRITE_TO_FILE

int main(int argc, char *argv[]) {
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char *pri_key;             // Private key
    char *pub_key;             // Public key
    char *msg;                 // Message to encrypt
    char *encrypt = NULL;      // Encrypted message
    char *decrypt = NULL;      // Decrypted message
    char *err;                 // Buffer for any error messages
    int encrypt_mode = 1;      // 1 for encryption, 0 for decryption

    if (argc < 2) {
        fprintf(stderr, "Usage: %s %s input_file [output_file]\n", argv[0], ENCRYPT_FLAG);
        return 1;
    }

    if (strcmp(argv[1], DECRYPT_FLAG) == 0) {
        encrypt_mode = 0;
        if (argc < 4) {
            fprintf(stderr, "Usage: %s %s input_file output_file\n", argv[0], DECRYPT_FLAG);
            return 1;
        }
    } else if (argc < 3) {
        fprintf(stderr, "Usage: %s %s input_file [output_file]\n", argv[0], ENCRYPT_FLAG);
        return 1;
    }

    // Generate key pair
    printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    fflush(stdout);
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    #ifdef PRINT_KEYS
    printf("\n%s\n%s\n", pri_key, pub_key);
    #endif
    printf("done.\n");

    if (encrypt_mode) {
        // Read the message to encrypt from the input file
        FILE *input_file = fopen(argv[2], "rb");
        if (!input_file) {
            fprintf(stderr, "Error opening input file: %s\n", argv[2]);
            return 1;
        }

        fseek(input_file, 0, SEEK_END);
        size_t input_file_size = ftell(input_file);
        fseek(input_file, 0, SEEK_SET);

        msg = malloc(input_file_size);
        if (!msg) {
            fclose(input_file);
            fprintf(stderr, "Memory allocation error for the input file\n");
            return 1;
        }

        if (fread(msg, 1, input_file_size, input_file) != input_file_size) {
            fclose(input_file);
            fprintf(stderr, "Error reading input file\n");
            return 1;
        }

        fclose(input_file);

        // Encrypt the message
        encrypt = malloc(RSA_size(keypair));
        int encrypt_len;
        err = malloc(130);
        if ((encrypt_len = RSA_public_encrypt(input_file_size, (unsigned char *)msg, (unsigned char *)encrypt,
                                             keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
            ERR_load_crypto_strings();
            ERR_error_string(ERR_get_error(), err);
            fprintf(stderr, "Error encrypting message: %s\n", err);
            goto free_stuff;
        }

        #ifdef WRITE_TO_FILE
        // Write the encrypted message to an output file
        FILE *output_file;
        if (argc > 3) {
            output_file = fopen(argv[3], "wb");
        } else {
            output_file = fopen("out.bin", "wb");
        }

        if (!output_file) {
            fprintf(stderr, "Error opening output file\n");
            goto free_stuff;
        }

        fwrite(encrypt, sizeof(*encrypt), encrypt_len, output_file);
        fclose(output_file);
        printf("Encrypted message written to file.\n");
        free(encrypt);
        encrypt = NULL;
        #endif
    } else {
        // Decrypt the message from the input file
        FILE *input_file = fopen(argv[2], "rb");
        if (!input_file) {
            fprintf(stderr, "Error opening input file\n");
            return 1;
        }

        fseek(input_file, 0, SEEK_END);
        size_t input_file_size = ftell(input_file);
        fseek(input_file, 0, SEEK_SET);

        encrypt = malloc(input_file_size);
        if (!encrypt) {
            fclose(input_file);
            fprintf(stderr, "Memory allocation error for the input file\n");
            return 1;
        }

        if (fread(encrypt, 1, input_file_size, input_file) != input_file_size) {
            fclose(input_file);
            fprintf(stderr, "Error reading input file\n");
            return 1;
        }

        fclose(input_file);

        // Decrypt the message
        int decrypt_len;
        err = malloc(130);
        if ((decrypt_len = RSA_private_decrypt(input_file_size, (unsigned char *)encrypt, (unsigned char *)msg,
                                               keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
            ERR_load_crypto_strings();
            ERR_error_string(ERR_get_error(), err);
            fprintf(stderr, "Error decrypting message: %s\n", err);
            goto free_stuff;
        }

        #ifdef WRITE_TO_FILE
        // Write the decrypted message to an output file
        FILE *output_file;
        if (argc > 3) {
            output_file = fopen(argv[3], "wb");
        } else {
            output_file = fopen("decrypted_out.txt", "wb");
        }

        if (!output_file) {
            fprintf(stderr, "Error opening output file\n");
            goto free_stuff;
        }

        fwrite(msg, 1, decrypt_len, output_file);
        fclose(output_file);
        printf("Decrypted message written to file.\n");
        #else
        // Print the decrypted message
        printf("Decrypted message: %s\n", msg);
        #endif
    }

    free_stuff:
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(msg);
    free(encrypt);
    free(decrypt);
    free(err);

    return 0;
}

