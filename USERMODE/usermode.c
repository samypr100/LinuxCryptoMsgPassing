/*********************************************************************
*
* This is a skeleton usermode program for the char device
* JHU Operating Systems Security (695.412)
*
*
* Author: T. McGuire
* License: GPL
*
*
*********************************************************************/
#include "../COMMON/char_ioctl.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//
// This header is required for the ioctl() call
#include <sys/ioctl.h>

// SMATOS2, EFORTE3: LibSSL Specifics
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// SMATOS2, EFORTE3: Structure Per Client (e.g. Client A and Client B)
struct jhu_crypto_client {
    int read_fd;                               // FD that client should read from
    int write_fd;                              // FD that client should write to
    bool is_read_client_ready;                 // Bool indicating Reading is Possible
    bool is_write_client_ready;                // Bool indicating Writing is Possible
    bool is_crypto_initialized;                // Bool indicating "Current" Client's Crypto Info is Initialized
    struct jhu_ioctl_crypto read_crypto_info;  // Structure that contains Crypto Info to use when reading from read_fd
    struct jhu_ioctl_crypto write_crypto_info; // Structure that contains Crypto Info to use when writing to write_fd
} __attribute__((__packed__));

// SMATOS2, EFORTE3: Declare Prototypes
void sigint_handler(int sig);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int ioctl_set_data(int fd, const unsigned char *key, const unsigned char *IV);
int ioctl_read_data(int fd, struct jhu_ioctl_crypto *crypto_info);
struct jhu_crypto_client init_client_crypto(char client, char *devname_a, char *devname_b);

// SMATOS2, EFORTE3: Application Start
// Takes 1 Arguments "a" or "b"
int main(int argc, char **argv)
{

    // SMATOS2, EFORTE3: Enforce an argument
    if (argc < 2 || argv[1] == NULL) {
        printf("Usage: ./usermode [a or b] \n");
        printf("Please enter an argument [a or b] \n");
        return -1;
    }

    // SMATOS2, EFORTE3: Add Signal Handler
    signal(SIGINT, sigint_handler);

    // SMATOS2, EFORTE3: Declare Device Names using char_ioctl.h
    char devname_a[32];
    char devname_b[32];
    strcpy(devname_a, "/dev/");
    strcpy(devname_b, "/dev/");
    strcat(devname_a, DEVICE_NAME_A);
    strcat(devname_b, DEVICE_NAME_B);

    // SMATOS2, EFORTE3: Initialize Randomness Pool for Seeding
    // Taken/Modified From: https://wiki.openssl.org/index.php/Random_Numbers
    int rc = RAND_load_file("/dev/random", 64);
    if (rc != 64) {
        printf("Unable to Initialize Seed\n");
        return -1;
    }

    // SMATOS2, EFORTE3: Trigger when argument is 'a'
    if (strchr(argv[1], 'a') != NULL) {

        // SMATOS2, EFORTE3
        // If user inputs a, we read from a and write to b
        // This call sets Encryption Info and tries to obtain KEY/IV info for 60 seconds
        struct jhu_crypto_client client_crypto = init_client_crypto('a', devname_a, devname_b);
        bool is_ready = client_crypto.is_crypto_initialized && client_crypto.is_read_client_ready && client_crypto.is_write_client_ready;
        if (!is_ready) {
            if (client_crypto.read_fd != -1) {
                close(client_crypto.read_fd);
            }
            if (client_crypto.write_fd != -1) {
                close(client_crypto.read_fd);
            }
            return -1;
        }

        printf("Please type your input below. The received data from \"b\" will show up as [b]:\n");
        printf("Your input will show up as [me]:\n");

        // SMATOS2, EFORTE3: Init Locals
        int num_read = 0, ciphertext_len = 0, decryptedtext_len = 0;
        char read_msg[JHU_IOCTL_MESSAGE_LIMIT] = {0};
        char userInput[JHU_IOCTL_MESSAGE_LIMIT] = {0};
        unsigned char ciphertext[JHU_IOCTL_MESSAGE_LIMIT] = {0};
        unsigned char decryptedtext[JHU_IOCTL_MESSAGE_LIMIT] = {0};

        // SMATOS2, EFORTE3: Start Client
        while (1) {

            // SMATOS2, EFORTE3: Take user input to write to client B
            printf("[me]: ");
            fgets(userInput, JHU_IOCTL_MESSAGE_LIMIT, stdin);
            userInput[strcspn(userInput, "\r\n")] = 0; // (Removes new line) Taken from: https://stackoverflow.com/a/28462221
            userInput[JHU_IOCTL_MESSAGE_LIMIT] = '\0';
            // printf("[me]: %s\n", userInput);

            // SMATOS2, EFORTE3: Encrypt User Input
            ciphertext_len = encrypt(userInput, strlen(userInput), client_crypto.write_crypto_info.KEY, client_crypto.write_crypto_info.IV, ciphertext);
            if (ciphertext_len < 0) {
                printf("An error was encountered, please restart both clients.\n");
                close(client_crypto.write_fd);
                close(client_crypto.read_fd);
                exit(1);
            }

            // SMATOS2, EFORTE3: Send Encrypted Input to Client B
            write(client_crypto.write_fd, ciphertext, ciphertext_len);
            if (errno != 0) {
                printf("An error was encountered with code %d, please restart both clients.\n", errno);
                close(client_crypto.write_fd);
                close(client_crypto.read_fd);
                exit(1);
            }

            // SMATOS2, EFORTE3: Wait on Client B to Respond
            printf("Waiting for client b...\n");
            while (1) {
                num_read = read(client_crypto.read_fd, read_msg, JHU_IOCTL_MESSAGE_LIMIT);
                if (errno != 0) {
                    printf("An error was encountered with code %d, please restart both clients.\n", errno);
                    close(client_crypto.write_fd);
                    close(client_crypto.read_fd);
                    exit(1);
                }
                read_msg[JHU_IOCTL_MESSAGE_LIMIT] = '\0';
                // SMATOS2, EFORTE3: Number of Bytes Read must be greater than 0
                if (num_read <= 0) {
                    sleep(0.5);
                } else {
                    break;
                }
            }

            // SMATOS2, EFORTE3: Client B Responded
            if (num_read > 0) {

                // SMATOS2, EFORTE3: Decrypt the ciphertext
                decryptedtext_len = decrypt(read_msg, num_read, client_crypto.read_crypto_info.KEY, client_crypto.read_crypto_info.IV, decryptedtext);

                // SMATOS2, EFORTE3: Add a NULL terminator since we are expecting printable text
                decryptedtext[decryptedtext_len] = '\0';

                // SMATOS2, EFORTE3: Show the decrypted text
                printf("[b]: %s\n", decryptedtext);
            }
        }
    }

    // SMATOS2, EFORTE3: Trigger when argument is 'a'
    if (strchr(argv[1], 'b') != NULL) {

        // SMATOS2, EFORTE3
        // If user inputs b, we read from b and write to a
        // This call sets Encryption Info and tries to obtain KEY/IV info for 60 seconds
        struct jhu_crypto_client client_crypto = init_client_crypto('b', devname_a, devname_b);
        bool is_ready = client_crypto.is_crypto_initialized && client_crypto.is_read_client_ready && client_crypto.is_write_client_ready;
        if (!is_ready) {
            if (client_crypto.read_fd != -1) {
                close(client_crypto.read_fd);
            }
            if (client_crypto.write_fd != -1) {
                close(client_crypto.read_fd);
            }
            return -1;
        }

        printf("Please type your input below. The received data from \"a\" will show up as [a]:\n");
        printf("Your input will show up as [me]:\n");

        // SMATOS2, EFORTE3: Init Locals
        int num_read = 0, ciphertext_len = 0, decryptedtext_len = 0;
        char read_msg[JHU_IOCTL_MESSAGE_LIMIT] = {0};
        char userInput[JHU_IOCTL_MESSAGE_LIMIT] = {0};
        unsigned char ciphertext[JHU_IOCTL_MESSAGE_LIMIT] = {0};
        unsigned char decryptedtext[JHU_IOCTL_MESSAGE_LIMIT] = {0};

        // SMATOS2, EFORTE3: Start Client
        while (1) {

            // SMATOS2, EFORTE3: Take user input to write to client A
            printf("[me]: ");
            fgets(userInput, JHU_IOCTL_MESSAGE_LIMIT, stdin);
            userInput[strcspn(userInput, "\r\n")] = 0; // (Removes new line) Taken from: https://stackoverflow.com/a/28462221
            userInput[JHU_IOCTL_MESSAGE_LIMIT] = '\0';
            // printf("[me]: %s\n", userInput);

            // SMATOS2, EFORTE3: Encrypt User Input
            ciphertext_len = encrypt(userInput, strlen(userInput), client_crypto.write_crypto_info.KEY, client_crypto.write_crypto_info.IV, ciphertext);
            if (ciphertext_len < 0) {
                printf("An error was encountered, please restart both clients.\n");
                close(client_crypto.write_fd);
                close(client_crypto.read_fd);
                exit(1);
            }

            // SMATOS2, EFORTE3: Send Encrypted Input to Client A
            write(client_crypto.write_fd, ciphertext, ciphertext_len);
            if (errno != 0) {
                printf("An error was encountered with code %d, please restart both clients.\n", errno);
                close(client_crypto.write_fd);
                close(client_crypto.read_fd);
                exit(1);
            }

            // SMATOS2, EFORTE3: Wait on Client A to Respond
            printf("Waiting for client a...\n");
            while (1) {
                num_read = read(client_crypto.read_fd, read_msg, JHU_IOCTL_MESSAGE_LIMIT);
                if (errno != 0) {
                    printf("An error was encountered with code %d, please restart both clients.\n", errno);
                    close(client_crypto.write_fd);
                    close(client_crypto.read_fd);
                    exit(1);
                }
                read_msg[JHU_IOCTL_MESSAGE_LIMIT] = '\0';
                // SMATOS2, EFORTE3: Number of Bytes Read must be greater than 0
                if (num_read <= 0) {
                    sleep(0.5);
                } else {
                    break;
                }
            }

            // SMATOS2, EFORTE3: Client A Responded
            if (num_read > 0) {

                // SMATOS2, EFORTE3: Decrypt the ciphertext
                decryptedtext_len = decrypt(read_msg, num_read, client_crypto.read_crypto_info.KEY, client_crypto.read_crypto_info.IV, decryptedtext);

                // SMATOS2, EFORTE3: Add a NULL terminator since we are expecting printable text
                decryptedtext[decryptedtext_len] = '\0';

                // SMATOS2, EFORTE3: Show the decrypted text
                printf("[a]: %s\n", decryptedtext);
            }
        }
    }

    return 0;
}

// SMATOS2, EFORTE3: Initializes a Client both Devices and exchanges Crypto Info
// This implements the logic of calling a Device Driver with Key/IV info
// It also waits 60 seconds for the other client to be ready
struct jhu_crypto_client init_client_crypto(char client, char *devname_a, char *devname_b)
{

    // SMATOS2, EFORTE3: Init Locals
    int rc_key, rc_iv;                                            // KEY/IV Init Return Codes
    int fd_read, fd_write;                                        // FD's for Read and Write
    int sleep_limit = 60;                                         // Sleep Timeout
    int ioctl_read_rc, ioctl_write_rc;                            // Responses from IOCTL calls
    struct jhu_crypto_client crypto_client;                       // Client Initialization Structure
    char opposite_client = (client == 'a') ? 'b' : 'a';           // Used to determine the client this client will talk to
    char *dev_to_read = (client == 'a') ? devname_a : devname_b;  // Used to determine the device to read from
    char *dev_to_write = (client == 'a') ? devname_b : devname_a; // Used to determine the device to write to

    printf("Setting up encryption info for client %c \n", client);
    // SMATOS2, EFORTE3: Init Client's Struct with Safe Defaults
    crypto_client.read_fd = -1;
    crypto_client.write_fd = -1;
    crypto_client.is_read_client_ready = false;
    crypto_client.is_write_client_ready = false;
    crypto_client.is_crypto_initialized = false;

    // SMATOS2, EFORTE3: Setup Current Client Crypto Info for Reading
    rc_key = RAND_bytes(crypto_client.read_crypto_info.KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN);
    rc_iv = RAND_bytes(crypto_client.read_crypto_info.IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);
    if (!rc_iv || !rc_key) {
        printf("Unable to retrieve Random Bytes for %c \n", client);
        return crypto_client;
    }
    crypto_client.is_crypto_initialized = true;

    // SMATOS2, EFORTE3
    // Send Current Client's Crypto Info for to the Opposing Client to allow him to read this client's messages
    // Also open opposing client's device for writing since this client will be sending messages to him
    printf("Sending encryption info to client %c on device %s \n", opposite_client, dev_to_write);
    fd_write = open(dev_to_write, O_WRONLY);
    if (fd_write < 0 || errno != 0) {
        printf("Can't open device file: %s for writing \n", dev_to_write);
        return crypto_client;
    }
    // SMATOS2, EFORTE3: Perform the IOCTL write of KEY/IV Information
    ioctl_write_rc = ioctl_set_data(fd_write, crypto_client.read_crypto_info.KEY, crypto_client.read_crypto_info.IV);
    if (ioctl_write_rc < 0 || errno != 0) {
        printf("Can't initialize KEY/IV for writing on %s \n", dev_to_write);
        close(fd_write);
        return crypto_client;
    }
    crypto_client.write_fd = fd_write;
    crypto_client.is_write_client_ready = true;

    // SMATOS2, EFORTE3
    // Retrieve Crypto Info for the Opposing Client in order to be able to encrypt the messages this client will send him
    // Also open this client's device for reading messages encrypted with this clients crypto info
    printf("Preparing to wait for %c on device %s \n", opposite_client, dev_to_read);
    fd_read = open(dev_to_read, O_RDONLY);
    if (fd_read < 0 || errno != 0) {
        printf("Can't open device file: %s for reading\n", dev_to_read);
        close(fd_write);
        return crypto_client;
    }
    // SMATOS2, EFORTE3: Perform the IOCTL read of KEY/IV Information
    ioctl_read_rc = ioctl_read_data(fd_read, &crypto_client.write_crypto_info);
    // SMATOS2, EFORTE3: Retry each second up to 60 seconds if the opposing client is not ready (has not sent KEY/IV info)
    while (sleep_limit > 0 && errno == EAGAIN) {
        printf("Waiting for %c... %d \n", opposite_client, sleep_limit);
        sleep_limit--;
        sleep(1);
        errno = 0; // Once errno is not 0, it stays that way unless you acknowledge it for the ioctl
        ioctl_read_rc = ioctl_read_data(fd_read, &crypto_client.write_crypto_info);
    }
    if (ioctl_read_rc < 0 || errno != 0) {
        printf("Can't retrieve KEY/IV for writing on %s \n", dev_to_write);
        close(fd_write);
        close(fd_read);
        return crypto_client;
    }

    printf("%c is ready.\n", client);

    crypto_client.read_fd = fd_read;
    crypto_client.is_read_client_ready = true;

    return crypto_client;
}

// SMATOS2, EFORTE3: Sends IOCTL WRITE to the Device
// This is used to write KEY/IV information
int ioctl_set_data(int fd, const unsigned char *key, const unsigned char *IV)
{

    printf("[+] %s called\n", __FUNCTION__);

    // SMATOS2, EFORTE3: Create jhu_ioctl_crypto based on Input
    struct jhu_ioctl_crypto crypto_info;
    strncpy(crypto_info.KEY, key, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN);
    strncpy(crypto_info.IV, IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);

    // SMATOS2, EFORTE3: Print Key/IV for debugging purposes
    printf("[+] Key Written is:\n");
    BIO_dump_fp(stdout, crypto_info.KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN);
    printf("[+] IV Written is:\n");
    BIO_dump_fp(stdout, crypto_info.IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);

    // SMATOS2, EFORTE3: Send IOCTL command
    ioctl(fd, IOCTL_WRITE_TO_KERNEL, &crypto_info);

    return 0;
}

// SMATOS2, EFORTE3: Sends IOCTL READ to the Device
// This is used to read KEY/IV information
int ioctl_read_data(int fd, struct jhu_ioctl_crypto *crypto_info)
{

    printf("[+] %s called\n", __FUNCTION__);

    // SMATOS2, EFORTE3: Send IOCTL command
    ioctl(fd, IOCTL_READ_FROM_KERNEL, crypto_info);

    // SMATOS2, EFORTE3: Print Key/IV for debugging purposes
    printf("[+] Key Read is:\n");
    BIO_dump_fp(stdout, crypto_info->KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN);
    printf("[+] IV Read is:\n");
    BIO_dump_fp(stdout, crypto_info->IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);

    return 0;
}

// SMATOS2, EFORTE3
// Taken From https://stackoverflow.com/questions/4217037/catch-ctrl-c-in-c
// Add Signal Handler for Nice Message on Exit
void sigint_handler(int sig)
{
    printf("\nQuiting process %d\n", getpid());
    exit(0);
}

// SMATOS2, EFORTE3 Taken/Modified from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Encrypting_the_message
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// SMATOS2, EFORTE3 Taken/Modified from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Decrypting_the_Message
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}