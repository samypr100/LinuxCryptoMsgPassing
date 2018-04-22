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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//
// This header is required for the ioctl() call
#include <sys/ioctl.h>

// SMATOS2, EFORTE3 LibSSL
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


// SMATOS2, EFORTE3 Modified from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Encrypting_the_message
void handleErrors(void)
{
    printf("An error occured with the encryption, and my error handling is bad\n");
    //ERR_print_errors_fp(stderr);
    //printf(stderr);
    abort();
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        handleErrors();
    }
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
        handleErrors();
    }

    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
        handleErrors();
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        handleErrors();
    }

    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
        handleErrors();
    }
    
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


// SMATOS2, EFORTE3 Crypt Test Function
int cryptTest(void)
{
    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char *plaintext = (unsigned char *)"Encrypt this for oss_695_412 project 2";
    printf("The pre-encrypted text: ");
    printf("%s\n",plaintext);

    /* Buffer for ciphertext. Ensure the buffer is long enough for the
    * ciphertext which may be longer than the plaintext, dependant on the
    * algorithm and mode
    */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;


    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv, ciphertext);

    /* Do something useful with the ciphertext here */
    //printf("Ciphertext is:\n");
    //BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);


    return 0;
}




int ioctl_set_data(int fd, char *data)
{
    int i;
    char c;

    printf("[+] %s called\n", __FUNCTION__);

    ioctl(fd, IOCTL_WRITE_TO_KERNEL, data);

    printf("[+]    Data written: %s\n", data);

    return 0;
}

int ioctl_read_data(int fd, char *data)
{
    int i;
    char c;

    printf("[+] %s called\n", __FUNCTION__);

    ioctl(fd, IOCTL_READ_FROM_KERNEL, data);

    printf("[+]    Data read: %s\n", data);

    return 0;
}

int ioctl_set_data_evp(int fd, const unsigned char *key, const unsigned char *IV)
{

    printf("[+] %s called\n", __FUNCTION__);

    struct jhu_ioctl_crypto crypto_info;
    strncpy(crypto_info.KEY, key, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN);
    strncpy(crypto_info.IV, IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);
    // make sure they're NULL terminated...
    crypto_info.KEY[JHU_IOCTL_CRYPTO_KEY_CHAR_LEN - 1] = '\0';
    crypto_info.IV[JHU_IOCTL_CRYPTO_IV_CHAR_LEN - 1] = '\0';

    printf("[+] key to write is %s, IV to write is %s, total struct size %lu\n", crypto_info.KEY, crypto_info.IV, sizeof(crypto_info));

    ioctl(fd, IOCTL_WRITE_TO_KERNEL_EVP, &crypto_info);

    return 0;
}

int ioctl_read_data_evp(int fd, struct jhu_ioctl_crypto *crypto_info)
{

    printf("[+] %s called\n", __FUNCTION__);

    ioctl(fd, IOCTL_READ_FROM_KERNEL_EVP, crypto_info);

    printf("[+] key read is %s, IV read is %s, total struct size %lu\n", crypto_info->KEY, crypto_info->IV, sizeof(*crypto_info));

    return 0;
}

int main(int argc, char **argv)
{
    int fd_ar = -1;
    int fd_aw = -1;
    int fd_br = -1;
    int fd_bw = -1;
    int ret_ar = -1;
    int ret_aw = -1;
    int ret_br = -1;
    int ret_bw = -1;
    struct jhu_ioctl_crypto crypto_info_a;
    struct jhu_ioctl_crypto crypto_info_b;
    char devname_a[32];
    char devname_b[32];
    unsigned char iv_a[16];
    unsigned char iv_b[16];

    if (argc < 2 || argv[1] == NULL) {
        printf("Usage: ./myuser [a or b] \n");
        printf("Please enter an argument \n");
        return -1;
    }
    printf("Setting up encryption info...\n");
    printf("Waiting for device to be ready...\n");

    //Debuging arguments
    //printf(argv[1]);

    // TODO
    // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Encrypting_the_message
    // EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    // const unsigned char *key;
    // const unsigned char *IV;
    // EVP_EncryptInit(ctx, cipher, key, IV);
    strcpy(devname_a, "/dev/");
    strcpy(devname_b, "/dev/");
    strcat(devname_a, DEVICE_NAME_A);
    strcat(devname_b, DEVICE_NAME_B);

    // Initialize Randomness Pool for Seeding
    // https://wiki.openssl.org/index.php/Random_Numbers
    int rc = RAND_load_file("/dev/urandom", 32); // TODO: switch to /dev/random later (since /dev/random is precious)
    if (rc != 32) {
        printf("Unable to Initialize Seed\n");
        return -1;
    }

    int rc_iv_a = RAND_bytes(iv_a, sizeof(iv_a));
    int rc_iv_b = RAND_bytes(iv_b, sizeof(iv_b));
    if (!rc_iv_a || !rc_iv_b) {
        printf("Unable to retrieve Random Bytes\n");
        return -1;
    }



    // Client A for Writing to Device B

    fd_aw = open(devname_b, O_WRONLY);

    if (fd_aw < 0) {
        printf("Can't open device file: %s for writing \n", DEVICE_NAME_B);
        return -1;
    }

    ret_aw = ioctl_set_data_evp(fd_aw, "01234567890123456789012345678901", "0123456789012345");
    // ret_aw = ioctl_set_data_evp(fd_aw, "01234567890123456789012345678901", iv_a);

    if (ret_aw < 0) {
        printf("Can't initialize KEY/IV for writing on %s \n", DEVICE_NAME_B);
        close(fd_aw);
        return -1;
    }

    // Client B for Writing to Device A

    fd_bw = open(devname_a, O_WRONLY);

    if (fd_bw < 0) {
        printf("Can't open device file: %s for writing \n", DEVICE_NAME_A);
        return -1;
    }

    ret_bw = ioctl_set_data_evp(fd_bw, "10987654321098765432109876543210", "5432109876543210");
    // ret_bw = ioctl_set_data_evp(fd_bw, "10987654321098765432109876543210", iv_b);

    if (ret_bw < 0) {
        printf("Can't initialize KEY/IV for writing on %s \n", DEVICE_NAME_A);
        close(fd_aw);
        close(fd_bw); // I know this is horrible, fix later
        return -1;
    }

    // Client A for Reading from Device A

    fd_ar = open(devname_a, O_RDONLY);

    if (fd_ar < 0) {
        printf("Can't open device file: %s for reading\n", DEVICE_NAME_A);
        return -1;
    }

    ret_ar = ioctl_read_data_evp(fd_ar, &crypto_info_a);

    if (ret_ar < 0) {
        printf("Can't retrieve KEY/IV for reading on %s \n", DEVICE_NAME_A);
        close(fd_aw);
        close(fd_bw);
        close(fd_ar); // I know this is horrible, fix later
        return -1;
    }

    // Client B for Reading from Device B

    fd_br = open(devname_b, O_RDONLY);

    if (fd_br < 0) {
        printf("Can't open device file: %s for reading\n", DEVICE_NAME_B);
        return -1;
    }

    ret_br = ioctl_read_data_evp(fd_br, &crypto_info_b);

    if (ret_ar < 0) {
        printf("Can't retrieve KEY/IV for reading on %s \n", DEVICE_NAME_B);
        close(fd_aw);
        close(fd_bw);
        close(fd_ar);
        close(fd_br); // I know this is horrible, fix later
        return -1;
    }

    char msg_1024[] = "dO1bLdFZuABpJ2nwfvKSPUfmoTPWVVUS1WTCEaPKJmILUj1pRx3HEueHuIhlC9nE2v3XWEuxijw2tJSTJiozuWSYEfFEvpvjBnqx9eeIx5UWEH27M1FqIhQRQcftwB2V5Xo8EpkZ47NSZ4FzQSPtORjuyT9aaZFrR7NV1ESkR7ZvTYMBdib3biAc4MOOfJDvNNDqM4NMS4BqFGJuIPL8dIyNrGXd5AwUX5qUPsYR2EDSmic6wQXAermGtmXgncqJKeMVmgO3zXm9LvIatTZHxRT7WSMeg1bOEYCVs3S5byEZdJV37cTNPoP27L4oJOhAVCWrWAl3o1jllzm2oTOIXgeZ3v43sgZ6PXaf5k93t5VbdYHUooeWXb2B3S4U2SsRVaHQBpsUSrXpGPpLVp0MstTHqIYdnhkGpdLMv6pMMQP22T9tencSdOtcsBkQF1tkMAIbzuPvJzJVMsuQ15MjzZUnQQ8cXeLwnZeFdqMeigIr8aSXvAgOTPJJIijVBxpMQo8nArqT7aOfsXzDUMkEgCN9rh2CPYbhGYegcin2gKsFxxpDaCxaukmMkqhamZaaklJXoi3XeBrmY15wiReU6xsjjPaDEOYn1vFXbwXN12exfVg0MLwTTlCmGUCXbQzBQa3omVLQ94z91I7obVTFdq5JOYV1wDuQDuPQdsChLmz933k9Vqr7er7pPK3iLMpYQ0igGDKNxc1J7UtsoOxAszW1QAEZYhIpTtIGWYV5gUifbVNw5c6F3dPN5HHPCOkpG4SBtLKagdnbk7toNK1LsKdTKHEQ6pTLq6zKHt5MG7AxnoPqH1jU05UNui74wPUL2A1QB9lPGPIdrT041z1LDqOqS1gCIcCkmcXAwoOx4ISMZOIJtlQGXA5RvyJbCVarvLjR8fsu14Tp2ygmHcOd45xsKDwZEtaGRhWRbu70DEGULK8rt3sYYqCUbmPCvr5WWovhDsWNIERssUrwEewzdpN6ieCrdy4xNQDXoJgn0JP5FMNKNjl8bRKQNxKhIeg9";
    char msg_512_a[] = "UBJAypUPyQICrVC1bYigZeozibRxuNWZZlwANoNkoGjdeztxAtNXdKhKBKVTaSvfdIficGWNI7JHTiUmwKiOPLrITrLriV8apbbrq8ACFtwJt1nndYEsA7IK4uj1INo1P1rlhqzHN9qkp1qaIcA5ZB3uoHZaycEJw3VFrqw7yLHTKV5Eu9TiQ2Jlv4VSvgnodG0SIrchZO7oeAP7svBoZ9FwYmPOVZmBslMtL1xHFdcQOcunkPQwzGKH9ndH8y0LNOvXOIt6m7t3kuDDQdoV0s2sI1WscymNYMVduCOAXWrQ2KZ2vrZtUtiejIH3O1tNizChHP0k7tOmaD8xEZmPrstRliCZqBUrxHnuIrgKrKhZAmyEEcs4j5TnHzkDkYcVOOcXTOOhtQ70K1K7Ja7AN5EWxDiJicNtn1mkyYjiSsMOEwSY0TZoaYfX9a2GuRUzLUa8qegnk87sq5AD9Qbbws8xeOT2yWTgogBgvKrJqdkyQ0a01l4ZIXN0bg75aKWp";
    char msg_512_b[] = "0gXAADTDsp5eUtyCrxG3XqtVWJ1ShAlu5tvbBfQF3EibtExjRe7nUWyQrrjrYN6cn8Mv6epmz4yBnfYaHdqiVdPM2QIOFGm46iBtLVd12h9QO1u14jG33w4AnFYUEwVjIltiTlqU040Pqu9za2NlrZt8ng4AqSENHUQ3LeJF0z4chjut0pHVBZEMKcPoaofaxyC0a6WpBiyX4H2P5nTGdspfU5zMWjIGLuRiZHZnyfLtHg6gnPhg8OOWijR1V63ajuNzvEgAtCUFZYKA92Zrimog9bqoqn4aJ4omdhRhnqe6Jezx1AsVGkS0DWLELXPgxJuESs4OQf77dIdvytbusounhLiiZfLMsxleKloYLVmDMM90M28hyKareDa2iuXMJpznisH4tqVJBNrd0alZr15rKSY0HTKDnqDLuGATNyY0XSBaiBnrQAX0Qc9wb6ugtuEC2ZZ33fGURYaJ1U6nBhrjftWXhegPiz6dPWDxmhuyg7keX5EcSJDoCMxtmRHX";
    char msg_2[] = "ab";
    // write(fd_aw, msg_1024, sizeof(msg_1024));
    // write(fd_aw, msg_2, sizeof(msg_2));
    write(fd_aw, msg_512_a, sizeof(msg_512_a));
    write(fd_aw, msg_512_b, sizeof(msg_512_b));
    char read_msg[1025];
    read(fd_br, read_msg, 1025);
    printf("Read msg %s %zu\n", read_msg, strlen(read_msg));

    close(fd_aw);
    close(fd_bw);
    close(fd_ar);
    close(fd_br);

    cryptTest();

    //TODO
    //1. Send IV/KEY information between devices (depending on device, one sends one recives)
    //2. Setup User interaction to recive data and encrypt then transmit to device
    //3. Recive data from device and decrypt



    return 0;
}
