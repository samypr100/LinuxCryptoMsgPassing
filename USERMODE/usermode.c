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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

//
// This header is required for the ioctl() call
#include <sys/ioctl.h>

// SMATOS2 LibSSL
#include <openssl/evp.h>
#include <openssl/aes.h>

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

int ioctl_read_data_evp(int fd)
{

    printf("[+] %s called\n", __FUNCTION__);

    struct jhu_ioctl_crypto crypto_info;

    ioctl(fd, IOCTL_READ_FROM_KERNEL_EVP, &crypto_info);

    printf("[+] key read is %s, IV read is %s, total struct size %lu\n", crypto_info.KEY, crypto_info.IV, sizeof(crypto_info));

    return 0;
}

int main(int argc, char **argv)
{
    int fd = -1;
    int ret = -1;
    char set_data[32];
    char read_data[32];

    memset(read_data, 0, 32);

    strcpy(set_data, "Hello world!\n");

    // TODO
    // EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    // const unsigned char *key;
    // const unsigned char *IV;
    // EVP_EncryptInit(ctx, cipher, key, IV);

    char devname[32];
    strcpy(devname, "/dev/");
    strcat(devname, DEVICE_NAME_A);

    fd = open(devname, O_RDONLY);

    if (fd < 0)
    {
        printf("Can't open device file: %s\n", DEVICE_NAME_A);
        return -1;
    }

    ret = ioctl_set_data(fd, set_data);
    ret = ioctl_read_data(fd, read_data);

    ret = ioctl_set_data_evp(fd, "01234567890123456789012345678901", "0123456789012345");
    ret = ioctl_read_data_evp(fd);

    //
    // You will also use the read() and write() system calls
    //

    close(fd);

    return 0;
}
