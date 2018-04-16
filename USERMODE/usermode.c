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

int ioctl_read_data_evp(int fd, struct jhu_ioctl_crypto *crypto_info)
{

    printf("[+] %s called\n", __FUNCTION__);

    ioctl(fd, IOCTL_READ_FROM_KERNEL_EVP, crypto_info);

    printf("[+] key read is %s, IV read is %s, total struct size %lu\n", crypto_info->KEY, crypto_info->IV, sizeof(crypto_info));

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
    char set_data[32];
    char read_data[32];
    char devname_a[32];
    char devname_b[32];
    memset(read_data, 0, 32);

    strcpy(set_data, "Hello world!\n");

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

    // Client A for Writing

    fd_aw = open(devname_b, O_WRONLY);

    if (fd_aw < 0)
    {
        printf("Can't open device file: %s for writing \n", DEVICE_NAME_B);
        return -1;
    }

    ret_aw = ioctl_set_data_evp(fd_aw, "01234567890123456789012345678901", "0123456789012345");

    // Client B for Writing

    fd_bw = open(devname_a, O_WRONLY);

    if (fd_bw < 0)
    {
        printf("Can't open device file: %s for writing \n", DEVICE_NAME_A);
        return -1;
    }

    ret_bw = ioctl_set_data_evp(fd_bw, "10987654321098765432109876543210", "5432109876543210");

    // Client A for Reading

    fd_ar = open(devname_a, O_RDONLY);

    if (fd_ar < 0)
    {
        printf("Can't open device file: %s for reading\n", DEVICE_NAME_A);
        return -1;
    }

    ret_ar = ioctl_read_data_evp(fd_ar, &crypto_info_a);

    // Client B for Reading

    fd_br = open(devname_b, O_RDONLY);

    if (fd_br < 0)
    {
        printf("Can't open device file: %s for reading\n", DEVICE_NAME_B);
        return -1;
    }

    ret_br = ioctl_read_data_evp(fd_br, &crypto_info_b);

    // ret = ioctl_set_data(fd, set_data);
    // ret = ioctl_read_data(fd, read_data);

    //
    // You will also use the read() and write() system calls
    //

    close(fd_ar);
    close(fd_aw);
    close(fd_br);
    close(fd_bw);

    return 0;
}
