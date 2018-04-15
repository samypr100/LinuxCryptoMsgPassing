/*********************************************************************
*
* This is a character device driver header file for
* JHU Operating Systems Security (695.412)
*
*
* Original Author: T. McGuire
* Modified By: Samuel Matos, Eric Forte
* License: GPL
*
*
*********************************************************************/
#ifndef JHU_OSS_CHAR_H
#define JHU_OSS_CHAR_H

//
// This header is required for ioctl functionality
//
#include <linux/ioctl.h>

// SMATOS2,EFORTE3 Declaring the two devices
#define DEVICE_NAME_A "secret412a"
#define DEVICE_NAME_B "secret412b"

//
// The below comments are taken from Documentation/ioctl/ioctl-number.txt
// within the Linux v4.15.2 source tree
//
// The "identifying letter or number" table was not copied. You can look
// at the above file for the complete table. For this exercise, you can
// pick a simple value
//
// ---------------------------------------------------------------------
//
// If you are adding new ioctl's to the kernel, you should use the _IO
// macros defined in <linux/ioctl.h>:
//
//     _IO    an ioctl with no parameters
//     _IOW   an ioctl with write parameters (copy_from_user)
//     _IOR   an ioctl with read parameters  (copy_to_user)
//     _IOWR  an ioctl with both write and read parameters.
//
// 'Write' and 'read' are from the user's point of view, just like the
// system calls 'write' and 'read'.  For example, a SET_FOO ioctl would
// be _IOW, although the kernel would actually read data from user space;
// a GET_FOO ioctl would be _IOR, although the kernel would actually write
// data to user space.
//
// The first argument to _IO, _IOW, _IOR, or _IOWR is an identifying letter
// or number from the table below.  Because of the large number of drivers,
// many drivers share a partial letter with other drivers.
//
// If you are writing a driver for a new device and need a letter, pick an
// unused block with enough room for expansion: 32 to 256 ioctl commands.
// You can register the block by patching this file and submitting the
// patch to Linus Torvalds.  Or you can e-mail me at <mec@shout.net> and
// I'll register one for you.
//
// The second argument to _IO, _IOW, _IOR, or _IOWR is a sequence number
// to distinguish ioctls from each other.  The third argument to _IOW,
// _IOR, or _IOWR is the type of the data going into the kernel or coming
// out of the kernel (e.g.  'int' or 'struct foo').  NOTE!  Do NOT use
// sizeof(arg) as the third argument as this results in your ioctl thinking
// it passes an argument of type size_t.
//

#define JHU_IOCTL_MAGIC 208 // picking 0xd0

// base sequence number
#define JHU_IOCTL_BASE_SEQ 0

// read from kernel sequence number is base + 1
#define JHU_IOCTL_RFK (JHU_IOCTL_BASE_SEQ + 1)

// write to kernel sequence number is base + 2
#define JHU_IOCTL_WTK (JHU_IOCTL_BASE_SEQ + 2)

// read from kernel sequence number is base evp + 3
#define JHU_IOCTL_RFK_EVP (JHU_IOCTL_BASE_SEQ + 3)

// write to kernel sequence number is base evp + 4
#define JHU_IOCTL_WTK_EVP (JHU_IOCTL_BASE_SEQ + 4)

//
// _IOR() creates an IOCTL that is reading from the kernel
//        JHU_IOCTL_MAGIC is the magic byte
//
// The last argument might be better suited as a structure!
//

/*
 * For Sending Encryption Info using 256-bit CBS
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */
#define JHU_IOCTL_CRYPTO_KEY_CHAR_LEN 32 + 1

#define JHU_IOCTL_CRYPTO_IV_CHAR_LEN 16 + 1

#define JHU_IOCTL_CRYPTO
struct jhu_ioctl_crypto
{
    unsigned char KEY[JHU_IOCTL_CRYPTO_KEY_CHAR_LEN]; // 32 len unsigned char should be 256-bit
    unsigned char IV[JHU_IOCTL_CRYPTO_IV_CHAR_LEN];   // 16 len unsigned char should be 128-bit IV (IV should be same as block size)
};

#define IOCTL_READ_FROM_KERNEL _IOR(JHU_IOCTL_MAGIC, JHU_IOCTL_RFK, char *)

#define IOCTL_WRITE_TO_KERNEL _IOWR(JHU_IOCTL_MAGIC, JHU_IOCTL_WTK, char *)

#define IOCTL_READ_FROM_KERNEL_EVP _IOR(JHU_IOCTL_MAGIC, JHU_IOCTL_RFK_EVP, struct jhu_ioctl_crypto)

#define IOCTL_WRITE_TO_KERNEL_EVP _IOWR(JHU_IOCTL_MAGIC, JHU_IOCTL_WTK_EVP, struct jhu_ioctl_crypto)

#endif // JHU_OSS_CHAR_H
