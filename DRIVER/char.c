/*********************************************************************
*
* This is a character device driver for 
* JHU Operating Systems Security (695.412)
*
*
* Original Author: T. McGuire
* Modified By: Samuel Matos, Eric Forte
* License: GPL
*
*
*********************************************************************/
#include <linux/init.h>

// Contains types, macros, functions for the kernel
#include <linux/kernel.h>

// The header for loadable kernel modules
#include <linux/module.h>

// The header for kernel device structures
#include <linux/device.h>

// The header for the Linux file system support
#include <linux/fs.h>

// Required for the copy to user function
#include <linux/uaccess.h>

// Memory Allocation
#include <linux/slab.h>

// Using a common header file for usermode/kernel mode code
#include "../COMMON/char_ioctl.h"

//
// Setup your class name here
//
#define CLASS_NAME "sec412"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("S. Matos, E. Forte - JHU");
MODULE_DESCRIPTION("Linux character device driver for OSS to provide encryption chat capabilities.");
MODULE_VERSION("4.0.2018");

//
// Setup some global variables for your device
// Note: Below is not an accurate/complete list for the assignment
// You will need to modify these in order to complete the assignment
//

#define MAX_ALLOWED_LEN 16
#define MAX_ALLOWED_MESSAGE 1024 + 1 // Account for null terminator as well...

static int g_majornum_a;
static int g_majornum_b;
static char g_buffer[MAX_ALLOWED_LEN] = {0};
static char msg_a[MAX_ALLOWED_MESSAGE] = {0}; // should hold 1024 1-byte characters + null terminator
static char msg_b[MAX_ALLOWED_MESSAGE] = {0}; // should hold 1024 1-byte characters + null terminator
static struct jhu_ioctl_crypto evp_a;
static struct jhu_ioctl_crypto evp_b;

static struct class *jhu_oss_class = NULL;
static struct device *jhu_oss_device_a = NULL;
static struct device *jhu_oss_device_b = NULL;

//
// Relevant function prototypes that will be used
// for the file_operations structure
//
static int dev_open(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static long dev_ioctl(struct file *, unsigned int, unsigned long);
static int dev_release(struct inode *, struct file *);

//
// Setup the relevant fields within the file_operations structure
// Any non-filled in values will use the system defaults
//
static struct file_operations fops =
    {
        .owner = THIS_MODULE,
        .open = dev_open,
        .read = dev_read,
        .write = dev_write,
        .compat_ioctl = dev_ioctl,
        .unlocked_ioctl = dev_ioctl,
        .release = dev_release,
};

/*
 * SMATOS2, EFORTE3 per-device data
 */
struct dev_private_data {
    bool is_open_for_read;
    bool is_open_for_write;
    bool is_key_initialized;
    bool is_iv_initialized;
    int major;
    int minor;
    struct mutex lock;
    // ...
};

// SMATOS2, EFORTE3
// https://elixir.bootlin.com/linux/v4.15.2/source/drivers/tty/tty_io.c#L3224
// Use to set mode upon device creation to rw-rw-rw-
static char *jhu_oss_char_devnode(struct device *dev, umode_t *mode)
{
    if (!mode) {
        return NULL;
    }
    if (dev->devt == MKDEV(g_majornum_a, 0) || dev->devt == MKDEV(g_majornum_b, 0)) {
        *mode = 0666;
    }
    return NULL;
}

//
// This path is called when the module is being loaded
//
static int __init jhu_oss_char_init(void)
{

    //
    // Register the first device dynamically
    //
    g_majornum_a = register_chrdev(0, DEVICE_NAME_A, &fops);

    if (g_majornum_a < 0) {
        return g_majornum_a;
    }

    printk(KERN_INFO "[+] Successfully registered device A with major number %d\n", g_majornum_a);

    //
    // Register the second device dynamically
    //
    g_majornum_b = register_chrdev(0, DEVICE_NAME_B, &fops);

    if (g_majornum_b < 0) {
        return g_majornum_b;
    }

    printk(KERN_INFO "[+] Successfully registered device B with major number %d\n", g_majornum_b);

    //
    // Create the device class
    //
    jhu_oss_class = class_create(THIS_MODULE, CLASS_NAME);

    if (IS_ERR(jhu_oss_class)) {

        unregister_chrdev(g_majornum_a, DEVICE_NAME_A);
        unregister_chrdev(g_majornum_b, DEVICE_NAME_B);

        printk(KERN_WARNING "[-] Failed to create device class\n");

        return PTR_ERR(jhu_oss_class);
    }

    // SMATOS2, EFORTE3
    // https://elixir.bootlin.com/linux/v4.15.2/source/drivers/tty/tty_io.c#L3224
    // Use to set mode upon device creation to rw-rw-rw-
    jhu_oss_class->devnode = jhu_oss_char_devnode;

    printk(KERN_INFO "[+] Successfully created the device class\n");

    //
    // create the device now
    //

    //
    // NOTE:
    // The MKDEV takes a major/minor pair and creates an appropriate device number
    //
    jhu_oss_device_a = device_create(jhu_oss_class, NULL, MKDEV(g_majornum_a, 0), NULL, DEVICE_NAME_A);
    jhu_oss_device_b = device_create(jhu_oss_class, NULL, MKDEV(g_majornum_b, 0), NULL, DEVICE_NAME_B);

    if (IS_ERR(jhu_oss_device_a) || IS_ERR(jhu_oss_device_b)) {
        class_destroy(jhu_oss_class);

        unregister_chrdev(g_majornum_a, DEVICE_NAME_A);
        unregister_chrdev(g_majornum_b, DEVICE_NAME_B);

        printk(KERN_WARNING "[-] Failed to create device class\n");

        if (IS_ERR(jhu_oss_device_a)) {
            return PTR_ERR(jhu_oss_device_a);
        } else {
            return PTR_ERR(jhu_oss_device_b);
        }
    }

    printk(KERN_INFO "[+] Module successfully initialized\n");

    return 0;
}

//
// This path is called when the module is being unloaded
//
static void __exit jhu_oss_char_exit(void)
{

    printk(KERN_INFO "[*] Unloading the module\n");
    //
    // destroy the created device
    //
    device_destroy(jhu_oss_class, MKDEV(g_majornum_a, 0));
    device_destroy(jhu_oss_class, MKDEV(g_majornum_b, 0));

    //
    // unregister the class
    //
    class_unregister(jhu_oss_class);

    //
    // unregister the character device
    //
    unregister_chrdev(g_majornum_a, DEVICE_NAME_A);
    unregister_chrdev(g_majornum_b, DEVICE_NAME_B);
}

static int dev_open(struct inode *inodep, struct file *filep)
{

    struct dev_private_data *priv_data = filep->private_data;
    bool is_open_read, is_open_write, is_open_valid;
    //
    // Add your checking to this code path
    //
    printk(KERN_INFO "[*] Opening the Device\n");

    // SMATOS2, EFORTE3
    // Check Capability before allowing open
    if (!capable(CAP_SECRET_FOURONETWO)) {
        printk(KERN_WARNING "[*]    Invalid Capability");
        //return -EPERM; TODO UNCOMMENT ME TO ENFOCE THIS LATER AFTER FINALIZING THE MODULE
    }

    // SMATOS2, EFORTE3
    /* enforce read OR write access to this device */
    is_open_read = (filep->f_mode & FMODE_READ) == FMODE_READ;
    is_open_write = (filep->f_mode & FMODE_WRITE) == FMODE_WRITE;
    is_open_valid = (is_open_read || is_open_write) && !(is_open_read && is_open_write);
    if (!is_open_valid) {
        printk(KERN_WARNING "[*]    Invalid Open Mode");
        return -EINVAL;
    }

    // Initialize priv_data for particular device file decriptor
    printk(KERN_INFO "[*]    Initializing State");
    priv_data = kzalloc(sizeof(struct dev_private_data), GFP_KERNEL);
    if (!priv_data) {
        return -ENOMEM;
    }
    priv_data->major = imajor(inodep); // we can use for comparisons later with the major
    priv_data->minor = iminor(inodep); // if we decide to use it...
    priv_data->is_open_for_read = is_open_read ? true : false;
    priv_data->is_open_for_write = is_open_write ? true : false;
    mutex_init(&priv_data->lock);

    printk(KERN_INFO "[*]    Successfully Opened Device\n");
    printk(KERN_INFO "[*]    Init State {isRead: %d, isWrite: %d, isKey: %d, isIV: %d, major: %d, minor: %d}\n",
           priv_data->is_open_for_read, priv_data->is_open_for_write,
           priv_data->is_key_initialized, priv_data->is_iv_initialized,
           priv_data->major, priv_data->minor);

    filep->private_data = priv_data;

    return 0;
}

//
// This path is called when read() is made on the file descriptor
// That is, the user mode program is expected to read data from
// this device
//
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{

    char *buf;
    int max_len_to_read;
    int error = 0;
    bool can_read;
    struct dev_private_data *priv_data = filep->private_data; // device should be opened at this stage...
    struct jhu_ioctl_crypto *correct_device = NULL;
    char *correct_msg = NULL;

    printk(KERN_INFO "[*] Usermode is requesting %zu chars from kernelmode\n", len);

    // better safe than sorry
    if (!priv_data) {
        return -EBADF;
    }

    // verify if we can read and it's initialized properly
    can_read = priv_data->is_open_for_read && priv_data->is_key_initialized && priv_data->is_iv_initialized;
    if (!can_read) {
        printk(KERN_WARNING "[*]    Unable to read data because state is not ready.\n");
        return -EAGAIN;
    }

    // verify what device we're writing to
    if (priv_data->major == g_majornum_a) {
        correct_device = &evp_a;
        correct_msg = msg_a;
    } else if (priv_data->major == g_majornum_b) {
        correct_device = &evp_b;
        correct_msg = msg_b;
    } else {
        return -EFAULT;
    }

    // make sure that the user doesn't attempt to read more than 1024 bytes at a time
    if (len > MAX_ALLOWED_MESSAGE) {
        printk(KERN_WARNING "[*]    Message to read is too long.\n");
        return -EINVAL;
    }

    // atomic operation start
    mutex_lock(&priv_data->lock);

    max_len_to_read = strlen(correct_msg);

    printk(KERN_INFO "[*]    Current Stored Message Size %d\n", max_len_to_read);

    // make sure to read requested len if possible...
    if (len <= max_len_to_read) {
        max_len_to_read = len;
    }

    printk(KERN_INFO "[*]    Going to read %d bytes.\n", max_len_to_read);

    // allocate internal buffer to copy data to
    buf = kzalloc(max_len_to_read + 1, GFP_KERNEL);
    if (buf == NULL) {
        mutex_unlock(&priv_data->lock);
        return -ENOMEM;
    }
    strncpy(buf, correct_msg, max_len_to_read);
    buf[max_len_to_read] = '\0'; // make sure it's null terminated
    error = copy_to_user(buffer, buf, max_len_to_read + 1);
    if (error) {
        kfree(buf);
        mutex_unlock(&priv_data->lock);
        return -EFAULT;
    }

    print_hex_dump(KERN_INFO, "[*]    MSG READ: ", DUMP_PREFIX_NONE, 16, 1, buf, max_len_to_read + 1, true);

    // clear out stored message
    // TODO: should we partition message after read (e.g. shift the non-read bytes at the beggining of the file)
    memset(correct_msg, 0, MAX_ALLOWED_MESSAGE);

    kfree(buf);
    mutex_unlock(&priv_data->lock);

    return max_len_to_read;
}

//
// This path is called when write() is made on the file descriptor
// That is, the user mode program is passing data to this function
//
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{

    // https://github.com/torvalds/linux/blob/v4.15/kernel/printk/printk.c#L756
    char *buf;
    int error = 0;
    bool can_write;
    int curr_space_left;
    struct dev_private_data *priv_data = filep->private_data; // device should be opened at this stage...
    struct jhu_ioctl_crypto *correct_device = NULL;
    char *correct_msg = NULL;

    printk(KERN_INFO "[*] Usermode is writing %zu chars to usermode\n", len);

    // better safe than sorry
    if (!priv_data) {
        return -EBADF;
    }

    // verify if we can write and it's initialized properly
    can_write = priv_data->is_open_for_write && priv_data->is_key_initialized && priv_data->is_iv_initialized;
    if (!can_write) {
        printk(KERN_WARNING "[*]    Unable to write data because state is not ready.\n");
        return -EAGAIN;
    }

    // verify what device we're writing to
    if (priv_data->major == g_majornum_a) {
        correct_device = &evp_a;
        correct_msg = msg_a;
    } else if (priv_data->major == g_majornum_b) {
        correct_device = &evp_b;
        correct_msg = msg_b;
    } else {
        return -EFAULT;
    }

    // make sure that the user doesn't attempt to write more than 1024 bytes at a time
    if (len > MAX_ALLOWED_MESSAGE) {
        printk(KERN_WARNING "[*]    Message to write is too long.\n");
        return -EINVAL;
    }

    // allocate internal buffer to copy data to
    buf = kzalloc(len + 1, GFP_KERNEL);
    if (buf == NULL) {
        return -ENOMEM;
    }

    buf[len] = '\0'; // make sure it's null terminated
    error = copy_from_user(buf, buffer, len);
    if (error) {
        kfree(buf);
        return -EFAULT;
    }

    mutex_lock(&priv_data->lock);

    curr_space_left = MAX_ALLOWED_MESSAGE - strlen(correct_msg); // fyi: when full, curr_space_left should be 1

    printk(KERN_INFO "[*]    Current Space left to write is %d\n", curr_space_left);

    if (len > curr_space_left) {
        kfree(buf);
        mutex_unlock(&priv_data->lock);
        return -E2BIG;
    }

    strncat(correct_msg, buf, len);
    correct_msg[MAX_ALLOWED_MESSAGE] = '\0'; // make sure it's null terminated... always.
    kfree(buf);

    printk(KERN_INFO "[*]    Wrote %zu bytes. \n", len);
    print_hex_dump(KERN_INFO, "[*]    CURR MSG: ", DUMP_PREFIX_NONE, 16, 1, correct_msg, MAX_ALLOWED_MESSAGE, true);

    mutex_unlock(&priv_data->lock);

    return len;
}

long dev_ioctl(struct file *filep, unsigned int ioctl_num, unsigned long ioctl_param)
{
    int i = 0;
    int error = 0;
    char *temp = NULL;
    struct jhu_ioctl_crypto *correct_evp = NULL;
    struct jhu_ioctl_crypto __user *temp_evp = NULL;
    char ch;
    struct dev_private_data *priv_data = filep->private_data; // device should be opened at this stage...

    // better safe than sorry
    if (!priv_data) {
        return -EBADF;
    }

    printk(KERN_INFO "[*] Usermode is requesting %08x ioctl\n", ioctl_num);

    switch (ioctl_num) {
    case IOCTL_READ_FROM_KERNEL:
        printk(KERN_INFO "[*]    IOCTL_READ_FROM_KERNEL\n");
        //
        //  The code below is not safe..be sure to fix it properly
        //  if you use it
        //
        temp = (char *)ioctl_param;
        error = copy_to_user(temp, g_buffer, MAX_ALLOWED_LEN);
        if (error)
            return -EFAULT;
        printk(KERN_INFO "[+]    The message is %s\n", g_buffer);

        break;

    case IOCTL_WRITE_TO_KERNEL:
        printk(KERN_INFO "[*]    IOCTL_WRITE_TO_KERNEL\n");
        temp = (char *)ioctl_param;
        get_user(ch, temp);
        for (i = 0; ch && i < MAX_ALLOWED_LEN; i++, temp++)
            get_user(ch, temp);

        //
        //  The code below is not safe..be sure to fix it properly
        //  if you use it
        //
        memset(g_buffer, 0, MAX_ALLOWED_LEN);
        error = copy_from_user(g_buffer, (char *)ioctl_param, i);
        if (error) {
            return -EFAULT;
        }

        printk(KERN_INFO "[+]    The length passed in is %d\n", i);
        printk(KERN_INFO "[+]    The message is %s\n", g_buffer);

        break;
    case IOCTL_READ_FROM_KERNEL_EVP:
        printk(KERN_INFO "[*]    IOCTL_READ_FROM_KERNEL_EVP\n");
        temp_evp = (struct jhu_ioctl_crypto *)ioctl_param;

        if (priv_data->major == g_majornum_a) {
            correct_evp = &evp_a;
        } else if (priv_data->major == g_majornum_b) {
            correct_evp = &evp_b;
        } else {
            return -ENOENT;
        }

        // TODO we should check if it's null terminated on WRITE
        if (strlen(correct_evp->KEY) != JHU_IOCTL_CRYPTO_KEY_CHAR_LEN - 1) {
            printk(KERN_WARNING "[*]    KEY not initialized properly\n");
            return -EAGAIN;
        }

        // TODO we should check if it's null terminated on WRITE
        if (strlen(correct_evp->IV) != JHU_IOCTL_CRYPTO_IV_CHAR_LEN - 1) {
            printk(KERN_WARNING "[*]    IV not initialized properly\n");
            return -EAGAIN;
        }

        error = copy_to_user(temp_evp->KEY, correct_evp->KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN);
        if (error) {
            return -EFAULT;
        }
        priv_data->is_key_initialized = true;

        error = copy_to_user(temp_evp->IV, correct_evp->IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);
        if (error) {
            return -EFAULT;
        }
        priv_data->is_iv_initialized = true;

        print_hex_dump(KERN_INFO, "[*]    KEY READ ", DUMP_PREFIX_NONE, 16, 1, correct_evp->KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN, true);
        print_hex_dump(KERN_INFO, "[*]    IV READ ", DUMP_PREFIX_NONE, 16, 1, correct_evp->IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN, true);

        printk(KERN_INFO "[*]    Post Read State {isRead: %d, isWrite: %d, isKey: %d, isIV: %d, major: %d, minor: %d}\n",
               priv_data->is_open_for_read, priv_data->is_open_for_write,
               priv_data->is_key_initialized, priv_data->is_iv_initialized,
               priv_data->major, priv_data->minor);

        // TODO Once this is read, we should erase it from the kernel right?

        break;
    case IOCTL_WRITE_TO_KERNEL_EVP:
        printk(KERN_INFO "[*]    IOCTL_WRITE_TO_KERNEL_EVP\n");
        temp_evp = (struct jhu_ioctl_crypto *)ioctl_param;

        if (priv_data->major == g_majornum_a) {
            correct_evp = &evp_a;
        } else if (priv_data->major == g_majornum_b) {
            correct_evp = &evp_b;
        } else {
            return -EFAULT;
        }

        // TODO Does this check if it's null terminated? or strnlen_user does a good job?
        if (strnlen_user(temp_evp->KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN) != JHU_IOCTL_CRYPTO_KEY_CHAR_LEN) {
            printk(KERN_WARNING "[*]    KEY not correct size\n");
            return -EAGAIN;
        }
        // TODO Does this check if it's null terminated? or strnlen_user does a good job?
        if (strnlen_user(temp_evp->IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN) != JHU_IOCTL_CRYPTO_IV_CHAR_LEN) {
            printk(KERN_WARNING "[*]    IV not correct size\n");
            return -EAGAIN;
        }

        memset(correct_evp->KEY, 0, sizeof(correct_evp->KEY));
        error = copy_from_user(correct_evp->KEY, temp_evp->KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN);
        if (error) {
            memset(correct_evp->KEY, 0, sizeof(correct_evp->KEY)); // Clear memory after error
            return -EFAULT;
        }
        priv_data->is_key_initialized = true;

        memset(correct_evp->IV, 0, sizeof(correct_evp->IV));
        error = copy_from_user(correct_evp->IV, temp_evp->IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);
        if (error) {
            memset(correct_evp->KEY, 0, sizeof(correct_evp->KEY)); // Clear memory after error
            return -EFAULT;
        }
        priv_data->is_iv_initialized = true;

        print_hex_dump(KERN_INFO, "[*]    KEY WRITE ", DUMP_PREFIX_NONE, 16, 1, correct_evp->KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN, true);
        print_hex_dump(KERN_INFO, "[*]    IV WRITE ", DUMP_PREFIX_NONE, 16, 1, correct_evp->IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN, true);

        printk(KERN_INFO "[*]    Post Write State {isRead: %d, isWrite: %d, isKey: %d, isIV: %d, major: %d, minor: %d}\n",
               priv_data->is_open_for_read, priv_data->is_open_for_write,
               priv_data->is_key_initialized, priv_data->is_iv_initialized,
               priv_data->major, priv_data->minor);

        break;
    default:
        break;
    }

    return 0;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
    //
    // This path is called when the file descriptor is closed
    //
    struct dev_private_data *priv_data = filep->private_data; // device should be opened at this stage...

    if (!priv_data) {
        return 0;
    }

    mutex_destroy(&priv_data->lock);
    filep->private_data = NULL;
    kfree(priv_data);

    printk(KERN_INFO "[*] Releasing the file\n");

    return 0;
}

module_init(jhu_oss_char_init);
module_exit(jhu_oss_char_exit);
