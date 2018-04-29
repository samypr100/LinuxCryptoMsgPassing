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

// SMATOS2, EFORTE3 Memory Allocation
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

// Define Max Message Size
#define MAX_ALLOWED_MESSAGE 1024 // 1024 chars

static int g_majornum_a;                            // Holds MajorNum for Device A
static int g_majornum_b;                            // Holds MajorNum for Device B
static char g_msg_a[MAX_ALLOWED_MESSAGE + 1] = {0}; // should hold 1024 1-byte characters (0-1023) + null terminator (1024)
static char g_msg_b[MAX_ALLOWED_MESSAGE + 1] = {0}; // should hold 1024 1-byte characters (0-1023) + null terminator (1024)
static int g_offset_a = 0;                          // Serve's as the seek for g_msg_a to know up to where it has been written to.
static int g_offset_b = 0;                          // Serve's as the seek for g_msg_b to know up to where it has been written to.
static struct jhu_ioctl_crypto g_crypto_info_a;     // Holds Crypto Info for Device A
static struct jhu_ioctl_crypto g_crypto_info_b;     // Holds Crypto Info for Device B
static bool g_crypto_initialized_a = false;         // Flag that determines if Crypt Info has been Written for Device A
static bool g_crypto_initialized_b = false;         // Flag that determines if Crypt Info has been Written for Device B
static DEFINE_MUTEX(g_lock_a);                      // Holds Global Lock for Device A
static DEFINE_MUTEX(g_lock_b);                      // Holds Global Lock for Device B

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

//
// SMATOS2, EFORTE3 per-device data
//
struct dev_private_data {
    bool is_open_for_read;                   // Use to determine if this Device is Opened for Read
    bool is_open_for_write;                  // Use to determine if this Device is Opened for Write
    bool is_key_initialized;                 // Use to determine if this Device has Key Information
    bool is_iv_initialized;                  // Use to determine if this Device has IV Information
    int major;                               // This Device Major Num
    int minor;                               // This Device Minor Num
    bool *current_crypto_initialized;        // Holds Reference to the Global Crypto Info Init Flag for the Proper Device
    int *current_offset;                     // Holds Reference to the Global Message Seek for the Proper Device
    char *current_msg;                       // Holds Reference to the Global Message for the Proper Device
    struct mutex *current_lock;              // Holds Reference to the Global Lock for the Proper Device
    struct jhu_ioctl_crypto *current_crypto; // Holds Reference to the Global Crypto Info for the Proper Device
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
        unregister_chrdev(g_majornum_a, DEVICE_NAME_A);
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

    // Create Device A
    jhu_oss_device_a = device_create(jhu_oss_class, NULL, MKDEV(g_majornum_a, 0), NULL, DEVICE_NAME_A);

    if (IS_ERR(jhu_oss_device_a)) {
        class_destroy(jhu_oss_class);                   // Destroy and Unregister Class
        unregister_chrdev(g_majornum_a, DEVICE_NAME_A); // Unregister Device A...
        unregister_chrdev(g_majornum_b, DEVICE_NAME_B); // Unregister Device B...
        printk(KERN_WARNING "[-] Failed to create Device A\n");
        return PTR_ERR(jhu_oss_device_a);
    }

    // Create Device B
    jhu_oss_device_b = device_create(jhu_oss_class, NULL, MKDEV(g_majornum_b, 0), NULL, DEVICE_NAME_B);

    if (IS_ERR(jhu_oss_device_b)) {
        device_destroy(jhu_oss_class, MKDEV(g_majornum_a, 0)); // Destroy Device A since it got created...
        class_destroy(jhu_oss_class);                          // Destroy and Unregister Class
        unregister_chrdev(g_majornum_a, DEVICE_NAME_A);        // Unregister Device A...
        unregister_chrdev(g_majornum_b, DEVICE_NAME_B);        // Unregister Device B...
        printk(KERN_WARNING "[-] Failed to create Device B\n");
        return PTR_ERR(jhu_oss_device_b);
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
    // destroy and unregister the class
    //
    class_destroy(jhu_oss_class);

    //
    // unregister the character device
    //
    unregister_chrdev(g_majornum_a, DEVICE_NAME_A);
    unregister_chrdev(g_majornum_b, DEVICE_NAME_B);
}

static int dev_open(struct inode *inodep, struct file *filep)
{

    struct dev_private_data *priv_data = filep->private_data;
    bool is_open_read, is_open_write, is_open_valid, is_valid_device;
    //
    // Add your checking to this code path
    //
    printk(KERN_INFO "[*] Opening the Device\n");

    // SMATOS2, EFORTE3
    // Check Capability before allowing open
    if (!capable(CAP_SECRET_FOURONETWO)) {
        printk(KERN_WARNING "[*]    Invalid Capability\n");
        //return -EPERM; TODO UNCOMMENT ME TO ENFOCE THIS LATER AFTER FINALIZING THE MODULE
    }

    // SMATOS2, EFORTE3
    /* enforce read OR write access to this device */
    is_open_read = (filep->f_mode & FMODE_READ) == FMODE_READ;
    is_open_write = (filep->f_mode & FMODE_WRITE) == FMODE_WRITE;
    is_open_valid = (is_open_read || is_open_write) && !(is_open_read && is_open_write);
    if (!is_open_valid) {
        printk(KERN_WARNING "[*]    Invalid Open Mode\n");
        return -EINVAL;
    }

    // I'm being extremely paranoid
    is_valid_device = (imajor(inodep) == g_majornum_a) ? true : (imajor(inodep) == g_majornum_b) ? true : false;
    if (!is_valid_device) {
        printk(KERN_WARNING "[*]    Invalid Device\n");
        return -EBADFD;
    }

    // Initialize priv_data for particular device file decriptor
    printk(KERN_INFO "[*]    Initializing State\n");
    priv_data = kzalloc(sizeof(struct dev_private_data), GFP_KERNEL);
    if (!priv_data) {
        return -ENOMEM;
    }
    priv_data->major = imajor(inodep); // we can use for comparisons later with the major
    priv_data->minor = iminor(inodep); // if we decide to use it...
    priv_data->is_open_for_read = is_open_read ? true : false;
    priv_data->is_open_for_write = is_open_write ? true : false;

    if (priv_data->major == g_majornum_a) {
        priv_data->current_crypto_initialized = &g_crypto_initialized_a;
        priv_data->current_crypto = &g_crypto_info_a;
        priv_data->current_lock = &g_lock_a;
        priv_data->current_offset = &g_offset_a;
        priv_data->current_msg = g_msg_a;
    }

    if (priv_data->major == g_majornum_b) {
        priv_data->current_crypto_initialized = &g_crypto_initialized_b;
        priv_data->current_crypto = &g_crypto_info_b;
        priv_data->current_lock = &g_lock_b;
        priv_data->current_offset = &g_offset_b;
        priv_data->current_msg = g_msg_b;
    }

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
static ssize_t dev_read(struct file *filep, char __user *buffer, size_t len, loff_t *offset)
{

    char *kbuf;
    int max_len_to_read;
    int error = 0;
    int i = 0;
    bool can_read;
    struct dev_private_data *priv_data = filep->private_data; // device should be opened at this stage...

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

    // make sure that the user doesn't attempt to read more than 1024 bytes at a time
    if (len > MAX_ALLOWED_MESSAGE) {
        printk(KERN_WARNING "[*]    Message to read %zu is too long.\n", len);
        return -EINVAL;
    }

    // atomic operation start
    mutex_lock(priv_data->current_lock);

    max_len_to_read = *priv_data->current_offset;

    printk(KERN_INFO "[*]    Current Stored Message Size %d\n", max_len_to_read);

    // make sure to read requested len if possible...
    if (len <= max_len_to_read) {
        max_len_to_read = len;
    }

    printk(KERN_INFO "[*]    Going to read %d bytes.\n", max_len_to_read);

    // allocate internal buffer to copy data to
    kbuf = kzalloc(max_len_to_read + 1, GFP_KERNEL);
    if (kbuf == NULL) {
        mutex_unlock(priv_data->current_lock);
        return -ENOMEM;
    }
    kbuf[max_len_to_read] = '\0'; // Add null terminator just in case...

    for (i = 0; i < max_len_to_read; i++) {
        kbuf[i] = priv_data->current_msg[i];
    }

    error = copy_to_user(buffer, kbuf, max_len_to_read);
    if (error) {
        kfree(kbuf);
        mutex_unlock(priv_data->current_lock);
        return -EFAULT;
    }

    printk(KERN_INFO "[*]    READ MSG:\n");
    print_hex_dump(KERN_INFO, "[*]    ", DUMP_PREFIX_NONE, 16, 1, kbuf, max_len_to_read + 1, true);

    // clear out stored message
    // TODO: should we partition message after read (e.g. shift the non-read bytes at the beggining of the file)
    memset(priv_data->current_msg, 0, MAX_ALLOWED_MESSAGE);
    (*priv_data->current_offset) = 0;

    kfree(kbuf);
    mutex_unlock(priv_data->current_lock);

    return max_len_to_read;
}

//
// This path is called when write() is made on the file descriptor
// That is, the user mode program is passing data to this function
//
static ssize_t dev_write(struct file *filep, const char __user *buffer, size_t len, loff_t *offset)
{

    // https://github.com/torvalds/linux/blob/v4.15/kernel/printk/printk.c#L756
    char *kbuf;
    int i = 0;
    int seek = 0;
    int error = 0;
    bool can_write;
    int curr_space_left;
    struct dev_private_data *priv_data = filep->private_data; // device should be opened at this stage...

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

    // make sure that the user doesn't attempt to write more than 1024 bytes at a time
    if (len > MAX_ALLOWED_MESSAGE) {
        printk(KERN_WARNING "[*]    Message to write %zu is too long.\n", len);
        return -EINVAL;
    }

    // allocate internal buffer to copy data to
    kbuf = kzalloc(len + 1, GFP_KERNEL);
    if (kbuf == NULL) {
        return -ENOMEM;
    }
    kbuf[len] = '\0'; // Add null terminator just in case...

    error = copy_from_user(kbuf, buffer, len);
    if (error) {
        kfree(kbuf);
        return -EFAULT;
    }

    mutex_lock(priv_data->current_lock);

    curr_space_left = MAX_ALLOWED_MESSAGE - *priv_data->current_offset; // fyi: when full, curr_space_left should be 1

    printk(KERN_INFO "[*]    Current Space left to write is %d\n", curr_space_left);

    if (len > curr_space_left) {
        kfree(kbuf);
        mutex_unlock(priv_data->current_lock);
        printk(KERN_WARNING "[*]    Message to write %zu is too long.\n", len);
        return -E2BIG;
    }

    for (i = 0; i < len; i++) {
        priv_data->current_msg[i + *priv_data->current_offset] = kbuf[i];
        seek++;
    }
    (*priv_data->current_offset) += seek;
    kfree(kbuf);

    printk(KERN_INFO "[*]    Wrote %zu bytes. \n", len);

    curr_space_left = MAX_ALLOWED_MESSAGE - *priv_data->current_offset; // fyi: when full, curr_space_left should be 1
    printk(KERN_INFO "[*]    Current Space left to write is %d\n", curr_space_left);

    printk(KERN_INFO "[*]    STORED MSG:\n");
    print_hex_dump(KERN_INFO, "[*]    ", DUMP_PREFIX_NONE, 16, 1, priv_data->current_msg, MAX_ALLOWED_MESSAGE + 1, true);

    mutex_unlock(priv_data->current_lock);

    return len;
}

long dev_ioctl(struct file *filep, unsigned int ioctl_num, unsigned long ioctl_param)
{
    int error = 0;
    struct jhu_ioctl_crypto __user *temp_evp = NULL;
    struct dev_private_data *priv_data = filep->private_data; // device should be opened at this stage...

    // better safe than sorry
    if (!priv_data) {
        return -EBADF;
    }

    printk(KERN_INFO "[*] Usermode is requesting %08x ioctl\n", ioctl_num);

    switch (ioctl_num) {
    case IOCTL_READ_FROM_KERNEL:
        printk(KERN_INFO "[*]    IOCTL_READ_FROM_KERNEL\n");
        temp_evp = (struct jhu_ioctl_crypto __user *)ioctl_param;

        if (*priv_data->current_crypto_initialized == false) {
            printk(KERN_WARNING "[*]    Crypto not initialized yet.\n");
            return -EAGAIN;
        }

        error = copy_to_user(temp_evp, priv_data->current_crypto, sizeof(struct jhu_ioctl_crypto));
        if (error) {
            return -EFAULT;
        }
        priv_data->is_key_initialized = true;
        priv_data->is_iv_initialized = true;

        printk(KERN_INFO "[*]    KEY READ\n");
        print_hex_dump(KERN_INFO, "[*]    ", DUMP_PREFIX_NONE, 16, 1, priv_data->current_crypto->KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN, true);
        printk(KERN_INFO "[*]    IV READ\n");
        print_hex_dump(KERN_INFO, "[*]    ", DUMP_PREFIX_NONE, 16, 1, priv_data->current_crypto->IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN, true);

        // Clear Data Remnants (Prevents Unstable Write/Read)
        // TODO Should we do this?
        (*priv_data->current_crypto_initialized) = false;
        memset(priv_data->current_crypto->KEY, 0, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN);
        memset(priv_data->current_crypto->IV, 0, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);

        printk(KERN_INFO "[*]    Post Read State {isRead: %d, isWrite: %d, isKey: %d, isIV: %d, major: %d, minor: %d}\n",
               priv_data->is_open_for_read, priv_data->is_open_for_write,
               priv_data->is_key_initialized, priv_data->is_iv_initialized,
               priv_data->major, priv_data->minor);

        break;
    case IOCTL_WRITE_TO_KERNEL:
        printk(KERN_INFO "[*]    IOCTL_WRITE_TO_KERNEL\n");
        temp_evp = (struct jhu_ioctl_crypto __user *)ioctl_param;

        // Clear Data Remnants (Prevents Unstable Write/Read)
        (*priv_data->current_crypto_initialized) = false;
        memset(priv_data->current_crypto->KEY, 0, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN);
        memset(priv_data->current_crypto->IV, 0, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);

        error = copy_from_user(priv_data->current_crypto, temp_evp, sizeof(struct jhu_ioctl_crypto));
        if (error) {
            memset(priv_data->current_crypto->KEY, 0, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN); // Clear memory after error
            memset(priv_data->current_crypto->IV, 0, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);   // Clear memory after error
            return -EFAULT;
        }
        priv_data->is_key_initialized = true;
        priv_data->is_iv_initialized = true;

        // Indicate that Crypto Info has been written to Device
        (*priv_data->current_crypto_initialized) = true;

        printk(KERN_INFO "[*]    KEY WRITEN\n");
        print_hex_dump(KERN_INFO, "[*]    ", DUMP_PREFIX_NONE, 16, 1, priv_data->current_crypto->KEY, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN, true);
        printk(KERN_INFO "[*]    IV WRITEN\n");
        print_hex_dump(KERN_INFO, "[*]    ", DUMP_PREFIX_NONE, 16, 1, priv_data->current_crypto->IV, JHU_IOCTL_CRYPTO_IV_CHAR_LEN, true);

        printk(KERN_INFO "[*]    Post Write State {isRead: %d, isWrite: %d, isKey: %d, isIV: %d, major: %d, minor: %d}\n",
               priv_data->is_open_for_read, priv_data->is_open_for_write,
               priv_data->is_key_initialized, priv_data->is_iv_initialized,
               priv_data->major, priv_data->minor);

        break;
    default:
        break;
    }

    printk(KERN_INFO "[*] Usermode %08x ioctl request finished\n", ioctl_num);

    return 0;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
    //
    // This path is called when the file descriptor is closed
    //
    bool is_write, is_read;
    int device_id = imajor(inodep);
    struct dev_private_data *priv_data = filep->private_data; // device should be opened at this stage...
    char *device_name = (device_id == g_majornum_a) ? "Device A" : (device_id == g_majornum_b) ? "Device B" : "UNKNOWN";
    char *device_role;

    // better safe than sorry
    if (!priv_data) {
        return 0;
    }

    is_write = priv_data->is_open_for_write;
    is_read = priv_data->is_open_for_read;
    device_role = is_write ? "Write" : is_read ? "Read" : "N/A";
    // TODO Should I delete here or in the IOCTL READ?
    // Writer Closed, Cleanup KEY/IV received and any message sent.
    // There should be nothing to read anymore for the reader...
    // if (priv_data->is_open_for_write) {
    //     printk("[*] Deleting data for %s\n", device_name);
    //     (*priv_data->current_offset) = 0;
    //     (*priv_data->current_crypto_initialized) = false;
    //     memset(priv_data->current_msg, 0, MAX_ALLOWED_MESSAGE);
    //     memset(priv_data->current_crypto->KEY, 0, JHU_IOCTL_CRYPTO_KEY_CHAR_LEN); // Clear memory KEY
    //     memset(priv_data->current_crypto->IV, 0, JHU_IOCTL_CRYPTO_IV_CHAR_LEN);   // Clear memory IV
    // }

    // Cleanup Private Device Data
    filep->private_data = NULL;
    kfree(priv_data);

    printk(KERN_INFO "[*] Releasing the file %s opened for %s \n", device_name, device_role);

    return 0;
}

module_init(jhu_oss_char_init);
module_exit(jhu_oss_char_exit);
