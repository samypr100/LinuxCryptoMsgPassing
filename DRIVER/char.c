/*********************************************************************
*
* This is a skeleton character device driver for 
* JHU Operating Systems Security (695.412)
*
*
* Author: T. McGuire
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

// Using a common header file for usermode/kernel mode code
#include "../COMMON/char_ioctl.h"


//
// Setup your class name here
//
#define  CLASS_NAME  "jhu_oss"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("T. McGuire - JHU");
MODULE_DESCRIPTION("Linux character device driver for OSS");
MODULE_VERSION("1.0.2018");

//
// Setup some global variables for your device
// Note: Below is not an accurate/complete list for the assignment
// You will need to modify these in order to complete the assignment
//

#define MAX_ALLOWED_LEN 16

static int    g_majornum;
static char   g_buffer[MAX_ALLOWED_LEN] = {0};

static struct class*  jhu_oss_class  = NULL;
static struct device* jhu_oss_device = NULL;

//
// Relevant function prototypes that will be used
// for the file_operations structure
//
static int     dev_open(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static long    dev_ioctl(struct file *, unsigned int, unsigned long );
static int     dev_release(struct inode *, struct file *);


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
// This path is called when the module is being loaded
//
static int __init jhu_oss_char_init(void)
{

   //
   // Register the device dynamically
   //
   g_majornum = register_chrdev(0, DEVICE_NAME, &fops);

   if( g_majornum < 0 )
   {
      return g_majornum;
   }

   printk("[+] Successfully registered device with major number %d\n", g_majornum);

   //
   // Create the device class
   // 
   jhu_oss_class = class_create(THIS_MODULE, CLASS_NAME);

   if( IS_ERR(jhu_oss_class) )
   { 

      unregister_chrdev(g_majornum, DEVICE_NAME);

      printk("[-] Failed to create device class\n");

      return PTR_ERR(jhu_oss_class);          
   }

   printk("[+] Successfully created the device class\n");

   // 
   // create the device now
   //

   // 
   // NOTE:
   // The MKDEV takes a major/minor pair and creates an appropriate device number
   //
   jhu_oss_device = device_create(jhu_oss_class, NULL, MKDEV(g_majornum, 0), NULL, DEVICE_NAME);

   if( IS_ERR(jhu_oss_device) )
   {
      class_destroy(jhu_oss_class);

      unregister_chrdev(g_majornum, DEVICE_NAME);

      printk("[-] Failed to create device class\n");

      return PTR_ERR(jhu_oss_device);
   }

   printk("[+] Module successfully initialized\n");

   return 0;

}

// 
// This path is called when the module is being unloaded
//
static void __exit jhu_oss_char_exit(void)
{

   printk("[*] Unloading the module\n");
   //
   // destroy the created device
   //
   device_destroy(jhu_oss_class, MKDEV(g_majornum, 0));     

   //
   // unregister the class
   //
   class_unregister(jhu_oss_class);                          

   //
   // unregister the character device
   //
   unregister_chrdev(g_majornum, DEVICE_NAME);            


}

static int dev_open(struct inode *inodep, struct file *filep){

   //
   // Add your checking to this code path
   //
   printk("[*] Opening the file\n");

   return 0;
}


//
// This path is called when read() is made on the file descriptor
// That is, the user mode program is expected to read data from
// this device
//
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{

   size_t num_read;
   //int error = -1;
   printk("[*] Usermode is requesting %zu chars from kernelmode\n", len);
   //
   // NOTE: copy_to_user takes the format ( to, from, size)
   //       it returns 0 on success
   //
   // Make sure you are only reading the requested amount!
   //
   //error= copy_to_user(buffer, KERNEL_SOURCE, KERNEL_SOURCE_SIZE);

   num_read = len;

   return num_read;
}

//
// This path is called when write() is made on the file descriptor
// That is, the user mode program is passing data to this function
//
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{

   printk("[*] Usermode is writing %zu chars to usermode\n", len);

   return len;
}

long dev_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
    int i = 0;
    int error = 0;
    char *temp = NULL;
    char ch;

    printk("[*] Usermode is requesting %08x ioctl\n", ioctl_num);

    switch (ioctl_num) 
    {
        case IOCTL_READ_FROM_KERNEL:
            printk("[*]    IOCTL_READ_FROM_KERNEL\n");
            // 
            //  The code below is not safe..be sure to fix it properly
            //  if you use it
            // 
            temp = (char *)ioctl_param;
            error= copy_to_user(temp, g_buffer, MAX_ALLOWED_LEN);

            printk("[+]    The message is %s\n", g_buffer );

            break;

        case IOCTL_WRITE_TO_KERNEL:
            printk("[*]    IOCTL_WRITE_TO_KERNEL\n");
            temp = (char *)ioctl_param;
            get_user(ch, temp);
            for (i = 0; ch && i < MAX_ALLOWED_LEN; i++, temp++)
                get_user(ch, temp);

            // 
            //  The code below is not safe..be sure to fix it properly
            //  if you use it
            // 
            memset( g_buffer, 0, MAX_ALLOWED_LEN );
            error= copy_from_user(g_buffer, (char*)ioctl_param, i);

            printk("[+]    The length passed in is %d\n", i );
            printk("[+]    The message is %s\n", g_buffer );

            break;

        default:
            break;

    }

    return 0;
}


static int dev_release(struct inode *inodep, struct file *filep){
   //
   // This path is called when the file descriptor is closed
   //

   printk("[*] Releasing the file\n");

   return 0;
}

module_init(jhu_oss_char_init);
module_exit(jhu_oss_char_exit);
