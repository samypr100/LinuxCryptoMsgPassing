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


int ioctl_set_data(int fd, char * data)
{
    int i;
    char c;

    printf("[+] %s called\n", __FUNCTION__ );

    ioctl(fd, IOCTL_WRITE_TO_KERNEL, data );

    printf("[+]    Data written: %s\n", data );

    return 0;

}

int ioctl_read_data(int fd, char * data)
{
    int i;
    char c;

    printf("[+] %s called\n", __FUNCTION__ );

    ioctl(fd, IOCTL_READ_FROM_KERNEL, data );

    printf("[+]    Data read: %s\n", data );

    return 0;

}

int main( int argc, char ** argv )
{
    int fd = -1;
    int ret = -1;
    char set_data[32];
    char read_data[32];

    memset(read_data, 0, 32 );

    strcpy( set_data, "Hello world!\n");

    char devname[32];
    strcpy(devname, "/dev/");
    strcat(devname, DEVICE_NAME_A );

    fd = open(devname, 0);

    if (fd < 0) 
    {
        printf("Can't open device file: %s\n", DEVICE_NAME_A);
        return -1;
    }

    ret = ioctl_set_data(fd, set_data);
    ret = ioctl_read_data(fd, read_data);

    //
    // You will also use the read() and write() system calls
    //

    close(fd);

    return 0;
}
