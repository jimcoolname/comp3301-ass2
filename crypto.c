/*
 * =============================================================================
 *
 *       Filename:  crypto.c
 *
 *    Description:  Main C file for COMP3301 Assignment 2
 *
 *        Version:  0.0.1
 *        Created:  24/09/12 18:11:01
 *
 *         Author:  Tony Lee (Roganartu), uni@roganartu.com
 *   Organisation:  UQ Bachelor of Engineering
 *
 *          Notes:  
 * =============================================================================
 */

#include "crypto.h"

int __init init_module(void)
{
    int errno = 0;

    // THIS IS HERE TO MAKE DEV EASIER. REMOVE BEFORE SUBMITTING!!!
    // THIS IS HERE TO MAKE DEV EASIER. REMOVE BEFORE SUBMITTING!!!
    // THIS IS HERE TO MAKE DEV EASIER. REMOVE BEFORE SUBMITTING!!!
    // THIS IS HERE TO MAKE DEV EASIER. REMOVE BEFORE SUBMITTING!!!
    printk(KERN_INFO "\n\n");

    errno = alloc_chrdev_region(&device, 0, 1, "crypto");
    if (errno != 0)
        return errno;

    printk(KERN_INFO "crypto: major=%d, minor=%d", MAJOR(device),
            MINOR(device));

    printk(KERN_INFO "Initialised cryptomod.ko\n");
    return 0;
}

void __exit cleanup_module(void)
{
    unregister_chrdev_region(device, 1);

    printk(KERN_INFO "Killed cryptomod.ko\n");
}
