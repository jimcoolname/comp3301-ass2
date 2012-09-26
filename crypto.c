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

    errno = alloc_chrdev_region(&devno, 0, 1, "crypto");
    if (errno != 0)
        return errno;

    printk(KERN_INFO "crypto: major=%d, minor=%d", MAJOR(devno),
            MINOR(devno));

    errno = crypto_setup_cdev();
    if (errno != 0)
        return errno;

    bufhead = NULL;

    printk(KERN_INFO "Initialised cryptomod with buffer size %d\n",
            BUFFER_SIZE);
    return 0;
}

void __exit cleanup_module(void)
{

    cdev_del(&crypto_cdev);

    kfree(&bufhead);

    unregister_chrdev_region(devno, 1);

    printk(KERN_INFO "Killed cryptomod\n");
}

static int device_open(struct inode *inode, struct file *filp)
{
    try_module_get(THIS_MODULE); /* increase the refcount of the open module */

    printk(KERN_INFO "Opened new crytomod device");

    return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
    module_put(THIS_MODULE); /* decrease the refcount of the open module */

    printk(KERN_INFO "Closed crytomod device");

    return 0;
}

static ssize_t device_read(struct file *filp, char *buf, size_t len,
        loff_t * off)
{
/* 
    if (bufIndex > BUFFER_SIZE || filp == NULL)
        return -EINVAL;
    if (bufIndex == 0)
        return 0;
    */

    return -ENOSYS;
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len, 
        loff_t * off)
{
/* 
    if (bufIndex > BUFFER_SIZE)
        return -EINVAL;
    */

    return -ENOSYS;
}

static int device_ioctl(struct inode *inode, struct file *filp, 
        unsigned int cmd, unsigned long arg)
{
    return -ENOTTY;
}

static int device_mmap(struct file *filp, struct vm_area_struct *vma)
{
    return -ENOSYS;
}

struct file_operations fops = {
    .open = device_open,
    .release = device_release,
    .read = device_read,
    .write = device_write,
    .ioctl = device_ioctl,
    .mmap = device_mmap
};


int crypto_setup_cdev(void)
{
    int errno = 0;

    cdev_init(&crypto_cdev, &fops);
    crypto_cdev.owner = THIS_MODULE;
    crypto_cdev.ops = &fops;

    errno = cdev_add(&crypto_cdev, devno, 1);
    if (errno)
        printk(KERN_INFO "Error %d added cryptomod cdev to kernel\n", errno);
    return errno;
}
