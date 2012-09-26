/*
 * =============================================================================
 *
 *       Filename:  crypto.h
 *
 *    Description:  Main file for COMP3301 Assignment 2
 *
 *        Version:  0.0.1
 *        Created:  24/09/12 18:42:10
 *
 *         Author:  Tony Lee (Roganartu), uni@roganartu.com
 *   Organisation:  UQ Bachelor of Engineering
 *
 *          Notes:  
 * =============================================================================
 */

#ifndef COMP3301_CRYPTO_H
#define COMP3301_CRYPTO_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include "ioctl-1.2.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tony Lee (Roganartu)");
MODULE_DESCRIPTION("COMP3301 Assignment 2 - Cryptographic Character Device \
        Driver");

#define BUFFER_SIZE 8192

extern struct file_operations fops;

dev_t devno;

struct crypto_buffer {
    char buffer[BUFFER_SIZE + 1]; /* Where the buffer is actually stored */
    unsigned int size;            /* Amount of data stored in the buffer */
    int roff;                     /* read offset. -1 if no read fds */
    int woff;                     /* write offset. -1 if no write fds */
    int rwoff;                    /* read/write offset. -1 if no rw fds */
    int placeholder;              /* Prevent automatic deletion upon create */
    int uniq;                     /* unique buffer identifier */
    struct crypto_buffer *next;   /* linked list implementation */
};

struct cdev crypto_cdev;

// Head of buffer linked list. Defaults to NULL if no buffers
struct crypto_buffer *bufhead;

// Private methods
int __init init_module(void);

void __exit cleanup_module(void);

int crypto_setup_cdev(void);

static int device_open(struct inode *inode, struct file *filp);

static int device_release(struct inode *inode, struct file *filp);

static ssize_t device_read(struct file *filp, char *buf, size_t len,
        loff_t * off);

static ssize_t device_write(struct file *filp, const char *buf, size_t len, 
        loff_t * off);

static int device_ioctl(struct inode *inode, struct file *filp, 
        unsigned int cmd, unsigned long arg);

static int device_mmap(struct file *filp, struct vm_area_struct *vma);

#endif
