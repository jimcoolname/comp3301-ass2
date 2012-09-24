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
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tony Lee (Roganartu)");
MODULE_DESCRIPTION("COMP3301 Assignment 2 - Cryptographic Character Device \
        Driver");

#define BUFFER_SIZE 4096

extern struct file_operations fops;

char buf[BUFFER_SIZE + 1];
int bufIndex;
dev_t device;

// Private function definitions
int __init init_module(void);

void __exit cleanup_module(void);

static int device_open(struct inode *inode, struct file *filp);

static int device_release(struct inode *inode, struct file *filp);

static ssize_t device_read(struct file *filp, char *buf, size_t len,
        loff_t * off);

static ssize_t device_write(struct file *filp, const char *buf, size_t len, 
        loff_t * off);

#endif
