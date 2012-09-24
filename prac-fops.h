#ifndef COMP3301_FOPS_H
#define COMP3301_FOPS_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>

extern struct file_operations fops;

// Private function definitions
static int device_open(struct inode *inode, struct file *filp);

static int device_release(struct inode *inode, struct file *filp);

static ssize_t device_read(struct file *filp, char *buf, size_t len,
        loff_t * off);

static ssize_t device_write(struct file *filp, const char *buf, size_t len, 
        loff_t * off);

#endif
