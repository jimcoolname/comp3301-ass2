
#include "prac-fops.h"

static int device_open(struct inode *inode, struct file *filp)
{
    try_module_get(THIS_MODULE); /* increase the refcount of the open module */
    return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
    module_put(THIS_MODULE); /* decrease the refcount of the open module */
    return 0;
}

static ssize_t device_read(struct file *filp, char *buf, size_t len,
        loff_t * off)
{
    return -ENOSYS;
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len, 
        loff_t * off)
{
    return -ENOSYS;
}

struct file_operations fops = {
    .open = device_open,
    .release = device_release,
    .read = device_read,
    .write = device_write,
};
