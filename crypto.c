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

    if (bufhead != NULL)
        kfree(bufhead);

    unregister_chrdev_region(devno, 1);

    printk(KERN_INFO "Killed cryptomod\n");
}

static int device_open(struct inode *inode, struct file *filp)
{
    struct crypto_file_meta *fm = kmalloc(sizeof(struct crypto_file_meta*),
            GFP_KERNEL);
    if (fm == NULL)
        return -ENOMEM;
    fm->mode = filp->f_flags & O_ACCMODE;
    fm->buf = NULL;
    fm->r_smode.dir = CRYPTO_READ;
    fm->r_smode.mode = CRYPTO_PASSTHROUGH;
    fm->w_smode.dir = CRYPTO_WRITE;
    fm->w_smode.mode = CRYPTO_PASSTHROUGH;

    filp->private_data = fm;

    try_module_get(THIS_MODULE); /* increase the refcount of the open module */

    printk(KERN_INFO "Opened new instance of the crytomod device");

    return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
    struct crypto_file_meta *fm = filp->private_data;

    if (fm != NULL) {
        crypto_buffer_detach(fm);
        kfree(fm);
    }

    module_put(THIS_MODULE); /* decrease the refcount of the open module */

    printk(KERN_INFO "Closed instance of the crytomod device");

    return 0;
}

static ssize_t device_read(struct file *filp, char *buf, size_t len,
        loff_t * off)
{
    struct crypto_file_meta *fm = filp->private_data;
    if (fm == NULL)
        return -EINVAL;
    if (fm->buf == NULL)
        return -EOPNOTSUPP;
    if (fm->buf->size == 0)
        return 0;

    return -ENOSYS;
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len, 
        loff_t * off)
{
    struct crypto_file_meta *fm = filp->private_data;

    if (fm->buf == NULL)
        return -EOPNOTSUPP;

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
        printk(KERN_INFO "Error %d adding cryptomod cdev to kernel\n", errno);
    return errno;
}

void crypto_reset_buffer(struct crypto_buffer *buf)
{
    int x;
    struct crypto_buffer *bufloop;

    memset(&buf->buffer, 0, BUFFER_SIZE);
    buf->size = 0;
    buf->roff = 0;
    buf->woff = 0;
    buf->rcount = 0;
    buf->wcount = 0;
    buf->placeholder = 1;
    buf->next = NULL;

    /* Find next unique value */
    bufloop = bufhead;
    for ( x = 1; bufloop != NULL; x++ ) {
        /* We insert items into this list in sorted order by ID.
         * When it comes to finding an ID for a new element, all elements
         * should be in order, starting at 1. If the currently selected
         * bufloop does not equal x (ie: buffers are not incrementing by one)
         * then there is a gap in the buffer ids. eg: 1 2 3 5 (we can take 4) */
        if (bufloop->id != x) {
            buf->id = x;
            break;
        }
        /* If we get to here and bufloop->next is null, there were no gaps */
        if (bufloop->next == NULL)
            buf->id = x + 1;

        bufloop = bufloop->next;
    }
}

void crypto_buffer_cleanup()
{
    struct crypto_buffer *bufloop;
    struct crypto_buffer *tmpbuf;

    bufloop = bufhead;
    while (bufloop != NULL) {
        tmpbuf = NULL;
        if (bufloop->rcount < 1 && bufloop->wcount < 1 &&
                bufloop->placeholder == 0)
            tmpbuf = bufloop;

        bufloop = bufloop->next;

        /* Free the buffer, assigning a new head if necessary */
        if (tmpbuf != NULL) {
            if (tmpbuf == bufhead)
                bufhead = tmpbuf->next;
            kfree(tmpbuf);
        }
    }
}

struct crypto_buffer* crypto_buffer_create()
{
    struct crypto_buffer *newbuf;
    struct crypto_buffer *bufloop;

    newbuf = kmalloc(sizeof(struct crypto_buffer), GFP_KERNEL);
    if (newbuf == NULL)
        return NULL;

    /* Clear the buffer so we can start using it */
    crypto_reset_buffer(newbuf);

    if (bufhead == NULL)
        bufhead = newbuf;
    else {
        /* Insert items in order of their IDs. Makes it easier to find the
         * lowest available ID for new buffers */
        bufloop = bufhead;
        while (bufloop->next->id < newbuf->id) {
            bufloop = bufloop->next;
        }
        newbuf->next = bufloop->next;
        bufloop->next = newbuf;
    }
    return newbuf;
}

int crypto_buffer_attach(struct crypto_buffer *buf,
        struct crypto_file_meta *fm)
{
    int errno = 0;

    /* Check if we're exceeding our buffer reference limits */
    if ((fm->buf->rcount > 0 && fm->mode == O_RDONLY) ||
            (fm->buf->wcount > 0 && fm->mode == O_WRONLY) ||
            (fm->mode == O_RDWR && (fm->buf->rcount > 0 ||
                fm->buf->wcount > 0)))
        return -EALREADY;
    
    /* We're not, lets attach then */
    if (fm->mode == O_RDONLY || fm->mode == O_RDWR) {
        fm->buf->rcount++;
    }
    if (fm->mode == O_WRONLY || fm->mode == O_RDWR) {
        fm->buf->wcount++;
    }
    buf->placeholder = 0;

    fm->buf = buf;

    return errno;
}

void crypto_buffer_detach(struct crypto_file_meta *fm)
{
    if (fm->buf != NULL) {
        if (fm->mode == O_RDONLY || fm->mode == O_RDWR)
            fm->buf->rcount--;
        if (fm->mode == O_WRONLY || fm->mode == O_RDWR)
            fm->buf->wcount--;
    }

    crypto_buffer_cleanup();
}
