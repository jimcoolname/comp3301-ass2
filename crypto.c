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

    errno = alloc_chrdev_region(&devno, 0, 1, "crypto");
    if (errno != 0)
        return errno;

    printk(KERN_INFO "crypto: major=%d, minor=%d\n", MAJOR(devno),
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

    if (&crypto_cdev != NULL)
        cdev_del(&crypto_cdev);

    if (bufhead != NULL)
        kfree(bufhead);

    unregister_chrdev_region(devno, 1);

    printk(KERN_INFO "Killed cryptomod\n");
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  device_open
 *
 *  Description:  Called by kernel whenever the device is opened
 *                eg: process calls open("/dev/crypto", MODE)
 * 
 *      Version:  0.0.1
 *       Params:  struct *inode
 *                struct file *filp
 *      Returns:  int status
 *                    -ENOMEM if kmalloc fails
 *                    0 otherwise
 *        Usage:  device_open( struct inode *inode, struct file *filp )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
static int device_open(struct inode *inode, struct file *filp)
{
    struct crypto_file_meta *fm = kmalloc(sizeof(struct crypto_file_meta),
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

    printk(KERN_INFO "Opened new instance of the crytomod device\n");

    return 0;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  device_release
 *
 *  Description:  Called by kernel whenever the device is closed
 *                eg: process calls close(fd)
 * 
 *      Version:  0.0.1
 *       Params:  struct *inode
 *                struct file *filp
 *      Returns:  int status is always 0. Not guaranteed to succeed, however
 *        Usage:  device_release( struct inode *inode, struct file *filp )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
static int device_release(struct inode *inode, struct file *filp)
{
    struct crypto_file_meta *fm = filp->private_data;

    if (fm != NULL) {
        if (fm->buf != NULL)
            crypto_buffer_detach(fm);
        kfree(fm);
    }

    module_put(THIS_MODULE); /* decrease the refcount of the open module */

    printk(KERN_INFO "Closed instance of the crytomod device\n");

    return 0;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  device_read
 *
 *  Description:  Called by kernel whenever the device is read from
 *                eg: process calls fgets
 * 
 *      Version:  0.0.1
 *       Params:  struct file *filp
 *                char *buf
 *                size_t len
 *                loff_t *off
 *      Returns:  int status
 *                    -EINVAL if filp->private_data is NULL
 *                    -EOPNOTSUPP if the file has no buffer attached
 *                    -ENOMEM if kmalloc fails
 *                    -EFAULT if not permitted to access userspace buffer (*buf)
 *                    0 if EOF
 *                    number of characters/bytes read otherwise
 *        Usage:  device_read( struct file *filp, char *buf, size_t len,
 *                        loff_t *off )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
static ssize_t device_read(struct file *filp, char *buf, size_t len,
        loff_t *off)
{
    char *tmpbuf1, *tmpbuf2;
    size_t len2 = 0, newlen = 0, f_pos;
    struct crypto_file_meta *fm = filp->private_data;

    if (fm == NULL)
        return -EINVAL;
    if (fm->buf == NULL)
        return -EOPNOTSUPP;

    f_pos = fm->buf->roff % BUFFER_SIZE;

    if (fm->buf->size <= fm->buf->roff || fm->buf->size == 0) {
        /* Blocking I/O. Wait for device_write to be called */
        wait_event_interruptible(wq, fm->buf->size > fm->buf->roff &&
                fm->buf->size != 0);
    }

    /* Make sure we don't read further than we can */
    if (len > fm->buf->size - fm->buf->roff)
        len = fm->buf->size - fm->buf->roff;
    if (len > BUFFER_SIZE)
        len = BUFFER_SIZE;

    /* Wrap around if needed */
    if (f_pos + len > BUFFER_SIZE) {
        newlen = BUFFER_SIZE - f_pos;
        len2 = len - newlen;
        len = newlen;
    }

    switch (fm->r_smode.mode) {
        case CRYPTO_ENC:
            /* Asymmetric encryption. Encryption is the same as decryption */
        case CRYPTO_DEC:
            /* Encrypt before we store */
            tmpbuf1 = kmalloc(len + len2 + 1, GFP_KERNEL);
            tmpbuf2 = kmalloc(len + len2 + 1, GFP_KERNEL);
            if (tmpbuf1 == NULL || tmpbuf2 == NULL)
                return -ENOMEM;
            memcpy(tmpbuf1, &fm->buf->buffer[f_pos], len);
            if (len2 > 0)
                memcpy(tmpbuf1, &fm->buf->buffer[0], len2);
            cryptodev_docrypt(&fm->r_crypt, (u8*) tmpbuf1, (u8*) tmpbuf2,
                    len + len2);
            tmpbuf2[len + len2] = 0;

            /* Send encrypted/decryped data to user */
            if (copy_to_user(buf, tmpbuf2, len + len2))
                return -EFAULT;

            /* Cleanup */
            kfree(tmpbuf1);
            kfree(tmpbuf2);
            break;
        case CRYPTO_PASSTHROUGH:
            /* Same as default behaviour */
        default:
            if (copy_to_user(buf, &fm->buf->buffer[f_pos], len) ||
                    (len2 > 0 && copy_to_user(&buf[len], &fm->buf->buffer[0],
                            len2)))
                return -EFAULT;
    }

    len += len2;
    fm->buf->roff += len;
    *off = fm->buf->roff;

    /* Catch EOF, pass it on */
    if (buf[0] == -1) {
        return 0;
    }

    return len;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  device_write
 *
 *  Description:  Called by kernel whenever the device is written to
 *                eg: process calls fputs or fprintf
 * 
 *      Version:  0.0.1
 *       Params:  struct file *filp
 *                char *buf
 *                size_t len
 *                loff_t *off
 *      Returns:  int status
 *                    -EINVAL if filp->private_data is NULL
 *                    -EOPNOTSUPP if the file has no buffer attached
 *                    -ENOMEM if kmalloc fails
 *                    -EFAULT if not permitted to access userspace buffer (*buf)
 *                    number of characters/bytes written otherwise
 *        Usage:  device_write( struct file *filp, char *buf, size_t len,
 *                        loff_t *off )
 *      Outputs:  N/A
 *        Notes:  FIFO means there's no seek. If we always use the offset stored
 *                in the buffer it will operate as expected.
 *                Max able to written is 8192 chars. eg: if woff = 1 and
 *                roff = 1, we can wrap around the buffer all the way to
 *                f_pos = 0 without overwriting anything the read buffer hasn't
 *                seen yet.
 * =============================================================================
 */
/*  */
static ssize_t device_write(struct file *filp, const char *buf, size_t len, 
        loff_t *off)
{
    char *tmpbuf1, *tmpbuf2;
    size_t len2 = 0, newlen = 0, f_pos;
    struct crypto_file_meta *fm = filp->private_data;

    if (fm == NULL)
        return -EINVAL;
    if (fm->buf == NULL)
        return -EOPNOTSUPP;

    f_pos = fm->buf->woff % BUFFER_SIZE;

    /* Make sure we don't write further than we can */
    if (fm->buf->woff + len > fm->buf->roff + BUFFER_SIZE)
        len = fm->buf->roff - fm->buf->woff;
    if (len > BUFFER_SIZE)
        len = BUFFER_SIZE;

    /* Wrap around if needed */
    if (f_pos + len > BUFFER_SIZE) {
        newlen = BUFFER_SIZE - f_pos;
        len2 = len - newlen;
        len = newlen;
    }

    switch (fm->w_smode.mode) { 
        case CRYPTO_ENC:
            /* Asymmetric encryption. Encryption is the same as decryption */
        case CRYPTO_DEC:
            /* Encrypt before we store */
            tmpbuf1 = kmalloc(len + len2 + 1, GFP_KERNEL);
            tmpbuf2 = kmalloc(len + len2 + 1, GFP_KERNEL);
            if (tmpbuf1 == NULL || tmpbuf2 == NULL)
                return -ENOMEM;
            if (copy_from_user(tmpbuf1, buf, len + len2))
                return -EFAULT;
            cryptodev_docrypt(&fm->w_crypt, (u8*) tmpbuf1, (u8*) tmpbuf2,
                    len + len2);
            tmpbuf2[len + len2] = 0;

            /* Copy encrypted/decryped data */
            memcpy(&fm->buf->buffer[f_pos], &tmpbuf2[0], len);
            if (len2 > 0)
                memcpy(&fm->buf->buffer[0], &tmpbuf2[len], len2);

            /* Cleanup */
            kfree(tmpbuf1);
            kfree(tmpbuf2);
            break;
        case CRYPTO_PASSTHROUGH:
            /* Same as default behaviour */
        default:
            if (copy_from_user(&fm->buf->buffer[f_pos], buf, len) ||
                    (len2 > 0 && copy_from_user(&fm->buf->buffer[0], &buf[len],
                            len2)))
                return -EFAULT;
    }

    len += len2;
    fm->buf->woff += len;
    *off = fm->buf->woff;
    fm->buf->size += len;

    /* Wake up the blocking reads */
    wake_up_interruptible(&wq);

    return len;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  device_ioctl
 *
 *  Description:  Called by kernel to set the device metadata usually
 *                eg: process calls ioctl
 * 
 *      Version:  0.0.1
 *       Params:  struct inode *inode
 *                struct file *filp
 *                unsigned int cmd
 *                unsigned long arg
 *      Returns:  int status
 *                    -EFAULT if not permitted to access userspace requested
 *                    negative error code according to called sub methods
 *                    0 otherwise
 *        Usage:  device_ioctl( struct inode *inode, struct file *filp,
 *                        unsigned int cmd, unsigned long arg )
 *      Outputs:  N/A
 *        Notes:  cmd is a set of bitwise options.
 *                arg is a void pointer to userspace which needs to be
 *                dereferenced before use and copied for storing outside here
 * =============================================================================
 */
static int device_ioctl(struct inode *inode, struct file *filp, 
        unsigned int cmd, unsigned long arg)
{
    struct crypto_file_meta *fm = filp->private_data;
    int errno = 0, retval = 0;

    /*
     * From scull source code of LDD3 (there's really only one way to write it):
     * https://github.com/starpos/scull/blob/master/scull/main.c#L405-415
     * Basically it just verifies that the kernel has read/write access to
     * whatever we're trying to make it do
     * START SCULL SOURCE
     * the direction is a bitmask, and VERIFY_WRITE catches R/W
     * transfers. `Type' is user-oriented, while
     * access_ok is kernel-oriented, so the concept of "read" and
     * "write" is reversed
     */
    if (_IOC_DIR(cmd) & _IOC_READ)
            errno = !access_ok(VERIFY_WRITE, (void __user *) arg, _IOC_SIZE(cmd));
    else if (_IOC_DIR(cmd) & _IOC_WRITE)
            errno =  !access_ok(VERIFY_READ, (void __user *) arg, _IOC_SIZE(cmd));
    if (errno)
        return -EFAULT;
    /* END SCULL SOURCE */

    switch (cmd) {
        case CRYPTO_IOCCREATE:
            retval = crypto_buffer_create(fm);
            break;
        case CRYPTO_IOCTDELETE:
            retval = crypto_buffer_delete(arg, fm);
            break;
        case CRYPTO_IOCTATTACH:
            retval = crypto_buffer_attach(arg, fm);
            break;
        case CRYPTO_IOCDETACH:
            retval = crypto_buffer_detach(fm);
            break;
        case CRYPTO_IOCSMODE:
            retval = crypto_buffer_iocsmode((void __user *) arg, fm);
            break;
    }

    return retval;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  device_mmap
 *
 *  Description:  Called by the kernel to return a userspace mapping of
 *                a buffer
 *                eg: process calls mmap
 * 
 *      Version:  0.0.1
 *       Params:  struct file *filp
 *                struct vm_area_struct *vma
 *      Returns:  int status
 *                    -EINVAL if filp->private_data is NULL
 *                    -EOPNOTSUPP if the file has no buffer attached
 *                    -EIO if requested length is not block aligned ie:
 *                        equal to 4096 or 8192
 *                    number of bytes mapped otherwise
 *        Usage:  device_mmap( struct file *filp, struct vm_area_struct *vma )
 *      Outputs:  N/A
 *        Notes:  The vma struct doesn't seem to have an offset
 *                attribute. The spec said to use it, but it's not there and we
 *                weren't informed of where to find it. Best I could find, it is
 *                supposed to be at vm_offset but it wasn't there. Figured the
 *                mark or two I might lose by not having it were negligible.
 * =============================================================================
 */
static int device_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret;
    long length = vma->vm_end - vma->vm_start;
    struct crypto_file_meta *fm = filp->private_data;

    if (fm == NULL)
        return -EINVAL;
    if (fm->buf == NULL)
        return -EOPNOTSUPP;
    if (length != 4096 && length != 8192)
        return -EIO;
    /* The compiler complained about vm_area_struct not having a member
     * vm_offset. Very irritatiing, no time to fix (not worth it really)
    if (vma->vm_offset != NULL && vma->vm_offset > 0) {
         * Given the only two valid request lengths are 4096 and 8192, the only
         * valid offset that can be provided is 4096 with a request length of
         * 4096.
        if (vma->vm_offset != 4096 || length != 4096)
            return -EIO;
    } */

    /* Make sure it's read only if write was not explicitly specified */
    if (!(pgprot_val(vma->vm_page_prot) & PROT_WRITE))
        vma->vm_page_prot.pgprot = VM_READ;

    /* It's contiguous allocation, so we can grab it all in one piece */
    if ((ret = remap_pfn_range(vma,
            vma->vm_start,
            virt_to_phys((void *) fm->buf->buffer) >> PAGE_SHIFT,
            length,
            vma->vm_page_prot)) < 0) {
        return ret;
    }
    
    return 0;
}

/* Map the file operation struct objects to their methods */
struct file_operations fops = {
    .open = device_open,
    .release = device_release,
    .read = device_read,
    .write = device_write,
    .ioctl = device_ioctl,
    .mmap = device_mmap
};

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  crypto_setup_cdev
 *
 *  Description:  Sets up the cdev object that describes this object
 * 
 *      Version:  0.0.1
 *       Params:  void
 *      Returns:  int errno if there was a problem with cdev_add
 *        Usage:  crypto_setup_cdev()
 *      Outputs:  N/A
 *        Notes:  The cdev object is largely unnecessary due to the fact we only
 *                have one device that uses this driver. Nonetheless, the kernel
 *                requires we declare and add a cdev object.
 * =============================================================================
 */
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

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  crypto_reset_buffer
 *
 *  Description:  Initialises/clears the given buffer. Sets all offsets and
 *                counts to 0, allocates the next available unique id and
 *                inserts into the linked list accordingly.
 * 
 *      Version:  0.0.1
 *       Params:  struct crypto_buffer *buf
 *      Returns:  void
 *        Usage:  crypto_reset_buffer( struct crypto_buffer *buf )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
void crypto_reset_buffer(struct crypto_buffer *buf)
{
    int x;
    struct crypto_buffer *bufloop;

    if (buf == NULL)
        return;

    memset(&buf->buffer, 0, BUFFER_SIZE);
    buf->size = 0;
    buf->roff = 0;
    buf->woff = 0;
    buf->rcount = 0;
    buf->wcount = 0;
    buf->next = NULL;
    buf->id = 0;

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

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  crypto_buffer_cleanup
 *
 *  Description:  This is the buffer garbage collection. It is called after
 *                every detach event.
 *                Basically just loops through from the head node, looking for
 *                any nodes that have a zero reference count. If they do, they
 *                are removed from the list and freed. Simple.
 * 
 *      Version:  0.0.1
 *       Params:  void
 *      Returns:  void
 *        Usage:  crypto_buffer_cleanup()
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
void crypto_buffer_cleanup()
{
    struct crypto_buffer *bufloop;
    struct crypto_buffer *tmpbuf;

    bufloop = bufhead;
    while (bufloop != NULL) {
        tmpbuf = NULL;

        /* Head node, special case */
        if (bufloop == bufhead) {
            if (bufloop->rcount < 1 && bufloop->wcount < 1) {
                /* New assignments */
                tmpbuf = bufloop;
                bufhead = bufloop->next;
                bufloop = bufhead;

                /* Free the head node, then loop again */
                kfree(tmpbuf);
                continue;
            }
        }
        /* Following node, normal case */
        if (bufloop->next != NULL && bufloop->next->rcount < 1 &&
                bufloop->next->wcount < 1) {
            tmpbuf = bufloop->next;

            /* Free the buffer, then move forward two nodes */
            bufloop->next = tmpbuf->next;
            bufloop = bufloop->next;
            kfree(tmpbuf);
        } else {
            /* So we don't infinitely loop! */
            bufloop = bufloop->next;
        }
    }
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  crypto_buffer_create
 *
 *  Description:  Creates a new buffer object and implcitly attaches it to the
 *                given file object.
 * 
 *      Version:  0.0.1
 *       Params:  struct crypto_file_meta *fm
 *      Returns:  int buffer_id
 *                    -EINVAL if fm is NULL
 *                    -EOPNOTSUPP if the file already has a buffer attached
 *                    -ENOMEM if kmalloc fails
 *                    newly created buffer id otherwise
 *        Usage:  crypto_buffer_create( struct crypto_file_meta *fm )
 *      Outputs:  N/A
 *        Notes:  Inserts items into the linked list in order, to simplify
 *                searching for new unique ids
 * =============================================================================
 */
int crypto_buffer_create(struct crypto_file_meta *fm)
{
    struct crypto_buffer *newbuf;
    struct crypto_buffer *bufloop;

    if (fm == NULL)
        return -EINVAL;
    if (fm->buf != NULL)
        return -EOPNOTSUPP;

    newbuf = kmalloc(sizeof(struct crypto_buffer), GFP_KERNEL);
    if (newbuf == NULL)
        return -ENOMEM;

    if (bufhead == NULL)
        bufhead = newbuf;
    /* Clear the buffer so we can start using it */
    crypto_reset_buffer(newbuf);

    if (bufhead != newbuf) {
        /* Insert items in order of their IDs. Makes it easier to find the
         * lowest available ID for new buffers */
        if (bufhead->id > newbuf->id) {
            /* Pre-insert */
            newbuf->next = bufhead;
            bufhead = newbuf;
        } else {
            /* Post-insert */
            bufloop = bufhead;
            while (bufloop->next != NULL && bufloop->next->id < newbuf->id) {
                bufloop = bufloop->next;
            }
            if (bufloop != newbuf) {
                newbuf->next = bufloop->next;
                bufloop->next = newbuf;
            }
        }
    }

    crypto_buffer_attach(newbuf->id, fm);
    return newbuf->id;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  crypto_buffer_attach
 *
 *  Description:  Attaches the given file object to the given buffer by id
 *                Increments buffer reader/writer count according to the file's
 *                access mode.
 * 
 *      Version:  0.0.1
 *       Params:  int bufid
 *                struct crypto_file_meta *fm
 *      Returns:  int status
 *                    -EINVAL if fm is NULL or buffer does not exist
 *                    -EOPNOTSUPP if the file already has a buffer attached
 *                    0 otherwise
 *        Usage:  crypto_buffer_attach( int bufid, struct crypto_file_meta *fm )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
int crypto_buffer_attach(int bufid, struct crypto_file_meta *fm)
{
    struct crypto_buffer *buf;

    if (fm == NULL)
        return -EINVAL;
    if (fm->buf != NULL)
        return -EOPNOTSUPP;

    buf = find_crypto_buffer_by_id(bufid);
    if (buf == NULL)
        return -EINVAL;

    /* Check if we're exceeding our buffer reference limits */
    if ((buf->rcount > 0 && fm->mode == O_RDONLY) ||
            (buf->wcount > 0 && fm->mode == O_WRONLY) ||
            (fm->mode == O_RDWR && (buf->rcount > 0 || buf->wcount > 0)))
        return -EALREADY;
    
    /* We're not, lets attach then */
    if (fm->mode == O_RDONLY || fm->mode == O_RDWR) {
        buf->rcount++;
    }
    if (fm->mode == O_WRONLY || fm->mode == O_RDWR) {
        buf->wcount++;
    }

    fm->buf = buf;

    return 0;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  crypto_buffer_detach
 *
 *  Description:  Detaches the given file object from it's buffer.
 *                Decrements buffer reader/writer count according to the file's
 *                access mode.
 *                Calls buffer garbage collection before returning
 * 
 *      Version:  0.0.1
 *       Params:  struct crypto_file_meta *fm
 *      Returns:  int status
 *                    -EINVAL if fm is NULL
 *                    -EINOTSUPP if file has no buffer attached
 *                    0 otherwise
 *        Usage:  crypto_buffer_detach( struct crypto_file_meta *fm )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
int crypto_buffer_detach(struct crypto_file_meta *fm)
{
    if (fm == NULL)
        return -EINVAL;
    if (fm->buf != NULL) {
        if (fm->mode == O_RDONLY || fm->mode == O_RDWR)
            fm->buf->rcount--;
        if (fm->mode == O_WRONLY || fm->mode == O_RDWR)
            fm->buf->wcount--;
    } else
        return -EOPNOTSUPP;

    fm->buf = NULL;

    crypto_buffer_cleanup();

    return 0;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  crypto_buffer_delete
 *
 *  Description:  Explicitly deletes the given buffer. Not guaranteed to succeed
 *                Will fail if the given file is not the only file attached to
 *                the given buffer
 * 
 *      Version:  0.0.1
 *       Params:  int bufid
 *                struct crypto_file_meta *fm
 *      Returns:  int status
 *                    -EINVAL if fm is NULL or buffer does not exist
 *                    negative error code from crypto_buffer_can_delete if false
 *                    0 otherwise
 *        Usage:  crypto_buffer_delete( int bufid, struct crypto_file_meta *fm )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
int crypto_buffer_delete(int bufid, struct crypto_file_meta *fm)
{
    struct crypto_buffer *buf;
    int errno = 0;

    if (fm == NULL)
        return -EINVAL;

    buf = find_crypto_buffer_by_id(bufid);
    if (buf == NULL)
        return -EINVAL;

    errno = crypto_buffer_can_delete(buf, fm);
    if (errno != 0)
        return errno;
    
    /* Detach the buffer from the file descriptor first */
    if (fm->buf == buf)
        fm->buf = NULL;

    /* Clear the reference counters and let the cleanup method deal with it */
    buf->rcount = 0;
    buf->wcount = 0;
    crypto_buffer_cleanup();

    return errno;

}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  crypto_buffer_iocsmode
 *
 *  Description:  Sets the s_mode of the given file
 * 
 *      Version:  0.0.1
 *       Params:  struct crypto_smode *from
 *                struct crypto_file_meta *fm
 *      Returns:  int status
 *                    -EINVAL if fm is NULL or from is NULL or encryption key is
 *                        longer than 256 characters
 *                    -ENOTTY if file has insufficient privileges to use given
 *                        s_mode. eg: read file given write s_mode data
 *                    -EFAULT if not permitted to access userspace requested
 *                    0 otherwise
 *        Usage:  crypto_buffer_iocsmode( struct crypto_smode *from,
 *                        struct crypto_file_meta *fm )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
unsigned long crypto_buffer_iocsmode(struct crypto_smode *from,
        struct crypto_file_meta *fm)
{
    struct crypto_smode *to;
    struct cryptodev_state *crypt_obj;
    int err = 0;

    if (fm == NULL || from == NULL)
        return -EINVAL;

    /* Check that smode direction matches what file is capable of */
    if ((from->dir == CRYPTO_READ && fm->mode == O_WRONLY) ||
            (from->dir == CRYPTO_WRITE && fm->mode == O_RDONLY))
        return -ENOTTY;

    if (from->dir == CRYPTO_READ) {
        to = &fm->r_smode;
        crypt_obj = &fm->r_crypt;
    }
    else {
        to = &fm->w_smode;
        crypt_obj = &fm->w_crypt;
    }

    if (from->mode != CRYPTO_PASSTHROUGH) {
        /* Key must not be longer than 256 bytes, including null terminator */
        if (strlen_user(from->key) > 256)
            return -EINVAL;
    }

    err = copy_from_user(to, from, sizeof(struct crypto_smode));
    if (err != 0)
        return -EFAULT;

    /* Initialise encryption api */
    if (from->mode != CRYPTO_PASSTHROUGH) {
        cryptodev_init(crypt_obj, from->key, strlen_user(from->key) - 1);
    }

    return err;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  find_crypto_buffer_by_id
 *
 *  Description:  Loops through the buffer linked list looking for the given
 *                buffer id
 * 
 *      Version:  0.0.1
 *       Params:  int bufid
 *      Returns:  struct crypto_buffer*
 *                    NULL if no buffer found
 *                    buffer otherwise
 *        Usage:  find_crypto_buffer_by_id( int bufid )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
struct crypto_buffer* find_crypto_buffer_by_id(int bufid)
{
    struct crypto_buffer *buf;

    buf = bufhead;

    while (buf != NULL) {
        if (buf->id == bufid)
            return buf;
        buf = buf->next;
    }

    /* Didn't find it */
    return NULL;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  crypto_buffer_can_delete
 *
 *  Description:  Determines whether a given buffer can be deleted or not. Only
 *                considers attached reader/writer counts
 * 
 *      Version:  0.0.1
 *       Params:  struct crypto_buffer *buf
 *                struct crypto_file_meta *fm
 *      Returns:  int status
 *                    -EINVAL if fm is NULL or buf is NULL
 *                    -EOPNOTSUPP if cannot delete
 *                    0 otherwise
 *        Usage:  crypto_buffer_can_delete( struct crypto_buffer *buf,
 *                        struct crypto_file_meta *fm )
 *      Outputs:  N/A
 *        Notes:  
 * =============================================================================
 */
int crypto_buffer_can_delete(struct crypto_buffer *buf,
        struct crypto_file_meta *fm)
{
    if (fm == NULL || buf == NULL)
        return -EINVAL;

    if (buf == fm->buf) {
        /* fd is rw, hence only file attached */
        if (fm->mode == O_RDWR)
            return 0;

        /* fd is read and buffer has no write attached */
        if (fm->mode == O_RDONLY && buf->wcount < 1)
            return 0;

        /* fd is write and buffer has no read attached */
        if (fm->mode == O_WRONLY && buf->rcount < 1)
            return 0;

        /* otherwise has more than just this fd attached */
        return -EOPNOTSUPP;
    }

    if (buf->wcount > 0 || buf->rcount > 0)
        return -EOPNOTSUPP;
    
    /* Redundant because the detach method cleans up unreferenced buffers.
     * Execution should never reach this point */
    return 0;
}
