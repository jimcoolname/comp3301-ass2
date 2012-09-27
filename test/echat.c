/*
 * =============================================================================
 *
 *       Filename:  echat.c
 *
 *    Description:  echat crypto test program
 *
 *        Version:  0.0.1
 *        Created:  27/09/12 16:12:49
 *
 *         Author:  Tony Lee (Roganartu), uni@roganartu.com
 *   Organisation:  UQ Bachelor of Engineering
 *
 *          Notes:  
 * =============================================================================
 */
#include "echat.h"

int main(int argc, char *argv[])
{
    int err = 0;
    char *buf;

    bufid_1 = bufid_2 = 0;

    switch (argc) {
        case 4:
            bufid_1 = atoi(argv[2]);
            bufid_2 = atoi(argv[3]);
        case 2:
            key = malloc(strlen(argv[1]) + 1);
            if (key == NULL)
                return -ENOMEM;
            strncpy(key, argv[1], strlen(argv[1]) + 1);
            break;
        default:
            fprintf(stderr, "Usage: \n\
user 1: echat encryption_key\n\
user 2: echat encryption_key buffer_id_1 buffer_id_2\n");
            return 1;
    }

    fd_write = open(CRYPTO_DEVICE, O_WRONLY);
    fd_read = open(CRYPTO_DEVICE, O_RDONLY);

    if (fd_write == -1 || fd_read == -1) {
        perror("Error opening crypto device");
        return errno;
    }

    if (bufid_1 == 0 && bufid_2 == 0) {
        /* First instance setting up the buffers */
        bufid_1 = ioctl(fd_write, CRYPTO_IOCCREATE);
        if (bufid_1 < 1) {
            perror("Error creating buffer");
            return bufid_1;
        }
        bufid_2 = ioctl(fd_read, CRYPTO_IOCCREATE);
        if (bufid_2 < 1) {
            perror("Error creating buffer");
            return bufid_2;
        }
        fprintf(stderr, "first_buffer_id: %d, second_buffer_id: %d\n", bufid_1,
                bufid_2);
    } else if (bufid_1 > 0 && bufid_2 > 0) {
        /* Second instance checking in */
        err = ioctl(fd_read, CRYPTO_IOCTATTACH, bufid_1);
        if (err != 0) {
            perror("Error attaching to buffer");
            return err;
        }

        err = ioctl(fd_write, CRYPTO_IOCTATTACH, bufid_2);
        if (err != 0) {
            perror("Error attaching to buffer");
            return err;
        }
    } else {
        fprintf(stderr, "Invalid buffer id supplied\n");
        return 2;
    }

    file_write = fdopen(fd_write, "w");
    file_read = fdopen(fd_read, "r");

    if (argc == 2) {
        buf = malloc(81);
        if (buf == NULL)
            return -ENOMEM;
        while (fgets(buf, 80, stdin) != NULL) {
            fprintf(file_write, "%s", buf);
            fflush(file_write);
        }
        free(buf);
    } else {
        buf = malloc(81);
        if (buf == NULL)
            return -ENOMEM;
        while (fgets(buf, 80, file_read) != NULL) {
            fprintf(stdout, "%s", buf);
            fflush(stdout);
        }
        free(buf);
    }

    /* Cleanup */
    free(key);
    close(fd_write);
    close(fd_read);

    return 0;
}
