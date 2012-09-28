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
    pthread_t threads[2];
    struct crypto_smode m;

    bufid_1 = bufid_2 = 0;

    switch (argc) {
        case 4:
            bufid_1 = atoi(argv[2]);
            bufid_2 = atoi(argv[3]);
        case 2:
            key = malloc(strlen(argv[1]) + 1);
            if (key == NULL)
                return -ENOMEM;
            memcpy(key, argv[1], strlen(argv[1]) + 1);
            break;
        default:
            fprintf(stderr, "Usage: \n\
%c[1muser 1:%c[0m echat encryption_key\n\
%c[1muser 2:%c[0m echat encryption_key buffer_id_1 buffer_id_2\n",
            ESC, ESC, ESC, ESC);
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

    /* Set up file modes and encryption key */
    m.key = key;
    /* Write */
    m.dir = CRYPTO_WRITE;
    m.mode = CRYPTO_ENC;
    err = ioctl(fd_write, CRYPTO_IOCSMODE, &m);
    if (err != 0) {
        fprintf(stderr, "Error setting file mode\n");
        return err;
    }
    /* Read */
    m.dir = CRYPTO_READ;
    m.mode = CRYPTO_DEC;
    err = ioctl(fd_read, CRYPTO_IOCSMODE, &m);
    if (err != 0) {
        fprintf(stderr, "Error setting file mode\n");
        return err;
    }

    file_write = fdopen(fd_write, "w");
    file_read = fdopen(fd_read, "r");

    /* Spawn one thread for reading, one for writing */
    if(pthread_create(&threads[0], NULL, forward_local_input, NULL)) {
        fprintf(stderr, "Error spawning thread\n");
        return 3;
    }

    if(pthread_create(&threads[1], NULL, forward_remote_output, NULL)) {
        fprintf(stderr, "Error spawning thread\n");
        pthread_kill(threads[0], SIGINT);
        return 3;
    }

    /* Join the writer first. Spec says reader isn't interrupted by remote
     * actions */
    if (pthread_join(threads[0], NULL)) {
        fprintf(stderr, "Error joining thread\n");
        pthread_kill(threads[0], SIGINT);
        pthread_kill(threads[1], SIGINT);
        return 4;
    }
    /* Just kill the reader once the writer is finished. It'll never close
     * on it's own*/
    pthread_kill(threads[1], SIGINT);

    /* Cleanup */
    free(key);
    close(fd_write);
    close(fd_read);

    return 0;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  forward_local_input
 *
 *  Description:  Spawned by pthread to handle waiting and sending all stdin
 *                input to the crypto device
 * 
 *      Version:  0.0.1
 *       Params:  void *argument
 *      Returns:  NULL
 *        Usage:  forward_local_input( void *argument )
 *      Outputs:  Unable to allocate memory (if malloc fails)
 *        Notes:  
 * =============================================================================
 */
void *forward_local_input(void *argument)
{
    char *local = malloc(81);
    if (local == NULL) {
        fprintf(stderr, "Unable to allocate memory\n");
        exit(3);
    }
    while (fgets(local, 80, stdin) != NULL) {
        fprintf(file_write, "%s", local);
        fflush(file_write);
    }
    free(local);

    return NULL;
}

/* 
 * ===  FUNCTION  ==============================================================
 *         Name:  forward_remote_output
 *
 *  Description:  Spawned by pthread to handle waiting and printing all device
 *                output
 * 
 *      Version:  0.0.1
 *       Params:  void *argument
 *      Returns:  NULL
 *        Usage:  forward_remote_output( void *argument )
 *      Outputs:  Unable to allocate memory (if malloc fails)
 *        Notes:  
 * =============================================================================
 */
void *forward_remote_output(void *argument)
{
    char *remote = malloc(81);
    if (remote == NULL) {
        fprintf(stderr, "Unable to allocate memory\n");
        exit(3);
    }
    while (fgets(remote, 80, file_read) != NULL) {
        printf("%c[1mStranger:%c[0m ", ESC, ESC);
        fprintf(stdout, "%s", remote);
        fflush(stdout);
    }
    free(remote);

    return NULL;
}
