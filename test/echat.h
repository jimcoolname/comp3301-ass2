/*
 * =====================================================================
 *
 *       Filename:  echat.h
 *
 *    Description:  echat crypto test program
 *
 *        Version:  0.0.1
 *        Created:  27/09/12 16:13:43
 *
 *         Author:  Tony Lee (Roganartu), uni@roganartu.com
 *   Organisation:  UQ Bachelor of Engineering
 *
 *          Notes:  
 * =====================================================================
 */
#ifndef COMP3301_ECHAT_H
#define COMP3301_ECHAT_H

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include "../ioctl-1.2.h"

#define CRYPTO_DEVICE "/dev/crypto"

unsigned int bufid_1;
unsigned int bufid_2;
unsigned int fd_write;
unsigned int fd_read;
FILE *file_write;
FILE *file_read;

u8 *key;

/* For bold on/off */
const char ESC = 27;

void *forward_local_input(void *argument);

void *forward_remote_output(void *argument);

#endif
