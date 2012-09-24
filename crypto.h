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

dev_t device;

// Private function definitions
int __init init_module(void);

void __exit cleanup_module(void);

#endif
