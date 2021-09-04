/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_SNDPXY_H_
#define _HTTP_SNDPXY_H_

#ifdef UNIX
#include <regex.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
#define PCRE_STATIC 1
#include "pcre.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cli_send_proxy_s {
    char      * host;
#ifdef UNIX
    regex_t   * preg;
#endif
#if defined(_WIN32) || defined(_WIN64)
    pcre      * preg;
#endif

    char      * proxy;
    int         port;
} SendProxy;

int   http_send_proxy_init (void * vmgmt);
void  http_send_proxy_clean (void * vmgmt);

int   http_send_proxy_check (void * vmsg);

#ifdef __cplusplus
}
#endif


#endif

