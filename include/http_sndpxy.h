/*
 * Copyright (c) 2003-2020 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_SNDPXY_H_
#define _HTTP_SNDPXY_H_

#include <regex.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cli_send_proxy_s {
    char      * host;
    regex_t   * preg;

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

