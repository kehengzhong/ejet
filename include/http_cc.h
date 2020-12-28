/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_CONGESTION_H_
#define _HTTP_CONGESTION_H_

#ifdef __cplusplus
extern "C" {
#endif

int http_cli_recv_cc (void * vcon);
int http_cli_send_cc (void * vcon);

int http_srv_recv_cc (void * vcon);
int http_srv_send_cc (void * vcon);

int http_fcgi_recv_cc (void * vcon);
int http_fcgi_send_cc (void * vcon);

#ifdef __cplusplus
}
#endif

#endif


