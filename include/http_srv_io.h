/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_SRV_IO_H_
#define _HTTP_SRV_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

int http_srv_send_probe (void * vcon);
int http_srv_send       (void * vcon);
int http_srv_send_final (void * vmsg);

int http_srv_recv (void * vcon);

int http_srv_recv_parse (void * vcon);
int http_srv_resbody_parse  (void * vcon, void * vmsg, int64 * offset, int64 * savedbytes);

int http_srv_con_lifecheck (void * vcon);

#ifdef __cplusplus
}
#endif

#endif


