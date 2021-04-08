/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_FCGI_IO_H_
#define _HTTP_FCGI_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

int    http_fcgicon_crash_handle (void * vcon);

int    http_fcgi_send_probe (void * vcon);
int    http_fcgi_send       (void * vcon);
int    http_fcgi_send_final (void * vmsg);

int    http_fcgi_recv       (void * vcon);
int    http_fcgi_recv_parse (void * vcon);
int    http_fcgi_recv_forward (void * vcon);


int    http_fcgi_handle     (void * vmsg);
int    http_fcgi_check      (void * vmsg, void * purl, int urlen);
void * http_fcgi_send_start (void * vfcgisrv, void * vhttpmsg);

int    http_fcgi_srv_send (void * vfcgicon, void * vfcgimsg);

int    http_fcgi_con_lifecheck (void * vcon);

#ifdef __cplusplus
}
#endif

#endif


