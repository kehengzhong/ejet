/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_CLI_IO_H_
#define _HTTP_CLI_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

int http_cli_con_crash (void * vcon, int closelad);

int http_cli_accept (void * vmgmt, void * listendev);

int http_cli_recv (void * vcon);
int http_cli_recv_parse    (void * vcon);

int http_reqbody_handle    (void * vmsg);
int http_cli_reqbody_parse (void * vcon, void * vmsg);

int http_cli_send_probe (void * vcon);
int http_cli_send       (void * vcon);
int http_cli_send_final (void * vmsg);

int http_cli_con_lifecheck (void * vcon);


#ifdef __cplusplus
}
#endif

#endif


