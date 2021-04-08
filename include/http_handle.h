/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_HANDLE_H_
#define _HTTP_HANDLE_H_

#ifdef __cplusplus
extern "C" {
#endif


int http_msg_handle (void * vcon, void * vmsg);

int http_connect_process (void * vcon, void * vmsg);
int http_request_process (void * vcon, void * vmsg);


#ifdef __cplusplus
}
#endif

#endif

