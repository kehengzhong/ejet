/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_STATUS_H_
#define _HTTP_STATUS_H_

#ifdef __cplusplus
extern "C" {
#endif

int http_status_init    (void * vmgmt);
int http_status_cleanup (void * vmgmt);

int http_get_status     (void * vmgmt, char * status, int statuslen, char ** preason);
int http_get_status2    (void * vmgmt, int status, char ** preason);

#ifdef __cplusplus
}
#endif

#endif

