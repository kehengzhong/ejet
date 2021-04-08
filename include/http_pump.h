/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_PUMP_H_
#define _HTTP_PUMP_H_

#ifdef __cplusplus
extern "C" {
#endif


/* HTTP system pump, it's the callback of all device events and timer timeout events */
int http_pump (void * vmgmt, void * vobj, int event, int fdtype);


#ifdef __cplusplus
}
#endif

#endif


