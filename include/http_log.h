/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_LOG_H_
#define _HTTP_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_log_ {

    /* log config info */
    uint8              enable;        /* get from conf */
    char             * logfile;       /* get from conf */

    CRITICAL_SECTION   logCS;

    /* allocated space for log conent of HTTPMsg */
    frame_p            format;
    char             * logcont;
    int                loglen;

    FILE             * fp;

    void             * mgmt;
} HTTPLog, http_log_t;

void * http_log_init  (void * vmgmt);
int    http_log_clean (void * vlog);

int    http_log_write (void * vmsg);

#ifdef __cplusplus
}
#endif

#endif

