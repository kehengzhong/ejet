/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "http_mgmt.h"
#include "http_msg.h"
#include "http_variable.h"
#include "http_log.h"

void * http_log_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPLog  * plog = NULL;
    char       key[128];
    int        keylen = 0;
    char     * value = NULL;
    int        vallen = 0;
    int        i, ret;

    if (!mgmt) return NULL;

    plog = kzalloc(sizeof(*plog));
    if (!plog) return NULL;

    sprintf(key, "http.access log.log2file");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&value, &vallen);
    if (ret <= 0 || !value) plog->enable = 0;
    if (value && strcasecmp(value, "on") == 0)
        plog->enable = 1;
    else
        plog->enable = 0;

    sprintf(key, "http.access log.log file");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&value, &vallen);
    if (ret <= 0 || !value || vallen <= 0) {
        plog->logfile = "./access.log";
    } else {
        plog->logfile = value;

        file_dir_create(plog->logfile, 1);
    }

    plog->format = frame_new(256);

    sprintf(key, "http.access log.format");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&value, &vallen);
    if (ret > 0 && value && vallen > 0) {
        frame_put_nlast(plog->format, value, vallen);
        frame_put_last(plog->format, ' ');

        for (i = 1; i < ret; i++) {
            sprintf(key, "http.access log.format[%d]", i);  keylen = strlen(key);
            ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&value, &vallen);
            if (ret > 0 && value && vallen > 0) {
                frame_put_nlast(plog->format, value, vallen);
                frame_put_last(plog->format, ' ');
            }
        }
    } else {
        frame_append(plog->format, "$remote_addr - [$datetime[createtime]] \"$request\" "
                                   "\"$request_header[host]\" \"$request_header[referer]\" "
                                   "\"$http_user_agent\" $status $bytes_recv $bytes_sent");
    }

    InitializeCriticalSection(&plog->logCS);

    plog->loglen = 4096;
    plog->logcont = kalloc(plog->loglen + 1);

    plog->fp = fopen(plog->logfile, "a+");

    plog->mgmt = mgmt;

    tolog(1, "eJet - AccessLog '%s' init successfully.\n", plog->logfile);

    return plog;
}

int http_log_clean (void * vlog)
{
    HTTPLog  * plog = (HTTPLog *)vlog;

    if (!plog) return -1;

    if (plog->fp) {
        fclose(plog->fp);
        plog->fp = NULL;
    }

    if (plog->format) {
        frame_free(plog->format);
        plog->format = NULL;
    }

    if (plog->logcont) {
        kfree(plog->logcont);
        plog->logcont = NULL;
    }

    DeleteCriticalSection(&plog->logCS);

    kfree(plog);

    tolog(1, "eJet - AccessLog resource freed.\n");

    return 0;
}
 
int http_log_write (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    HTTPLog  * plog = NULL;
    int        ret = 0;

    if (!msg) return -1;

    //if (msg->proxied == 2) return 0;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;

    plog = (HTTPLog *)mgmt->httplog;
    if (!plog) return -3;

    if (!plog->fp) return -200;

    ret = http_var_copy(msg, frameP(plog->format), frameL(plog->format), 
                        NULL, 0, NULL, 0, NULL, 0);
    if (ret < 0) return -100;

    EnterCriticalSection(&plog->logCS);

    if (ret > plog->loglen) {
        plog->loglen = ret;
        kfree(plog->logcont);
        plog->logcont = kalloc(plog->loglen + 1);
    }

    ret = http_var_copy(msg, frameP(plog->format), frameL(plog->format), 
                        plog->logcont, plog->loglen, NULL, 0, NULL, 0);
    if (ret > 0) {
        fprintf(plog->fp, "%s\n", plog->logcont);
        fflush(plog->fp);
    }

    LeaveCriticalSection(&plog->logCS);

    return ret;
}

