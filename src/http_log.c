/*
 * Copyright (c) 2003-2024 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 *
 * #####################################################
 * #                       _oo0oo_                     #
 * #                      o8888888o                    #
 * #                      88" . "88                    #
 * #                      (| -_- |)                    #
 * #                      0\  =  /0                    #
 * #                    ___/`---'\___                  #
 * #                  .' \\|     |// '.                #
 * #                 / \\|||  :  |||// \               #
 * #                / _||||| -:- |||||- \              #
 * #               |   | \\\  -  /// |   |             #
 * #               | \_|  ''\---/''  |_/ |             #
 * #               \  .-\__  '-'  ___/-. /             #
 * #             ___'. .'  /--.--\  `. .'___           #
 * #          ."" '<  `.___\_<|>_/___.'  >' "" .       #
 * #         | | :  `- \`.;`\ _ /`;.`/ -`  : | |       #
 * #         \  \ `_.   \_ __\ /__ _/   .-` /  /       #
 * #     =====`-.____`.___ \_____/___.-`___.-'=====    #
 * #                       `=---='                     #
 * #     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   #
 * #               佛力加持      佛光普照              #
 * #  Buddha's power blessing, Buddha's light shining  #
 * #####################################################
 */

#include "adifall.ext"
#include "epump.h"
#include "http_mgmt.h"
#include "http_msg.h"
#include "http_variable.h"
#include "http_con.h"
#include "http_log.h"

#if defined(_WIN32) || defined(_WIN64)
#include <process.h>
#endif

#ifdef UNIX
#include <signal.h>
#endif

int http_log_wproc_start (void * vlog);
int http_log_wproc_stop (void * vlog);

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

    sprintf(key, "http.access log.proxy log2file");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&value, &vallen);
    if (ret <= 0 || !value) plog->proxyenable = 0;
    if (value && strcasecmp(value, "on") == 0)
        plog->proxyenable = 1;
    else
        plog->proxyenable = 0;

    sprintf(key, "http.access log.tunnel log2file");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&value, &vallen);
    if (ret <= 0 || !value) plog->tunnelenable = 0;
    if (value && strcasecmp(value, "on") == 0)
        plog->tunnelenable = 1;
    else
        plog->tunnelenable = 0;

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

    plog->mgmt = mgmt;

    plog->quit = 0;
    plog->wlog_num = 0;
    plog->eventwait = 0;

    if (plog->enable) {
        plog->wlog_mpool = kempool_alloc(4096*32, 0);

        plog->wlog_fifo = ar_fifo_new(8);
        plog->wlog_event = event_create();

        plog->fp = fopen(plog->logfile, "a+");

        http_log_wproc_start(plog);
    }

    tolog(1, "eJet - AccessLog '%s' init successfully.\n", plog->logfile);

    return plog;
}

int http_log_clean (void * vlog)
{
    HTTPLog  * plog = (HTTPLog *)vlog;

    if (!plog) return -1;

    http_log_wproc_stop(plog);

    while (plog->wlog_fifo && ar_fifo_num(plog->wlog_fifo) > 0) {
        kfree(ar_fifo_out(plog->wlog_fifo));
    }
    if (plog->wlog_fifo) {
        ar_fifo_free(plog->wlog_fifo);
        plog->wlog_fifo = NULL;
    }

    if (plog->wlog_mpool) {
        kempool_free(plog->wlog_mpool);
        plog->wlog_mpool = NULL;
    }

    if (plog->wlog_event) {
        event_destroy(plog->wlog_event);
        plog->wlog_event = NULL;
    }

    if (plog->fp) {
        fclose(plog->fp);
        plog->fp = NULL;
    }

    if (plog->format) {
        frame_free(plog->format);
        plog->format = NULL;
    }

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
    char     * logrec = NULL;
    int        loglen = 0;
    char       meminfo[256];
    int        milen = 0;

    if (!msg) return -1;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;

    /* if HTTPMsg is to be sent to origin server, actually not sent */
    if (msg->msgtype == 0 && !msg->reqsent)
        return -50;

    plog = (HTTPLog *)mgmt->httplog;
    if (!plog) return -3;

    if (!plog->enable) return 0;
    if (msg->proxied == 2 && !plog->proxyenable) return 0;

    if (!plog->fp) return -200;

    ret = http_var_copy(msg, frameP(plog->format), frameL(plog->format), 
                        NULL, 0, NULL, 0, NULL, 0);
    if (ret <= 0) return -100;

    loglen = ret;

    milen = kemblk_brief(msg->kmemblk, meminfo, sizeof(meminfo));
    if (milen < 0) milen = 0;

    logrec = kem_alloc(plog->wlog_mpool, milen + loglen + 4 + 2);
    if (!logrec) return -101;

    *(int *)logrec = loglen + milen;

    ret = http_var_copy(msg, frameP(plog->format), frameL(plog->format), 
                        logrec + 4, loglen, NULL, 0, NULL, 0);
    if (ret > 0) {
        if (milen > 0) snprintf(logrec + loglen + 4, milen, "%s", meminfo);
        logrec[4 + loglen + milen] = '\0';
        ar_fifo_push(plog->wlog_fifo, logrec);
        if (plog->eventwait) event_set(plog->wlog_event, 1);
    } else {
        kem_free(plog->wlog_mpool, logrec);
    }

    return ret;
}

int http_con_log_write (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPCon  * tunnelcon = NULL;
    HTTPMgmt * mgmt = NULL;
    HTTPLog  * plog = NULL;
    char       timebuf[32];
    char       dstsrv[64];
    char     * logrec = NULL;
    int        loglen = 0;
    char       meminfo[256] = {0};
    int        milen = 0;

    if (!pcon) return -1;

    if (pcon->httptunnel != 1 && pcon->httptunnel != 2)
        return 0;

    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;

    plog = (HTTPLog *)mgmt->httplog;
    if (!plog) return -3;

    if (!plog->enable || !plog->tunnelenable) return 0;

    if (!plog->fp) return -200;

    tunnelcon = pcon->tunnelcon;
    if (http_mgmt_con_get(mgmt, pcon->tunnelconid) != tunnelcon) {
        pcon->tunnelcon = NULL;
        tunnelcon = NULL;
    }

    str_datetime(&pcon->createtime, timebuf, sizeof(timebuf) - 1, 0);

    if (pcon->casetype == HTTP_SERVER) {
        if (tunnelcon)
            snprintf(dstsrv, sizeof(dstsrv)-1, "TO %s:%d",
                     tunnelcon->dstip, tunnelcon->dstport);
        else dstsrv[0] = '\0';

#if defined(_WIN32) || defined(_WIN64)
        loglen = snprintf(NULL, 0, "%s - [%s] \"CONNECT %s\" %s %ds %I64u %I64u",
#else
        loglen = snprintf(NULL, 0, "%s - [%s] \"CONNECT %s\" %s %lds %llu %llu",
#endif
                pcon->srcip, timebuf, pcon->tunnelhost, dstsrv,
                pcon->stamp - pcon->createtime,
                pcon->total_recv, pcon->total_sent);

        if (pcon->alloctype == 3 && pcon->kmemblk) {
            milen = kemblk_brief(pcon->kmemblk, meminfo, sizeof(meminfo));
            if (milen < 0) milen = 0;
        }

        logrec = kem_alloc(plog->wlog_mpool, loglen + milen + 4 + 2);
        if (!logrec) return -101;

        *(int *)logrec = loglen + milen;

#if defined(_WIN32) || defined(_WIN64)
        snprintf(logrec + 4, loglen + milen + 1, "%s - [%s] \"CONNECT %s\" %s %ds %I64u %I64u %s",
#else
        snprintf(logrec + 4, loglen + milen + 1, "%s - [%s] \"CONNECT %s\" %s %lds %llu %llu %s",
#endif
                pcon->srcip, timebuf, pcon->tunnelhost, dstsrv,
                pcon->stamp - pcon->createtime,
                pcon->total_recv, pcon->total_sent, meminfo);
    } else {
        if (tunnelcon)
            snprintf(dstsrv, sizeof(dstsrv)-1, "FROM %s:%d",
                     tunnelcon->srcip, tunnelcon->srcport);
        else dstsrv[0] = '\0';

#if defined(_WIN32) || defined(_WIN64)
        loglen = snprintf(NULL, 0, "%s - [%s] \"CONNECT %s\" %s %ds %I64u %I64u",
#else
        loglen = snprintf(NULL, 0, "%s - [%s] \"CONNECT %s\" %s %lds %llu %llu",
#endif
                pcon->dstip, timebuf, pcon->tunnelhost, dstsrv,
                pcon->stamp - pcon->createtime,
                pcon->total_recv, pcon->total_sent);

        if (pcon->alloctype == 3 && pcon->kmemblk) {
            milen = kemblk_brief(pcon->kmemblk, meminfo, sizeof(meminfo));
            if (milen < 0) milen = 0;
        }

        logrec = kem_alloc(plog->wlog_mpool, loglen + milen + 4 + 2);
        if (!logrec) return -101;

        *(int *)logrec = loglen + milen;

#if defined(_WIN32) || defined(_WIN64)
        snprintf(logrec + 4, loglen + milen + 1, "%s - [%s] \"CONNECT %s\" %s %ds %I64u %I64u %s",
#else
        snprintf(logrec + 4, loglen + milen + 1, "%s - [%s] \"CONNECT %s\" %s %lds %llu %llu %s",
#endif
                pcon->dstip, timebuf, pcon->tunnelhost, dstsrv,
                pcon->stamp - pcon->createtime,
                pcon->total_recv, pcon->total_sent, meminfo);
    }

    logrec[4 + loglen + milen + 1] = '\0';
    ar_fifo_push(plog->wlog_fifo, logrec);

    if (plog->eventwait) event_set(plog->wlog_event, 2);

    return 0;
}


int http_log_wproc (void * vlog)
{
    HTTPLog  * plog = (HTTPLog *)vlog;
    char     * logrec = NULL;
    int        lognum = 0;

    if (!plog) return -1;

    while (!plog->quit) {
        if (ar_fifo_num(plog->wlog_fifo) <= 0) {
            plog->eventwait = 1;
            event_wait(plog->wlog_event, 5*1000);
            plog->eventwait = 0;
            if (plog->quit) break;
        }

        lognum = 0;
        while ((logrec = ar_fifo_out(plog->wlog_fifo)) != NULL) {
            fprintf(plog->fp, "%s\n", logrec + 4);

            lognum++; plog->wlog_num++;

            kem_free(plog->wlog_mpool, logrec);
            logrec = NULL;
        }

        if (lognum > 0) fflush(plog->fp);
    }

    return 0;
}

#if defined(_WIN32) || defined(_WIN64)
unsigned WINAPI http_log_wproc_entry (void * arg)
{
#endif
#ifdef UNIX
void * http_log_wproc_entry (void * arg)
{
    sigset_t sigmask;
    int      ret = 0;

    pthread_detach(pthread_self());

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGPIPE);
    ret = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (ret != 0) {
#ifdef _DEBUG
        tolog(1, "httplog: block sigpipe error\n");
#endif
    }
#endif

    http_log_wproc (arg);

#ifdef UNIX
    return NULL;
#endif
#if defined(_WIN32) || defined(_WIN64)
    return 0;
#endif
}

int http_log_wproc_start (void * vlog)
{
    HTTPLog   * plog = (HTTPLog *)vlog;
#if defined(_WIN32) || defined(_WIN64)
    HANDLE      hpth;
    unsigned    thid;
#endif
#ifdef UNIX
    pthread_attr_t attr;
    pthread_t  thid;
    int        ret = 0;
#endif

    if (!plog) return -1;

#if defined(_WIN32) || defined(_WIN64)
    hpth = (HANDLE)_beginthreadex(
                                NULL,
                                0,
                                http_log_wproc_entry,
                                vlog,
                                0,
                                &thid);
    if (hpth == NULL) {
        return -101;
    }
#endif

#ifdef UNIX
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    do {
        ret = pthread_create(&thid, &attr,
                             http_log_wproc_entry, vlog);
    } while (ret != 0);

    pthread_detach(thid);
#endif

    return 0;
}

int http_log_wproc_stop (void * vlog)
{
    HTTPLog   * plog = (HTTPLog *)vlog;

    if (!plog) return -1;

    fflush(plog->fp);

    plog->quit = 1;
    event_set(plog->wlog_event, -10);

    SLEEP(500);

    return 0;
}

