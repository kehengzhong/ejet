/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"
#include "http_srv.h"
#include "http_con.h"
#include "http_srv_io.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_pump.h"
#include "http_ssl.h"

extern HTTPMgmt * gp_httpmgmt;

int http_con_cmp_http_con(void * a, void * b)
{
    HTTPCon * acon = (HTTPCon *)a;
    HTTPCon * bcon = (HTTPCon *)b;

    if (!acon || !bcon) return -1;

    if (acon->conid == bcon->conid) return 0;
    if (acon->conid > bcon->conid) return 1;
    return -1;
}

int http_con_cmp_conid (void * a, void * pat)
{
    HTTPCon * pcon = (HTTPCon *)a;
    ulong     cid = *(ulong *)pat;

    if (!pcon || !pat) return -1;

    if (pcon->conid == cid) return 0;
    if (pcon->conid > cid) return 1;
    return -1;
}
 
ulong http_con_hash_func (void * key)
{
    ulong cid = *(ulong *)key;
    return cid;
}


int http_con_init (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;

    if (!pcon) return -1;

    pcon->hl = NULL;

    pcon->casetype = 0x00;
    pcon->reqdiag = NULL;
    pcon->reqdiagobj = NULL;

    pcon->conid = 0;
    pcon->rcv_state = HTTP_CON_NULL;
    pcon->snd_state = HTTP_CON_IDLE;

    memset(&pcon->srcip, 0, sizeof(pcon->srcip));
    pcon->srcport = 0;
    memset(&pcon->dstip, 0, sizeof(pcon->dstip));
    pcon->dstport = 0;

    InitializeCriticalSection(&pcon->rcvCS);
    if (pcon->pdev) {
        iodev_close(pcon->pdev);
        pcon->pdev = NULL;
    }

#ifdef HAVE_OPENSSL
    if (pcon->sslctx) {
        pcon->sslctx = NULL;
    }
#endif

    if (pcon->tunnelcon) {
        pcon->tunnelcon = NULL;
    }
    pcon->tunnelconid = 0;
    pcon->read_ignored = 0;

    if (pcon->rcvstream == NULL) 
        pcon->rcvstream = frame_new(8192);
    frame_empty(pcon->rcvstream);

    if (pcon->ready_timer) {
        iotimer_stop(pcon->ready_timer);
        pcon->ready_timer = NULL;
    }

    pcon->stamp = 0;
    pcon->createtime = 0;
    pcon->transbgn = 0;
    if (pcon->life_timer) {
        iotimer_stop(pcon->life_timer);
        pcon->life_timer = NULL;
    }

    pcon->retrytimes = 0;
    pcon->reqnum = 0;
    pcon->resnum = 0;
    pcon->keepalive = 0;
    pcon->ssl_link = 0;
    pcon->ssl_handshaked = 0;
    pcon->transact = 0;
    pcon->httptunnel = 0;
    pcon->tunnelself = 0;

    if (pcon->msg) {
        pcon->msg = NULL;
    }

    InitializeCriticalSection(&pcon->msglistCS);
    if (pcon->msg_list == NULL) {
        pcon->msg_list = arr_new(4);
    }
    while (arr_num(pcon->msg_list) > 0)
        http_msg_close(arr_pop(pcon->msg_list));
    arr_zero(pcon->msg_list);
 
    pcon->srv = NULL;

    return 0;
}

int http_con_free (void * vcon)
{
    HTTPCon * pcon = (HTTPCon *)vcon;

    if (!pcon) return -1;

    pcon->rcv_state = HTTP_CON_NULL;
    pcon->snd_state = HTTP_CON_IDLE;

    if (pcon->msg) {
        pcon->msg = NULL;
    }

    DeleteCriticalSection(&pcon->rcvCS);
    if (pcon->pdev) {
        iodev_close(pcon->pdev);
        pcon->pdev = NULL;
    }

    if (pcon->tunnelcon) {
        pcon->tunnelcon = NULL;
    }
    pcon->tunnelconid = 0;
    pcon->read_ignored = 0;

#ifdef HAVE_OPENSSL
    if (pcon->sslctx) {
        pcon->sslctx = NULL;
    }

    if (pcon->ssl_link) {
        if (pcon->ssl) {
            http_ssl_free(pcon->ssl);
            pcon->ssl = NULL;
        }
    }
#endif

    frame_delete(&pcon->rcvstream);

    if (pcon->ready_timer) {
        iotimer_stop(pcon->ready_timer);
        pcon->ready_timer = NULL;
    }

    if (pcon->life_timer) {
        iotimer_stop(pcon->life_timer);
        pcon->life_timer = NULL;
    }

    DeleteCriticalSection(&pcon->msglistCS);

    arr_free(pcon->msg_list);

    kfree(pcon);
    return 0;
}
     
void * http_con_fetch (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;

    if (!mgmt) return NULL;

    pcon = bpool_fetch(mgmt->con_pool);
    if (!pcon) {
        pcon = kzalloc(sizeof(*pcon));
        if (!pcon) return NULL;

        pcon->mgmt = mgmt;
        http_con_init(pcon);
    }

    EnterCriticalSection(&mgmt->conCS);
    pcon->conid = mgmt->conid++;
    LeaveCriticalSection(&mgmt->conCS);

    http_mgmt_con_add(mgmt, pcon);

    pcon->mgmt = mgmt;
    pcon->pcore = mgmt->pcore;

    return pcon;
}

int http_con_recycle (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * msg = NULL;
 
    if (!pcon) return -1;
     
    mgmt = (HTTPMgmt *)gp_httpmgmt;

    if (pcon->casetype == HTTP_CLIENT) {
        while (arr_num(pcon->msg_list) > 0) {
            msg = arr_pop(pcon->msg_list);
 
            http_msg_close(msg);
        }
        arr_zero(pcon->msg_list);
        pcon->msg = NULL;

    } else {
        while (arr_num(pcon->msg_list) > 0) {
            msg = arr_pop(pcon->msg_list);

            if (msg && msg->tear_down_notify)
                (*msg->tear_down_notify)(msg, msg->tear_down_para);

            http_msg_close(msg);
        }

        arr_zero(pcon->msg_list);
    }

    pcon->rcv_state = HTTP_CON_NULL;
    pcon->snd_state = HTTP_CON_IDLE;
 
    if (pcon->pdev) {
        iodev_close(pcon->pdev);
        pcon->pdev = NULL; 
    }

    if (pcon->tunnelcon) {
        pcon->tunnelcon = NULL;
    }
    pcon->tunnelconid = 0;
    pcon->read_ignored = 0;

#ifdef HAVE_OPENSSL
    if (pcon->sslctx) {
        pcon->sslctx = NULL;
    }

    if (pcon->ssl_link) {
        if (pcon->ssl) {
            http_ssl_free(pcon->ssl);
            pcon->ssl = NULL;
        }
    }
#endif

    if (frame_size(pcon->rcvstream) > 16384)
        frame_delete(&pcon->rcvstream);
    frame_empty(pcon->rcvstream);

    if (pcon->ready_timer) {
        iotimer_stop(pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    if (pcon->life_timer) {
        iotimer_stop(pcon->life_timer);
        pcon->life_timer = NULL;
    }
 
    if (mgmt && mgmt->con_pool)
        bpool_recycle(mgmt->con_pool, pcon);
    else
        http_con_free(pcon);

    return 0;
}

int http_con_close (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;

    if (!pcon) return -1;

    if (http_mgmt_con_del(gp_httpmgmt, pcon->conid) != pcon) {
        return -2;
    }

    if (pcon->srv) {
        http_srv_con_del(pcon->srv, pcon->conid);
    }

    return http_con_recycle(pcon);
}


void * http_con_open (void * vsrv, char * dstip, int dstport, int ssl_link)
{
    HTTPSrv    * srv = (HTTPSrv *)vsrv;
    HTTPMgmt   * mgmt = NULL;
    HTTPCon    * pcon = NULL;
 
    if (srv) {
        mgmt = (HTTPMgmt *)srv->mgmt;
        if (!mgmt) return NULL;
 
        pcon = http_con_fetch(mgmt);
        if (!pcon) return NULL;
 
        strcpy(pcon->dstip, srv->ip);
        pcon->dstport = srv->port;
        pcon->casetype = HTTP_CLIENT;

        pcon->ssl_link = srv->ssl_link;
 
        pcon->srv = srv;

    } else {
        mgmt = gp_httpmgmt;

        pcon = http_con_fetch(mgmt);
        if (!pcon) return NULL;
 
        strcpy(pcon->dstip, dstip);
        pcon->dstport = dstport;
        pcon->casetype = HTTP_CLIENT;

        pcon->ssl_link = ssl_link;

        pcon->srv = NULL;
    }
 
    time(&pcon->stamp);

    if (http_con_connect(pcon) < 0) {
        http_srv_set_active(pcon->srv, 0);
        return NULL;
    }
 
    http_srv_con_add(srv, pcon);

    return pcon;
}
 
int http_con_connect (void * vpcon)
{
    HTTPCon  * pcon = (HTTPCon *)vpcon;
    HTTPMgmt * mgmt = NULL;
    int        ret = 0;
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
    for (pcon->retrytimes++ ; pcon->retrytimes < 3; pcon->retrytimes++) {

        if (pcon->pdev) {
            iodev_close(pcon->pdev);
            pcon->pdev = NULL;
        }
 
        if (pcon->ready_timer) {
            iotimer_stop(pcon->ready_timer);
            pcon->ready_timer = NULL;
        }
 
        EnterCriticalSection(&pcon->rcvCS);

        pcon->pdev = eptcp_connect(pcon->pcore,
                                   pcon->dstip, pcon->dstport,
                                   NULL, 0,
                                   (void *)pcon->conid, &ret,
                                   http_pump, pcon->mgmt);
        if (!pcon->pdev) {
            LeaveCriticalSection(&pcon->rcvCS);
            continue;
        }
 
        if (ret >= 0) { //connect successfully
            LeaveCriticalSection(&pcon->rcvCS);

            ret = http_con_connected(pcon);
            if (ret < 0) continue;

        } else {

            pcon->snd_state = HTTP_CON_CONNECTING;
 
            pcon->ready_timer = iotimer_start(pcon->pcore,
                                    mgmt->srv_connecting_time * 1000,
                                    t_http_srv_con_build,
                                    (void *)pcon->conid,
                                    http_pump, pcon->mgmt);

            LeaveCriticalSection(&pcon->rcvCS);
        }

        return 0;
    }
 
    tolog(1, "eJet - TCP Connect: failed connecting to '%s:%d'.\n",
          pcon->dstip, pcon->dstport);

    if (pcon->pdev) {
        iodev_close(pcon->pdev);
        pcon->pdev = NULL;
    }
 
    if (pcon->ready_timer) {
        iotimer_stop(pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    pcon->snd_state = HTTP_CON_IDLE;
    http_con_close(pcon);

    return -100;
}
 
int http_con_connected (void * vpcon)
{
    HTTPCon    * pcon = (HTTPCon *)vpcon;
    HTTPMgmt   * mgmt = NULL;
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
    http_srv_set_active(pcon->srv, 1);

    pcon->rcv_state = HTTP_CON_READY;
    pcon->snd_state = HTTP_CON_SEND_READY;
 
    if (pcon->ready_timer) {
        iotimer_stop(pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    time(&pcon->stamp);

    pcon->life_timer = iotimer_start(mgmt->pcore,
                                  mgmt->conn_check_interval * 1000,
                                  t_http_srv_con_life,
                                  (void *)pcon->conid,
                                  http_pump,
                                  mgmt);
 
#ifdef HAVE_OPENSSL
    if (pcon->ssl_link) {
        pcon->sslctx = http_srv_ssl_ctx_get(pcon->srv, pcon);
        pcon->ssl = http_ssl_new(pcon->sslctx, pcon);
        pcon->ssl_handshaked = 0;
        pcon->snd_state = HTTP_CON_SSL_HANDSHAKING;

        return http_ssl_connect(pcon);
    }
#endif

    /* send request to the origin server instantly after connected */
    if (arr_num(pcon->msg_list) > 0 || http_srv_msg_num(pcon->srv) || pcon->httptunnel > 0) {
        http_srv_send(pcon);
    }
 
    return 0;
}

char * http_con_srcip (void * vcon)
{
    HTTPCon * pcon = (HTTPCon *)vcon;

    if (!pcon) return "";

    return pcon->srcip;
}

int http_con_srcport (void * vcon)
{
    HTTPCon * pcon = (HTTPCon *)vcon;

    if (!pcon) return -1;
    return pcon->srcport;
}

int http_con_reqnum (void * vcon)
{
    HTTPCon * pcon = (HTTPCon *)vcon;

    if (!pcon) return 0;
    return pcon->reqnum;
}

ulong http_con_id (void * vcon)
{
    HTTPCon * pcon = (HTTPCon *)vcon;

    if (!pcon) return 0;
    return pcon->conid;
}

void * http_con_iodev (void * vcon)
{
    HTTPCon * pcon = (HTTPCon *)vcon;

    if (!pcon) return NULL;
    return pcon->pdev;
}


int http_con_msg_add (void * vcon, void * vmsg)
{
    HTTPCon * pcon = (HTTPCon *)vcon;
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    int       i, num;

    if (!pcon) return -1;
    if (!msg) return -2;

    EnterCriticalSection(&pcon->msglistCS);

    msg->pcon = pcon;
    msg->conid = pcon->conid;

    num = arr_num(pcon->msg_list);

    for (i = 0; i < num; i++) {
        if (arr_value(pcon->msg_list, i) == msg) {
            LeaveCriticalSection(&pcon->msglistCS);
            return 0;
        }
    }

    arr_push(pcon->msg_list, msg);

    LeaveCriticalSection(&pcon->msglistCS);

    return 0;
}

int http_con_msg_del (void * vcon, void * vmsg)
{
    HTTPCon * pcon = (HTTPCon *)vcon;
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!pcon) return -1;
    if (!msg) return -2;
 
    EnterCriticalSection(&pcon->msglistCS);

    arr_delete_ptr(pcon->msg_list, msg);

    if (msg->pcon == pcon)
        msg->pcon = NULL;
    if (msg->conid == pcon->conid)
        msg->conid = 0;

    if (pcon->msg == msg)
        pcon->msg = NULL;

    LeaveCriticalSection(&pcon->msglistCS);
     
    return 0;
}

void * http_con_msg_first (void * vcon)
{
    HTTPCon * pcon = (HTTPCon *)vcon;
    HTTPMsg * msg = NULL;
 
    if (!pcon) return NULL;
 
    EnterCriticalSection(&pcon->msglistCS);
    msg = arr_value(pcon->msg_list, 0);
    LeaveCriticalSection(&pcon->msglistCS);
     
    return msg;
}

void * http_con_msg_last (void * vcon)
{
    HTTPCon * pcon = (HTTPCon *)vcon;
    HTTPMsg * msg = NULL;
    int       num = 0;
 
    if (!pcon) return NULL;
 
    EnterCriticalSection(&pcon->msglistCS);

    num = arr_num(pcon->msg_list);
    if (num > 0)
        msg = arr_value(pcon->msg_list, num - 1);

    LeaveCriticalSection(&pcon->msglistCS);
     
    return msg;
}

