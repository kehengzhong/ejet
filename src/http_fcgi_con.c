/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"
#include "http_mgmt.h"
#include "http_fcgi_srv.h"
#include "http_fcgi_con.h"
#include "http_fcgi_msg.h"
#include "http_fcgi_io.h"

extern HTTPMgmt * gp_httpmgmt;

int http_fcgicon_cmp_http_fcgicon(void * a, void * b)
{
    FcgiCon * acon = (FcgiCon *)a;
    FcgiCon * bcon = (FcgiCon *)b;

    if (!acon || !bcon) return -1;

    if (acon->conid == bcon->conid) return 0;
    if (acon->conid > bcon->conid) return 1;
    return -1;
}

int http_fcgicon_cmp_conid (void * a, void * pat)
{
    FcgiCon * pcon = (FcgiCon *)a;
    ulong     cid = *(ulong *)pat;

    if (!pcon || !pat) return -1;

    if (pcon->conid == cid) return 0;
    if (pcon->conid > cid) return 1;
    return -1;
}
 
ulong http_fcgicon_hash_func (void * key)
{
    ulong cid = *(ulong *)key;
    return cid;
}


int http_fcgicon_init (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;

    if (!pcon) return -1;

    pcon->conid = 0;
    pcon->rcv_state = FCGI_CON_NULL;
    pcon->snd_state = FCGI_CON_IDLE;

    memset(&pcon->dstip, 0, sizeof(pcon->dstip));
    pcon->dstport = 0;

    InitializeCriticalSection(&pcon->rcvCS);
    if (pcon->pdev) {
        iodev_close(pcon->pdev);
        pcon->pdev = NULL;
    }
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
    if (pcon->life_timer) {
        iotimer_stop(pcon->life_timer);
        pcon->life_timer = NULL;
    }

    pcon->retrytimes = 0;
    pcon->reqnum = 0;
    pcon->resnum = 0;
    pcon->keepalive = 0;

    if (pcon->msg) {
        http_fcgimsg_close(pcon->msg);
        pcon->msg = NULL;
    }

    InitializeCriticalSection(&pcon->msglistCS);
    if (pcon->msg_list == NULL) {
        pcon->msg_list = arr_new(4);
    }
    while (arr_num(pcon->msg_list) > 0)
        http_fcgimsg_close(arr_pop(pcon->msg_list));
    arr_zero(pcon->msg_list);
 
    return 0;
}

int http_fcgicon_free (void * vcon)
{
    FcgiCon * pcon = (FcgiCon *)vcon;

    if (!pcon) return -1;

    pcon->rcv_state = FCGI_CON_NULL;
    pcon->snd_state = FCGI_CON_IDLE;

    if (pcon->msg) {
        http_fcgimsg_close(pcon->msg);
        pcon->msg = NULL;
    }

    DeleteCriticalSection(&pcon->rcvCS);
    if (pcon->pdev) {
        iodev_close(pcon->pdev);
        pcon->pdev = NULL;
    }
    pcon->read_ignored = 0;

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

    while (arr_num(pcon->msg_list) > 0) {
        if (pcon->srv)
            http_fcgisrv_msg_push(pcon->srv, arr_pop(pcon->msg_list));
        else
            http_fcgimsg_close(arr_pop(pcon->msg_list));
    }
    arr_free(pcon->msg_list);

    return 0;
}
     
void * http_fcgicon_fetch (void * vsrv)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    HTTPMgmt * mgmt = NULL;
    FcgiCon  * pcon = NULL;

    if (!srv) return NULL;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return NULL;

    pcon = mpool_fetch(mgmt->fcgicon_pool);
    if (!pcon) {
        pcon = kzalloc(sizeof(*pcon));
        if (!pcon) return NULL;

        http_fcgicon_init(pcon);
    }

    pcon->conid = http_fcgisrv_get_conid(srv);

    pcon->srv = srv;
    pcon->pcore = srv->pcore;

    return pcon;
}

int http_fcgicon_recycle (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;
    FcgiSrv  * srv = NULL;
    FcgiMsg  * msg = NULL;
    HTTPMgmt * mgmt = NULL;
 
    if (!pcon) return -1;
     
    srv = (FcgiSrv *)pcon->srv;
    if (!srv) return -2;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return -3;

    while (arr_num(pcon->msg_list) > 0) {
        msg = arr_pop(pcon->msg_list);
 
        http_fcgimsg_close(msg);
    }
    arr_zero(pcon->msg_list);
    pcon->msg = NULL;

    pcon->rcv_state = FCGI_CON_NULL;
    pcon->snd_state = FCGI_CON_IDLE;
 
    if (pcon->pdev) {
        iodev_close(pcon->pdev);
        pcon->pdev = NULL; 
    }
    pcon->read_ignored = 0;

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
 
    if (mgmt->fcgicon_pool)
        mpool_recycle(mgmt->fcgicon_pool, pcon);
    else
        http_fcgicon_free(pcon);

    return 0;
}

int http_fcgicon_close (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;

    if (!pcon) return -1;

    if (http_fcgisrv_con_del(pcon->srv, pcon->conid) != pcon) {
        return -2;
    }

    return http_fcgicon_recycle(pcon);
}

void * http_fcgicon_open (void * vsrv)
{
    FcgiSrv    * srv = (FcgiSrv *)vsrv;
    FcgiCon    * pcon = NULL;
 
    if (!srv) return NULL;
 
    pcon = http_fcgicon_fetch(srv);
    if (!pcon) return NULL;
 
    pcon->socktype = srv->socktype;
    strcpy(pcon->unixsock, srv->unixsock);
    strcpy(pcon->dstip, srv->ip);
    pcon->dstport = srv->port;

    time(&pcon->stamp);

    if (http_fcgicon_connect(pcon) < 0) {
        return NULL;
    }
 
    http_fcgisrv_con_add(srv, pcon);

    return pcon;
}
 
int http_fcgicon_connect (void * vpcon)
{
    FcgiCon  * pcon = (FcgiCon *)vpcon;
    int        ret = 0;
 
    if (!pcon) return -1;
 
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

        if (pcon->socktype == 0) {
            pcon->pdev = eptcp_connect(pcon->pcore,
                                   pcon->dstip, pcon->dstport,
                                   NULL, 0,
                                   (void *)pcon->conid, &ret,
                                   http_fcgisrv_pump, pcon->srv);
        } else {
#ifdef UNIX
            /* open unix socket */
            pcon->pdev = epusock_connect(pcon->pcore,
                                   pcon->unixsock, 
                                   (void *)pcon->conid, &ret,
                                   http_fcgisrv_pump, pcon->srv);
#endif
        }

        if (!pcon->pdev) {
            LeaveCriticalSection(&pcon->rcvCS);
            continue;
        }
 
        if (ret >= 0) { //connect successfully
            LeaveCriticalSection(&pcon->rcvCS);

            ret = http_fcgicon_connected(pcon);
            if (ret < 0) continue;

        } else {

            pcon->snd_state = FCGI_CON_CONNECTING;
 
            pcon->ready_timer = iotimer_start(pcon->pcore,
                                    12 * 1000,
                                    t_fcgi_srv_con_build,
                                    (void *)pcon->conid,
                                    http_fcgisrv_pump, pcon->srv);

            LeaveCriticalSection(&pcon->rcvCS);
        }

        return 0;
    }
 
    if (pcon->socktype == 0)
        tolog(1, "eJet - FastCGI Connect: failed to build TCP Connection to server '%s:%d'.\n",
              pcon->dstip, pcon->dstport);
    else
        tolog(1, "eJet - FastCGI Connect: failed to build Unix Socket to server '%s'.\n",
              pcon->unixsock);

    if (pcon->pdev) {
        iodev_close(pcon->pdev);
        pcon->pdev = NULL;
    }
 
    if (pcon->ready_timer) {
        iotimer_stop(pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    pcon->snd_state = FCGI_CON_IDLE;
    http_fcgicon_close(pcon);

    return -100;
}
 
int http_fcgicon_connected (void * vpcon)
{
    FcgiCon    * pcon = (FcgiCon *)vpcon;
 
    if (!pcon) return -1;
 
    pcon->rcv_state = FCGI_CON_READY;
    pcon->snd_state = FCGI_CON_SEND_READY;
 
    if (pcon->ready_timer) {
        iotimer_stop(pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    time(&pcon->stamp);

    pcon->life_timer = iotimer_start(pcon->pcore,
                                  6 * 1000,
                                  t_fcgi_srv_con_life,
                                  (void *)pcon->conid,
                                  http_fcgisrv_pump,
                                  pcon->srv);
 
    /* send request to the origin server instantly after connected */
    if (arr_num(pcon->msg_list) > 0 || http_fcgisrv_msg_num(pcon->srv) > 0) {
        http_fcgi_send(pcon);
    }
 
    return 0;
}

int http_fcgicon_reqnum (void * vcon)
{
    FcgiCon * pcon = (FcgiCon *)vcon;

    if (!pcon) return 0;
    return pcon->reqnum;
}

ulong http_fcgicon_id (void * vcon)
{
    FcgiCon * pcon = (FcgiCon *)vcon;

    if (!pcon) return 0;
    return pcon->conid;
}

void * http_fcgicon_device (void * vcon)
{
    FcgiCon * pcon = (FcgiCon *)vcon;

    if (!pcon) return NULL;
    return pcon->pdev;
}


int http_fcgicon_msg_add (void * vcon, void * vmsg)
{
    FcgiCon * pcon = (FcgiCon *)vcon;
    FcgiMsg * msg = (FcgiMsg *)vmsg;
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

int http_fcgicon_msg_del (void * vcon, void * vmsg)
{
    FcgiCon * pcon = (FcgiCon *)vcon;
    FcgiMsg * msg = (FcgiMsg *)vmsg;
 
    if (!pcon) return -1;
    if (!msg) return -2;
 
    EnterCriticalSection(&pcon->msglistCS);

    arr_delete_ptr(pcon->msg_list, msg);

    if (msg->pcon == pcon)
        msg->pcon = NULL;
    if (msg->conid == pcon->conid)
        msg->conid = 0;

    LeaveCriticalSection(&pcon->msglistCS);
     
    return 0;
}

void * http_fcgicon_msg_first (void * vcon)
{
    FcgiCon * pcon = (FcgiCon *)vcon;
    FcgiMsg * msg = NULL;
 
    if (!pcon) return NULL;
 
    EnterCriticalSection(&pcon->msglistCS);
    msg = arr_value(pcon->msg_list, 0);
    LeaveCriticalSection(&pcon->msglistCS);
     
    return msg;
}

void * http_fcgicon_msg_last (void * vcon)
{
    FcgiCon * pcon = (FcgiCon *)vcon;
    FcgiMsg * msg = NULL;
    int       num = 0;
 
    if (!pcon) return NULL;
 
    EnterCriticalSection(&pcon->msglistCS);

    num = arr_num(pcon->msg_list);
    if (num > 0)
        msg = arr_value(pcon->msg_list, num - 1);

    LeaveCriticalSection(&pcon->msglistCS);
     
    return msg;
}

