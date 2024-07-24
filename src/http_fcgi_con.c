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
#include "http_con.h"
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
    ulong     cid = (ulong)pat;

    if (!pcon || !pat) return -1;

    if (pcon->conid == cid) return 0;
    if (pcon->conid > cid) return 1;
    return -1;
}
 
ulong http_fcgicon_hash_func (void * key)
{
    ulong cid = (ulong)key;
    return cid;
}


int http_fcgicon_init (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;
    HTTPMgmt * mgmt = (HTTPMgmt *)gp_httpmgmt;

    if (!pcon) return -1;

    pcon->res[0] = pcon->res[1] = pcon->res[2] = pcon->res[3] = NULL;

    if (mgmt->con_kmem_pool && (pcon->kmemblk = mpool_fetch(mgmt->conmem_pool))) {
        kemblk_init(mgmt->con_kmem_pool, pcon->kmemblk, mpool_unitsize(mgmt->conmem_pool), 1);
        pcon->alloctype = 3;
    } else if (mgmt->con_kmem_pool) {
        pcon->kmemblk = mgmt->con_kmem_pool;
        pcon->alloctype = 2;
    } else {
        pcon->kmemblk = NULL;
        pcon->alloctype = 0;
    }

    pcon->conid = 0;
    pcon->workerid = 0;
    pcon->rcv_state = FCGI_CON_NULL;
    pcon->snd_state = FCGI_CON_IDLE;

    memset(&pcon->dstip, 0, sizeof(pcon->dstip));
    pcon->dstport = 0;

    InitializeCriticalSection(&pcon->rcvCS);
    InitializeCriticalSection(&pcon->excCS);

    pcon->pdev = NULL;
    pcon->devid = 0;
    pcon->read_ignored = 0;

    pcon->rcvstream = frame_alloc(0, pcon->alloctype, pcon->kmemblk);

    pcon->ready_timer = NULL;

    pcon->stamp = 0;
    pcon->createtime = 0;
    pcon->life_timer = NULL;

    pcon->retrytimes = 0;
    pcon->reqnum = 0;
    pcon->resnum = 0;
    pcon->keepalive = 0;

    pcon->msg = NULL;

    InitializeCriticalSection(&pcon->msglistCS);
    pcon->msg_list = arr_alloc(4, pcon->alloctype, pcon->kmemblk);
 
    return 0;
}


int http_mgmt_fcgicon_free (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;
    HTTPMgmt * mgmt = NULL;

    if (!pcon) return -1;

    mgmt = gp_httpmgmt;
    if (!mgmt) return -2;

    if (http_fcgicon_free(pcon) == 0)
        mpool_recycle(mgmt->fcgicon_pool, pcon);

    return 0;
}

int http_fcgicon_free (void * vcon)
{
    FcgiCon * pcon = (FcgiCon *)vcon;

    if (!pcon) return -1;

    pcon->rcv_state = FCGI_CON_NULL;
    pcon->snd_state = FCGI_CON_IDLE;

    if (pcon->msg) {
        pcon->msg = NULL;
    }

    DeleteCriticalSection(&pcon->rcvCS);
    DeleteCriticalSection(&pcon->excCS);

    if (pcon->pdev) {
        iodev_close_by(pcon->pcore, pcon->devid);
        pcon->pdev = NULL;
    }
    pcon->read_ignored = 0;

    if (pcon->rcvstream)
        frame_delete(&pcon->rcvstream);

    if (pcon->ready_timer) {
        iotimer_stop(pcon->pcore, pcon->ready_timer);
        pcon->ready_timer = NULL;
    }

    if (pcon->life_timer) {
        iotimer_stop(pcon->pcore, pcon->life_timer);
        pcon->life_timer = NULL;
    }

    DeleteCriticalSection(&pcon->msglistCS);

    if (pcon->msg_list) {
        while (arr_num(pcon->msg_list) > 0) {
            if (pcon->srv)
                http_fcgisrv_msg_push(pcon->srv, arr_pop(pcon->msg_list));
            else
                http_fcgimsg_close(arr_pop(pcon->msg_list));
        }
        arr_free(pcon->msg_list);
        pcon->msg_list = NULL;
    }

    if (pcon->kmemblk) {
        if (pcon->alloctype == 3) {
            kemblk_free(pcon->kmemblk);
        }
        pcon->kmemblk = NULL;
    }

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
    if (!pcon) return NULL;

    pcon->conid = http_fcgisrv_get_conid(srv);

    pcon->srv = srv;
    pcon->pcore = srv->pcore;

    return pcon;
}

int http_fcgicon_recycle_dbg (void * vcon, char * file, int line)
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

    EnterCriticalSection(&pcon->excCS);

    while (arr_num(pcon->msg_list) > 0) {
        msg = arr_pop(pcon->msg_list);
 
        http_fcgimsg_close(msg);
    }
    arr_free(pcon->msg_list);
    pcon->msg_list = NULL;
    pcon->msg = NULL;

    pcon->rcv_state = FCGI_CON_NULL;
    pcon->snd_state = FCGI_CON_IDLE;
 
    if (pcon->pdev) {
        iodev_close_by(mgmt->pcore, pcon->devid);
        pcon->pdev = NULL; 
    }
    pcon->read_ignored = 0;

    if (pcon->rcvstream) {
        frame_free(pcon->rcvstream);
        pcon->rcvstream = NULL;
    }

    if (pcon->ready_timer) {
        iotimer_stop_dbg(mgmt->pcore, pcon->ready_timer, file, line);
        pcon->ready_timer = NULL;
    }
 
    if (pcon->life_timer) {
        iotimer_stop_dbg(mgmt->pcore, pcon->life_timer, file, line);
        pcon->life_timer = NULL;
    }
 
    LeaveCriticalSection(&pcon->excCS);

    if (pcon->kmemblk) {
        if (pcon->alloctype == 3) {
            kemblk_free(pcon->kmemblk);
            mpool_recycle(mgmt->conmem_pool, pcon->kmemblk);
        }
        pcon->kmemblk = NULL;
    }

    mpool_recycle(mgmt->fcgicon_pool, pcon);

    return 0;
}

int http_fcgicon_close_dbg (void * vsrv, ulong conid, char * file, int line)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;

    if (!srv) return -1;

    pcon = http_fcgisrv_con_del(srv, conid);
    if (pcon == NULL) {
        return -2;
    }

    return http_fcgicon_recycle_dbg(pcon, file, line);
}

void * http_fcgicon_open (void * vsrv, ulong workerid)
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

    pcon->workerid = workerid;
    time(&pcon->stamp);

    http_fcgisrv_con_add(srv, pcon);

    if (http_fcgicon_connect(srv, pcon->conid) < 0) {
        return NULL;
    }
 
    return pcon;
}
 
int http_fcgicon_connect (void * vsrv, ulong conid)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;
    FcgiMsg  * msg = NULL;
    HTTPMgmt * mgmt = NULL;
    HTTPCon  * clicon = NULL;
    HTTPMsg  * climsg = NULL;
    int        ret = 0;
 
    if (!srv) return -1;

    pcon = http_fcgisrv_con_get(srv, conid);
    if (!pcon) return -2;
 
    mgmt = gp_httpmgmt;
    if (!mgmt) return -3;

    while (pcon->retrytimes < 3) {

        pcon->retrytimes++;

        if (pcon->pdev) {
            iodev_close_by(mgmt->pcore, pcon->devid);
            pcon->pdev = NULL;
        }
 
        if (pcon->ready_timer) {
            iotimer_stop(pcon->pcore, pcon->ready_timer);
            pcon->ready_timer = NULL;
        }
 
        EnterCriticalSection(&pcon->rcvCS);

        if (pcon->socktype == 0) {
            pcon->pdev = eptcp_connect(pcon->pcore, pcon->dstip, pcon->dstport,
                                   NULL, 0, NULL, (void *)pcon->conid,
                                   http_fcgisrv_pump, pcon->srv, pcon->workerid, &ret);
        } else {
#ifdef UNIX
            /* open unix socket */
            pcon->pdev = epusock_connect(pcon->pcore, pcon->unixsock, 
                                   (void *)pcon->conid, http_fcgisrv_pump,
                                   pcon->srv, pcon->workerid, &ret);
#endif
        }

        if (!pcon->pdev) {
            LeaveCriticalSection(&pcon->rcvCS);
            continue;
        }
        pcon->devid = iodev_id(pcon->pdev);
 
        if (ret >= 0) { //connect successfully
            LeaveCriticalSection(&pcon->rcvCS);

            ret = http_fcgicon_connected(pcon);
            if (ret < 0) continue;

        } else {
            pcon->snd_state = FCGI_CON_CONNECTING;
 
            pcon->ready_timer = iotimer_start(pcon->pcore,
                                    12 * 1000,
                                    t_fcgi_srv_con_build,
                                    (void *)conid,
                                    http_fcgisrv_pump, srv,
                                    iodev_epumpid(pcon->pdev));

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
        iodev_close_by(mgmt->pcore, pcon->devid);
        pcon->pdev = NULL;
    }
 
    if (pcon->ready_timer) {
        iotimer_stop(pcon->pcore, pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    pcon->snd_state = FCGI_CON_IDLE;

    msg = http_fcgicon_msg_first(pcon);

    if (msg && (climsg = msg->httpmsg) && climsg->fastcgi) {
        clicon = http_mgmt_con_get(mgmt, climsg->conid);
        if (clicon) {
            climsg->SetStatus(climsg, 503, NULL);
            climsg->Reply(climsg);
        }
    }

    http_fcgicon_close(srv, conid);

    return -100;
}
 
int http_fcgicon_connected (void * vpcon)
{
    FcgiCon    * pcon = (FcgiCon *)vpcon;
 
    if (!pcon) return -1;
 
    if (pcon->srv) {
        http_fcgisrv_consucc_times(pcon->srv, pcon->retrytimes);
    }

    pcon->rcv_state = FCGI_CON_READY;
    pcon->snd_state = FCGI_CON_SEND_READY;
 
    if (pcon->ready_timer) {
        iotimer_stop(pcon->pcore, pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    time(&pcon->stamp);

    pcon->life_timer = iotimer_start(pcon->pcore,
                                  6 * 1000,
                                  t_fcgi_srv_con_life,
                                  (void *)pcon->conid,
                                  http_fcgisrv_pump,
                                  pcon->srv, iodev_epumpid(pcon->pdev));
 
    /* send request to the origin server instantly after connected */
    if (arr_num(pcon->msg_list) > 0 || http_fcgisrv_msg_num(pcon->srv) > 0) {
        http_fcgi_send(pcon->srv, pcon->conid);
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

int http_fcgicon_msg_exist (void * vcon, void * vmsg)
{   
    FcgiCon * pcon = (FcgiCon *)vcon;
    FcgiMsg * msg = (FcgiMsg *)vmsg;
    FcgiMsg * iter = NULL;
    int       i, num = 0;

    if (!pcon) return -1;

    EnterCriticalSection(&pcon->msglistCS);

    num = arr_num(pcon->msg_list);
    for (i = 0; i < num; i++) {
        iter = arr_value(pcon->msg_list, i);
        if (iter == msg) {
            LeaveCriticalSection(&pcon->msglistCS);
            return i;
        }
    }

    LeaveCriticalSection(&pcon->msglistCS);

    return -1;
}

