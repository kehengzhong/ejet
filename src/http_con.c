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
#include "http_srv.h"
#include "http_con.h"
#include "http_srv_io.h"
#include "http_header.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_pump.h"
#include "http_ssl.h"
#include "http_log.h"
#include "http_request.h"
#include "http_proxy.h"

extern HTTPMgmt * gp_httpmgmt;
extern char * g_http_version;

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
    ulong     cid = (ulong)pat;

    if (!pcon) return -1;

    if (pcon->conid == cid) return 0;
    if (pcon->conid > cid) return 1;
    return -1;
}
 
ulong http_con_hash_func (void * key)
{
    ulong cid = (ulong)key;
    return cid;
}


int http_con_init (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
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

    pcon->hl = NULL;

    pcon->casetype = 0x00;

    pcon->conid = 0;
    pcon->workerid = 0;
    pcon->rcv_state = HTTP_CON_NULL;
    pcon->snd_state = HTTP_CON_IDLE;
    pcon->tunnel_built = 0;
    pcon->tunnel_state = HTTP_TUNNEL_NONE;

    memset(&pcon->srcip, 0, sizeof(pcon->srcip));
    pcon->srcport = 0;
    memset(&pcon->dstip, 0, sizeof(pcon->dstip));
    pcon->dstport = 0;

    InitializeCriticalSection(&pcon->rcvCS);
    InitializeCriticalSection(&pcon->excCS);
    pcon->pdev = NULL;
    pcon->devid = 0;

#ifdef HAVE_OPENSSL
    pcon->sslctx = NULL;
#endif

    pcon->tunnelcon = NULL;
    pcon->tunnelhost = NULL;
    pcon->tunnelconid = 0;
    pcon->read_ignored = 0;

    pcon->rcvstream = frame_alloc(0, pcon->alloctype, pcon->kmemblk);

    pcon->ready_timer = NULL;
    pcon->life_timer = NULL;

    pcon->stamp = 0;
    pcon->createtime = 0;
    pcon->transbgn = 0;

    pcon->retrytimes = 0;
    pcon->reqnum = 0;
    pcon->resnum = 0;
    pcon->keepalive = 0;
    pcon->ssl_link = 0;
    pcon->ssl_handshaked = 0;
    pcon->transact = 0;
    pcon->httptunnel = 0;
    pcon->tunnelself = 0;

    pcon->msg = NULL;

    InitializeCriticalSection(&pcon->msglistCS);
    pcon->msg_list = arr_alloc(4, pcon->alloctype, pcon->kmemblk);
 
    pcon->total_recv = 0;
    pcon->total_sent = 0;

    pcon->srv = NULL;

    return 0;
}

int http_mgmt_con_free (void * vcon)
{
    if (http_con_free(vcon) == 0)
        mpool_recycle(gp_httpmgmt->con_pool, vcon);

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

#ifdef HAVE_OPENSSL
    if (pcon->ssl_link) {
        if (pcon->ssl) {
            http_ssl_free(pcon->ssl);
            pcon->ssl = NULL;
        }
    }

    if (pcon->sslctx) {
        pcon->sslctx = NULL;
    }
#endif

    DeleteCriticalSection(&pcon->rcvCS);
    DeleteCriticalSection(&pcon->excCS);
    if (pcon->pdev) {
        iodev_close_by(pcon->pcore, pcon->devid);
        pcon->pdev = NULL;
    }

    if (pcon->tunnelcon) {
        pcon->tunnelcon = NULL;
    }
    if (pcon->tunnelhost) {
        k_mem_free(pcon->tunnelhost, pcon->alloctype, pcon->kmemblk);
        pcon->tunnelhost = NULL;
    }
    pcon->tunnelconid = 0;
    pcon->read_ignored = 0;

    if (pcon->rcvstream) {
        frame_delete(&pcon->rcvstream);
        pcon->rcvstream = NULL;
    }

    if (pcon->ready_timer) {
        iotimer_stop(pcon->pcore, pcon->ready_timer);
        pcon->ready_timer = NULL;
    }

    if (pcon->life_timer) {
        iotimer_stop(pcon->pcore, pcon->life_timer);
        pcon->life_timer = NULL;
    }

    DeleteCriticalSection(&pcon->msglistCS);

    /* Before the eJet system exits, it will first call http_con_free to release
       all HTTPCon objects, and then release all HTTPMsg. Therefore, if this processing
       flow is followed, the HTTPMsg associated with HTTPCon does not need to be
       released, but only recycled.
       However, in MPool, when the long-term unused memory block where HTTPCon is
       located is freed, the associated HTTPMsg needs to be released. */

    if (pcon->msg_list) {
        while (arr_num(pcon->msg_list) > 0) {
            http_msg_close(arr_pop(pcon->msg_list));
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
     
void * http_con_fetch (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;

    if (!mgmt) return NULL;

    pcon = mpool_fetch(mgmt->con_pool);
    if (!pcon) return NULL;

    EnterCriticalSection(&mgmt->conCS);
    pcon->conid = mgmt->conid++;
    LeaveCriticalSection(&mgmt->conCS);

    http_mgmt_con_add(mgmt, pcon);

    pcon->mgmt = mgmt;
    pcon->pcore = mgmt->pcore;

    return pcon;
}

int http_con_recycle_dbg (void * vcon, char * file, int line)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPCon  * tunnelcon = NULL;
    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * msg = NULL;
 
    if (!pcon) return -1;
     
    mgmt = (HTTPMgmt *)gp_httpmgmt;

    EnterCriticalSection(&pcon->excCS);

    if (pcon->casetype == HTTP_CLIENT) {
 
        while (arr_num(pcon->msg_list) > 0) {
            msg = arr_pop(pcon->msg_list);
            http_msg_close_dbg(msg, file, line);
        }
        arr_free(pcon->msg_list);
        pcon->msg = NULL;
        pcon->msg_list = NULL;

    } else {
        while (arr_num(pcon->msg_list) > 0) {
            msg = arr_pop(pcon->msg_list);

            if (msg && msg->tear_down_notify)
                (*msg->tear_down_notify)(msg, msg->tear_down_para);

            http_msg_close_dbg(msg, file, line);
        }

        arr_free(pcon->msg_list);
        pcon->msg_list = NULL;
    }

#ifdef HAVE_OPENSSL
    if (pcon->ssl_link) {
        if (pcon->ssl) {
            http_ssl_free(pcon->ssl);
            pcon->ssl = NULL;
        }
    }

    if (pcon->sslctx) {
        pcon->sslctx = NULL;
    }
#endif

    pcon->rcv_state = HTTP_CON_NULL;
    pcon->snd_state = HTTP_CON_IDLE;
 
    if (pcon->pdev) {
        iodev_close_by(pcon->pcore, pcon->devid);
        pcon->pdev = NULL; 
    }

    if (pcon->tunnelhost) {
        k_mem_free(pcon->tunnelhost, pcon->alloctype, pcon->kmemblk);
        pcon->tunnelhost = NULL;
    }

    if ((tunnelcon = pcon->tunnelcon) != NULL && tunnelcon->conid == pcon->tunnelconid) {
        tunnelcon->tunnelcon = NULL;
    }
    pcon->tunnelcon = NULL;

    if (pcon->rcvstream) {
        frame_free(pcon->rcvstream);
        pcon->rcvstream = NULL;
    }

    if (pcon->ready_timer) {
        iotimer_stop(mgmt->pcore, pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    if (pcon->life_timer) {
        iotimer_stop(mgmt->pcore, pcon->life_timer);
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

    mpool_recycle(mgmt->con_pool, pcon);

    return 0;
}


int http_con_close_dbg (void * vmgmt, ulong conid, char * file, int line)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;
    HTTPSrv  * srv = NULL;

    if (!mgmt) return -1;

    pcon = http_mgmt_con_del(mgmt, conid);
    if (!pcon) return -2;

    srv = pcon->srv;
    if (srv) {
        http_srv_con_del(srv, conid);
        http_srv_concnt_add(pcon->srv, -1);
    }

    if (pcon->casetype == HTTP_SERVER) {
        http_mgmt_acceptcon_del(gp_httpmgmt, pcon->conid);
    } else if (pcon->casetype == HTTP_CLIENT) {
        http_mgmt_issuedcon_del(gp_httpmgmt, pcon->conid);
    } 

    http_con_log_write(pcon);

    return http_con_recycle_dbg(pcon, file, line);
}


void * http_con_open (void * vsrv, char * dstip, int dstport, int ssl_link, ulong workerid)
{
    HTTPSrv    * srv = (HTTPSrv *)vsrv;
    HTTPMgmt   * mgmt = NULL;
    HTTPCon    * pcon = NULL;
 
    if (srv) {
        mgmt = (HTTPMgmt *)srv->mgmt;
        if (!mgmt) return NULL;
 
        pcon = http_con_fetch(mgmt);
        if (!pcon) return NULL;
 
        strcpy(pcon->dstip, srv->dstip[0]);
        pcon->dstport = srv->dstport;
        pcon->casetype = HTTP_CLIENT;

        pcon->ssl_link = srv->ssl_link;
 
        pcon->srv = srv;
        http_srv_concnt_add(srv, 1);

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
 
    pcon->workerid = workerid;
    pcon->createtime = time(&pcon->stamp);
    http_mgmt_issuedcon_add(mgmt, pcon);

    if (http_con_connect(mgmt, pcon->conid) < 0) {
        http_srv_set_active(pcon->srv, 0);
        return NULL;
    }
 
    return pcon;
}
 
int http_con_connect (void * vmgmt, ulong conid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;
    HTTPCon  * clicon = NULL;
    HTTPMsg  * msg = NULL;
    HTTPMsg  * climsg = NULL;
    int        ret = 0;
 
    if (!mgmt) return -1;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -2;

    while (pcon->retrytimes < 3) {

        pcon->retrytimes++;

        if (pcon->pdev) {
            iodev_close_by(mgmt->pcore, pcon->devid);
            pcon->pdev = NULL;

            http_srv_confail_times(pcon->srv, pcon->retrytimes);
        }
 
        if (pcon->ready_timer) {
            iotimer_stop(mgmt->pcore, pcon->ready_timer);
            pcon->ready_timer = NULL;
        }
 
        EnterCriticalSection(&pcon->rcvCS);

        pcon->pdev = eptcp_connect(pcon->pcore, pcon->dstip, pcon->dstport,
                                   NULL, 0, NULL, (void *)pcon->conid,
                                   http_pump, pcon->mgmt, pcon->workerid, &ret);
        if (!pcon->pdev) {
            LeaveCriticalSection(&pcon->rcvCS);
            continue;
        }
        pcon->devid = iodev_id(pcon->pdev);

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
                                    http_pump, pcon->mgmt,
                                    pcon->workerid);
                                    //iodev_epumpid(pcon->pdev));

            LeaveCriticalSection(&pcon->rcvCS);
        }

        return 0;
    }
 
    if (pcon->pdev) {
        iodev_close_by(mgmt->pcore, pcon->devid);
        pcon->pdev = NULL;

        http_srv_confail_times(pcon->srv, pcon->retrytimes);
    }
 
    if (pcon->ready_timer) {
        iotimer_stop(mgmt->pcore, pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    pcon->snd_state = HTTP_CON_IDLE;

    if (pcon->httptunnel == 2 && pcon->tunnelcon) {
        pcon->tunnelcon->tunnel_state = HTTP_TUNNEL_FAIL;

        msg = http_con_msg_first(pcon->tunnelcon);
        if (msg && msg->res_encoded == 0) {
            msg->SetStatus(msg, 406, NULL);
            msg->Reply(msg);
        } else {
            http_con_close(mgmt, pcon->tunnelconid);
        }

    } else {
        msg = http_con_msg_first(pcon);
        if (msg && msg->proxied == 2 && (climsg = msg->proxymsg)) {
            clicon = http_mgmt_con_get(mgmt, climsg->conid);
            if (clicon && climsg->res_encoded <= 0) {
                climsg->SetStatus(climsg, 503, NULL);
                climsg->AsynReply(climsg, 1, 1);
            }
        }
    }

    http_con_close(mgmt, conid);

    return -100;
}
 
int http_con_connected (void * vpcon)
{
    HTTPCon    * pcon = (HTTPCon *)vpcon;
    HTTPMgmt   * mgmt = NULL;
    HTTPSrv    * srv = NULL;
    HTTPMsg    * msg = NULL;
    HTTPCon    * clicon = NULL;
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
    if (pcon->workerid != iodev_workerid(pcon->pdev)) {
        pcon->workerid = iodev_workerid(pcon->pdev);
    }

    http_connection_issued(mgmt, 1);

    if ((srv = pcon->srv) != NULL) {
        http_srv_consucc_times(pcon->srv, pcon->retrytimes);
        http_srv_set_active(pcon->srv, 1);
    }

    pcon->rcv_state = HTTP_CON_READY;
    pcon->snd_state = HTTP_CON_SEND_READY;
 
    if (pcon->ready_timer) {
        iotimer_stop(mgmt->pcore, pcon->ready_timer);
        pcon->ready_timer = NULL;
    }
 
    time(&pcon->stamp);

    if (pcon->life_timer) iotimer_stop(mgmt->pcore, pcon->life_timer);
    pcon->life_timer = iotimer_start(mgmt->pcore,
                                  mgmt->conn_check_interval * 1000,
                                  t_http_srv_con_life,
                                  (void *)pcon->conid,
                                  http_pump, mgmt, iodev_epumpid(pcon->pdev));

    /* value of httptunnel: 
       1 --> accepted HTTPCon from client, that serves as HTTP Tunnel for the client side
       2 --> connected HTTPCon to Origin server, that serves as HTTP Tunnel for the Origin

       Two kinds of HTTPCon, (1) and (2), must be existing in pairs
     */
    if (srv && srv->proxied && srv->proxyhost) {
        pcon->tunnel_built = 0;

        /* sending HTTP CONNECT request by current HTTPCon */
        return http_con_tunnel_build(pcon);
    }

#ifdef HAVE_OPENSSL
    if (pcon->ssl_link && !pcon->ssl_handshaked) {
        pcon->sslctx = http_srv_ssl_ctx_get(pcon->srv, pcon);
        pcon->ssl = http_ssl_new(pcon->sslctx, pcon);
        pcon->ssl_handshaked = 0;
        pcon->snd_state = HTTP_CON_SSL_HANDSHAKING;

        return http_ssl_connect(mgmt, pcon->conid);
    }
#endif

    if (pcon->httptunnel == 2 && (clicon = pcon->tunnelcon) != NULL) {
        clicon->tunnel_state = HTTP_TUNNEL_SUCC;

        msg = http_con_msg_first(clicon);
        if (msg && msg->res_encoded == 0) {
            msg->SetStatus(msg, 200, "Connection Established");
            msg->Reply(msg);
        }

        if (frameL(clicon->rcvstream) > 0)
            http_tunnel_srv_send(clicon, pcon);
    }

    /* send request to the origin server instantly after connected */
    if (pcon->httptunnel != 2 && (arr_num(pcon->msg_list) > 0 || http_srv_msg_num(pcon->srv))) {
        http_srv_send(mgmt, pcon->conid);
    }

    return 0;
}

int http_con_tunnel_build (void * vcon)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMgmt   * mgmt = NULL;
    HTTPSrv    * srv = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * sslmsg = NULL;
    HeaderUnit * punit = NULL;
    char         buf[512];
 
    if (!pcon) return -1;
 
    if (pcon->httptunnel != 3) return -2;

    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -3;
 
    srv = (HTTPSrv *)pcon->srv;
    if (!srv) return -4;

    if (!srv->proxied || !srv->proxyhost) return -5;

    msg = http_msg_fetch(mgmt);
    if (!msg) return -100;

    msg->SetMethod(msg, "CONNECT", 7);

    sprintf(buf, "%s:%d", srv->host, srv->port);
    msg->SetURL(msg, buf, strlen(buf), 1);

    str_secpy(msg->req_ver, sizeof(msg->req_ver)-1, "HTTP/1.1", 8);
    msg->req_ver_major = 1;
    msg->req_ver_minor = 1;

    msg->req_body_flag = BC_NONE;

    http_header_append(msg, 0, "Connection", -1, "keep-alive", -1);
    http_header_append(msg, 0, "Proxy-Connection", -1, "keep-alive", -1);

    sslmsg = http_con_msg_first(pcon);
    if (sslmsg && (punit = http_header_get(sslmsg, 0, "User-Agent", -1))) {
        str_secpy(buf, sizeof(buf)-21, HUValue(punit), punit->valuelen);
        if (str_casecmp(buf, mgmt->useragent) != 0)
            snprintf(buf + strlen(buf), sizeof(buf)-1-strlen(buf), " via eJet/%s", g_http_version);
        http_header_append(msg, 0, HUName(punit), punit->namelen, buf, strlen(buf));

    } else {
        http_header_append(msg, 0, "User-Agent", -1, mgmt->useragent, strlen(mgmt->useragent));
    }

    http_req_encoding(msg, 1);
    msg->req_encoded = 1;
    chunk_set_end(msg->req_body_chunk);

    http_con_msg_prepend(pcon, msg);

    return http_srv_send(mgmt, pcon->conid);
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


int http_con_msg_prepend (void * vcon, void * vmsg)
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
            arr_delete(pcon->msg_list, i);
            i--; num--;
            continue;
        }
    }

    arr_insert(pcon->msg_list, msg, 0);

    LeaveCriticalSection(&pcon->msglistCS);

    return 0;
}

int http_con_msg_num (void * vcon)
{
    HTTPCon * pcon = (HTTPCon *)vcon;
    int       num = 0;

    if (!pcon) return 0;

    EnterCriticalSection(&pcon->msglistCS);
    num = arr_num(pcon->msg_list);
    LeaveCriticalSection(&pcon->msglistCS);
    return num;
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

int http_con_msg_exist (void * vcon, void * vmsg)
{
    HTTPCon * pcon = (HTTPCon *)vcon;
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    HTTPMsg * iter = NULL;
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

