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

/* Congestion Control of underlying TCP is activated by removing 
   the event-notification and filling the receiving buffer of TCP connection */

#include "adifall.ext"
#include "epump.h"
#include "http_con.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_srv.h"
#include "http_cli_io.h"
#include "http_srv_io.h"

#include "http_fcgi_srv.h"
#include "http_fcgi_msg.h"
#include "http_fcgi_con.h"
#include "http_fcgi_io.h"

extern HTTPMgmt * gp_httpmgmt;


int http_cli_recv_cc (void * vmgmt, ulong conid)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon    * pcon = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * srvmsg = NULL;
    HTTPCon    * srvcon = NULL;
    FcgiSrv    * cgisrv = NULL;
    FcgiMsg    * cgimsg = NULL;
 
    if (!mgmt) return -1;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -2;

    /* === TUNNEL === */

    if (pcon->httptunnel == 1 && /*pcon->tunnelcon &&*/
        frameL(pcon->rcvstream) >= mgmt->proxy_buffer_size)
    {
        /* As the tunnel connection of client request, if client-side
           receiving speed is greater than server-side sending speed,
           large data will be piled up in rcvstream. Limiting receiving
           speed is needed by neglecting the READ event to activate
           TCP Congestion Control mechanism */
 
        iodev_del_notify(pcon->pdev, RWF_READ);
        pcon->read_ignored++;
 
        if (!tcp_connected(iodev_fd(pcon->pdev))) {
           http_con_close(mgmt, pcon->tunnelconid);
           http_con_close(mgmt, conid);
           return -100;
        }
 
        time(&pcon->stamp);
        return 1;
    }
 
    /* === PROXY === */

    msg = http_con_msg_first(pcon);
    if (msg && msg->proxied == 1 && (srvmsg = msg->proxymsg) &&
            chunk_rest_size(srvmsg->req_body_chunk, 0) >= mgmt->proxy_buffer_size)
    {
        /* congestion control: by neglecting the read-ready event,
           underlying TCP stack recv-buffer will be full soon.
           TCP stack will start congestion control mechanism */
        iodev_del_notify(pcon->pdev, RWF_READ);
        pcon->read_ignored++;
 
        srvcon = srvmsg->pcon;
 
        if (!tcp_connected(iodev_fd(pcon->pdev)) ||
            (srvcon && !tcp_connected(iodev_fd(srvcon->pdev)))
           ) {
           http_con_close(mgmt, srvmsg->conid);
           http_con_close(mgmt, conid);
           return -100;
        }
 
        time(&pcon->stamp);
        return 2;
    }
 
    /* === FastCGI === */

    if (msg && msg->fastcgi == 1 && (cgimsg = msg->fcgimsg) &&
            chunk_rest_size(cgimsg->req_body_chunk, 0) >= mgmt->fcgi_buffer_size)
    {
        /* congestion control: by neglecting the read-ready event,
           underlying TCP stack recv-buffer will be full soon.
           TCP stack will start congestion control mechanism */
        iodev_del_notify(pcon->pdev, RWF_READ);
        pcon->read_ignored++;
 
        cgisrv = (FcgiSrv *)cgimsg->srv;
 
        if (!tcp_connected(iodev_fd(pcon->pdev))) {
           http_fcgicon_close(cgisrv, cgimsg->conid);
           http_con_close(mgmt, conid);
           return -100;
        }
 
        time(&pcon->stamp);
        return 3;
    }

    return 0;
}


int http_cli_send_cc (void * vmgmt, ulong conid)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon    * pcon = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * srvmsg = NULL;
    HTTPCon    * srvcon = NULL;
    FcgiSrv    * cgisrv = NULL;
    FcgiMsg    * cgimsg = NULL;
    FcgiCon    * cgicon = NULL;
 
    if (!mgmt) return -1;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -2;

    /* as the congestion of connection to client, data from peer side are piled up.
       after sending to client successfully, peer connection should be monitored for
       event notification.
     */

    /* === TUNNEL === */

    if (pcon->httptunnel == 1 && (srvcon = pcon->tunnelcon) && 
        srvcon->read_ignored > 0 && frameL(srvcon->rcvstream) < mgmt->proxy_buffer_size)
    {
        iodev_add_notify(srvcon->pdev, RWF_READ);
        srvcon->read_ignored = 0;
 
        http_srv_recv(mgmt, pcon->tunnelconid);
        return 1;
    }

    /* === PROXY === */

    msg = http_con_msg_first(pcon);
    if (msg && msg->proxied == 1 && (srvmsg = msg->proxymsg)) {
        srvcon = srvmsg->pcon;

        if (srvcon && srvcon->read_ignored > 0 && 
            chunk_rest_size(msg->res_body_chunk, 0) < mgmt->proxy_buffer_size)
        {
            iodev_add_notify(srvcon->pdev, RWF_READ);
            srvcon->read_ignored = 0;
 
            http_srv_recv(mgmt, srvmsg->conid);
            return 2;
        }
    }

    /* === FastCGI === */

    if (msg && msg->fastcgi == 1 && (cgimsg = msg->fcgimsg)) {
        cgisrv = (FcgiSrv *)cgimsg->srv;
        cgicon = http_fcgisrv_con_get(cgisrv, cgimsg->conid);
 
        /* read the blocked data in server-side kernel socket for
           client-side congestion control */
        if (cgicon && cgicon->read_ignored > 0 &&
            chunk_rest_size(msg->res_body_chunk, 0) < mgmt->fcgi_buffer_size)
        {
            iodev_add_notify(cgicon->pdev, RWF_READ);
            cgicon->read_ignored = 0;

            http_fcgi_recv(cgisrv, cgimsg->conid);
            return 3;
        }
    }

    return 0;
}


int http_srv_recv_cc (void * vmgmt, ulong conid)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon    * pcon = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * climsg = NULL;
    HTTPCon    * clicon = NULL;
 
    if (!mgmt) return -1;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -2;

    if (pcon->httptunnel == 2 && frameL(pcon->rcvstream) >= mgmt->proxy_buffer_size) {
        /* As the tunnel connection of client request, if server-side
           receiving speed is greater than client-side sending speed,
           large data will be piled up in rcvstream. Limiting receiving
           speed is needed by neglecting the READ event to activate
           TCP Congestion Control mechanism */
 
        iodev_del_notify(pcon->pdev, RWF_READ);
        pcon->read_ignored++;
 
        if (!tcp_connected(iodev_fd(pcon->pdev))) {
           http_con_close(mgmt, pcon->tunnelconid);
           http_con_close(mgmt, conid);
           return -100;
        }
 
        time(&pcon->stamp);
        if (pcon->srv)
            time(&((HTTPSrv *)(pcon->srv))->stamp);

        return 1;
    }
 
    msg = http_con_msg_first(pcon);
    if (msg && msg->workerid != iodev_workerid(pcon->pdev))
        msg->workerid = iodev_workerid(pcon->pdev);

    if (msg && msg->proxied == 2 && (climsg = msg->proxymsg) && climsg->proxied == 1 &&
            climsg->proxymsg == msg && !climsg->cacheon &&
            chunk_rest_size(climsg->res_body_chunk, 0) >= mgmt->proxy_buffer_size)
    {
        /* congestion control: by neglecting the read-ready event,
           underlying TCP stack recv-buffer will be full soon.
           TCP stack will start congestion control mechanism */
        iodev_del_notify(pcon->pdev, RWF_READ);
        pcon->read_ignored++;
 
        clicon = climsg->pcon;
 
        if (!tcp_connected(iodev_fd(pcon->pdev)) ||
            (clicon && !tcp_connected(iodev_fd(clicon->pdev)))
           ) {
           http_con_close(mgmt, climsg->conid);
           http_con_close(mgmt, conid);
           return -100;
        }
 
        time(&pcon->stamp);
        if (pcon->srv)
            time(&((HTTPSrv *)(pcon->srv))->stamp);
 
        return 2;
    }

    return 0;
}

int http_srv_send_cc (void * vmgmt, ulong conid)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon    * pcon = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * climsg = NULL;
    HTTPCon    * clicon = NULL;
 
    if (!mgmt) return -1;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -2;

    /* as the congestion of connection to server, data from peer side are piled up.
       after sending to server successfully, peer connection should be monitored for
       event notification.
     */

    /* === TUNNEL === */

    if (pcon->httptunnel == 2 && (clicon = pcon->tunnelcon) && 
        clicon->read_ignored > 0 && frameL(clicon->rcvstream) < mgmt->proxy_buffer_size)
    {
        iodev_add_notify(clicon->pdev, RWF_READ);
        clicon->read_ignored = 0;
 
        http_cli_recv(mgmt, pcon->tunnelconid);
        return 1;
    }

    /* === PROXY === */

    msg = http_con_msg_first(pcon);
    if (msg && msg->proxied == 2 && (climsg = msg->proxymsg)) {
        clicon = http_mgmt_con_get(mgmt, climsg->conid);

        if (clicon && clicon->read_ignored > 0 && 
            chunk_rest_size(msg->req_body_chunk, 0) < mgmt->proxy_buffer_size)
        {
            iodev_add_notify(clicon->pdev, RWF_READ);
            clicon->read_ignored = 0;
 
            http_cli_recv(mgmt, climsg->conid);
            return 2;
        }
    }

    return 0;
}


int http_fcgi_recv_cc (void * vsrv, ulong conid)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;
    FcgiMsg  * msg = NULL;
    HTTPMsg  * httpmsg = NULL;
    HTTPCon  * httpcon = NULL;
    HTTPMgmt * mgmt = NULL;
 
    if (!srv) return -1;
 
    pcon = http_fcgisrv_con_get(srv, conid);
    if (!pcon) return -2;

    msg = http_fcgicon_msg_first(pcon);
    if (msg) httpmsg = msg->httpmsg;
    if (httpmsg) mgmt = httpmsg->httpmgmt;
    if (!mgmt) mgmt = gp_httpmgmt;
 
    if (msg && httpmsg && mgmt &&
        chunk_rest_size(httpmsg->res_body_chunk, 0) >= mgmt->fcgi_buffer_size)
    {
        /* congestion control: by neglecting the read-ready event,
           underlying TCP/UnixSocket stack recv-buffer will be full soon.
           TCP/UnixSocket stack will start congestion control mechanism */
        iodev_del_notify(pcon->pdev, RWF_READ);
        pcon->read_ignored++;
 
        httpcon = http_mgmt_con_get(mgmt, httpmsg->conid);
 
        if ((httpcon && !tcp_connected(iodev_fd(httpcon->pdev)))) {
           http_con_close(mgmt, httpmsg->conid);
           http_fcgicon_close(srv, conid);
           return -100;
        }
 
        time(&pcon->stamp);
        if (pcon->srv)
            time(&((FcgiSrv *)(pcon->srv))->stamp);
 
        return 1;
    }

    return 0;
}

int http_fcgi_send_cc (void * vsrv, ulong conid)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;
    FcgiMsg  * msg = NULL;
    HTTPMsg  * httpmsg = NULL;
    HTTPCon  * httpcon = NULL;
    HTTPMgmt * mgmt = NULL;
 
    if (!srv) return -1;
 
    pcon = http_fcgisrv_con_get(srv, conid);
    if (!pcon) return -2;

    mgmt = gp_httpmgmt;
 
    msg = http_fcgicon_msg_first(pcon);
    if (msg && (httpmsg = msg->httpmsg) && httpmsg->fastcgi == 1) {
        httpcon = http_mgmt_con_get(mgmt, httpmsg->conid);
 
        /* read the blocked data in server-side kernel socket for
           client-side congestion control */
        if (httpcon && httpcon->read_ignored > 0 &&
            chunk_rest_size(msg->req_body_chunk, 0) < mgmt->fcgi_buffer_size)
        {
            iodev_add_notify(httpcon->pdev, RWF_READ);
            httpcon->read_ignored = 0;

            http_cli_recv(mgmt, httpmsg->conid);

            return 1;
        }
    }

    return 0;
}

