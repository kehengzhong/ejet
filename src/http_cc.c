/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.

   Congestion Control of underlying TCP is activated by removing 
   the event-notification and filling the receiving buffer of TCP connection
 */

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


int http_cli_recv_cc (void * vcon)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMgmt   * mgmt = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * srvmsg = NULL;
    HTTPCon    * srvcon = NULL;
    FcgiSrv    * cgisrv = NULL;
    FcgiMsg    * cgimsg = NULL;
    FcgiCon    * cgicon = NULL;
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
    /* === TUNNEL === */

    if (pcon->httptunnel == 1 && pcon->tunnelcon &&
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
           http_con_close(pcon->tunnelcon);
           http_con_close(pcon);
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
           http_con_close(srvmsg->pcon);
           http_con_close(pcon);
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
        cgicon = http_fcgisrv_con_get(cgisrv, cgimsg->conid);
 
        if (!tcp_connected(iodev_fd(pcon->pdev)) /*||
            (cgicon && !tcp_connected(iodev_fd(cgicon->pdev))) */
           ) {
           http_fcgicon_close(cgicon);
           http_con_close(pcon);
           return -100;
        }
 
        time(&pcon->stamp);
        return 3;
    }

    return 0;
}


int http_cli_send_cc (void * vcon)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMgmt   * mgmt = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * srvmsg = NULL;
    HTTPCon    * srvcon = NULL;
    FcgiSrv    * cgisrv = NULL;
    FcgiMsg    * cgimsg = NULL;
    FcgiCon    * cgicon = NULL;
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
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
 
        http_srv_recv(srvcon);
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
 
            http_srv_recv(srvcon);
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

            http_fcgi_recv(cgicon);
            return 3;
        }
    }

    return 0;
}


int http_srv_recv_cc (void * vcon)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMgmt   * mgmt = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * climsg = NULL;
    HTTPCon    * clicon = NULL;
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
    if ((clicon = pcon->tunnelcon) && frameL(pcon->rcvstream) >= mgmt->proxy_buffer_size) {
        /* As the tunnel connection of client request, if server-side
           receiving speed is greater than client-side sending speed,
           large data will be piled up in rcvstream. Limiting receiving
           speed is needed by neglecting the READ event to activate
           TCP Congestion Control mechanism */
 
        iodev_del_notify(pcon->pdev, RWF_READ);
        pcon->read_ignored++;
 
        if (!tcp_connected(iodev_fd(pcon->pdev))) {
           http_con_close(pcon->tunnelcon);
           http_con_close(pcon);
           return -100;
        }
 
        time(&pcon->stamp);
        if (pcon->srv)
            time(&((HTTPSrv *)(pcon->srv))->stamp);

        return 1;
    }
 
    msg = http_con_msg_first(pcon);
    if (msg && msg->proxied == 2 && (climsg = msg->proxymsg) && !climsg->cacheon &&
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
           http_con_close(climsg->pcon);
           http_con_close(pcon);
           return -100;
        }
 
        time(&pcon->stamp);
        if (pcon->srv)
            time(&((HTTPSrv *)(pcon->srv))->stamp);
 
        return 2;
    }

    return 0;
}

int http_srv_send_cc (void * vcon)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMgmt   * mgmt = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * climsg = NULL;
    HTTPCon    * clicon = NULL;
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
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
 
        http_cli_recv(clicon);
        return 1;
    }

    /* === PROXY === */

    msg = http_con_msg_first(pcon);
    if (msg && msg->proxied == 2 && (climsg = msg->proxymsg)) {
        clicon = climsg->pcon;

        if (clicon && clicon->read_ignored > 0 && 
            chunk_rest_size(msg->req_body_chunk, 0) < mgmt->proxy_buffer_size)
        {
            iodev_add_notify(clicon->pdev, RWF_READ);
            clicon->read_ignored = 0;
 
            http_cli_recv(clicon);
            return 2;
        }
    }

    return 0;
}


int http_fcgi_recv_cc (void * vcon)
{
    FcgiCon    * pcon = (FcgiCon *)vcon;
    FcgiMsg    * msg = NULL;
    HTTPMsg    * httpmsg = NULL;
    HTTPCon    * httpcon = NULL;
    HTTPMgmt   * mgmt = NULL;
 
    if (!pcon) return -1;
 
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
 
        httpcon = httpmsg->pcon;
 
        if (/*!tcp_connected(iodev_fd(pcon->pdev)) ||*/
            (httpcon && !tcp_connected(iodev_fd(httpcon->pdev)))
           ) {
           http_con_close(httpmsg->pcon);
           http_fcgicon_close(pcon);
           return -100;
        }
 
        time(&pcon->stamp);
        if (pcon->srv)
            time(&((FcgiSrv *)(pcon->srv))->stamp);
 
        return 1;
    }

    return 0;
}

int http_fcgi_send_cc (void * vcon)
{
    FcgiCon    * pcon = (FcgiCon *)vcon;
    FcgiMsg    * msg = NULL;
    HTTPMsg    * httpmsg = NULL;
    HTTPCon    * httpcon = NULL;
    HTTPMgmt   * mgmt = NULL;
 
    if (!pcon) return -1;
 
    msg = http_fcgicon_msg_first(pcon);
    if (msg && (httpmsg = msg->httpmsg) && httpmsg->fastcgi == 1) {
        httpcon = httpmsg->pcon;
 
        mgmt = (HTTPMgmt *)httpmsg->httpmgmt;
        if (!mgmt) mgmt = gp_httpmgmt;
 
        /* read the blocked data in server-side kernel socket for
           client-side congestion control */
        if (httpcon && httpcon->read_ignored > 0 &&
            chunk_rest_size(msg->req_body_chunk, 0) < mgmt->fcgi_buffer_size)
        {
            iodev_add_notify(httpcon->pdev, RWF_READ);
            httpcon->read_ignored = 0;

            http_cli_recv(httpcon);

            return 1;
        }
    }

    return 0;
}

