/*
 * Copyright (c) 2003-2020 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"
#include "http_con.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_pump.h"
#include "http_cli_io.h"
#include "http_srv_io.h"
#include "http_listen.h"
#include "http_header.h"
#include "http_do.h"
#include "http_request.h"
#include "http_response.h"
#include "http_srv.h"
#include "http_chunk.h"
#include "http_ssl.h"
#include "http_cache.h"
#include "http_proxy.h"


int http_proxy_check (void * vmsg, void * purl, int urlen)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    HTTPListen   * hl = NULL;
    char         * url = (char *)purl;
    int            ret = 0;

    if (!msg) return 0;

    if (msg->proxied == 1) {
        /* when rewrite a new absolute URL with forward or proxy, start proxy operation */
        if (msg->req_url_type > 0) {
            str_secpy(url, urlen, frameP(msg->docuri->uri), frameL(msg->docuri->uri));

            if (msg->fwdurl) kfree(msg->fwdurl);
            msg->fwdurllen = frameL(msg->docuri->uri);
            msg->fwdurl = str_dup(frameP(msg->docuri->uri), frameL(msg->docuri->uri));

            return 1;
        }
        msg->proxied = 0;
    }

    hl = (HTTPListen *)msg->hl;
    if (!hl) return 0;

    if (msg->req_url_type > 0 && hl->forwardproxy == 1) {
        /* current server is also served as proxy for the requesting client,
           the url in request line is absolute address. */

        str_secpy(url, urlen, frameP(msg->docuri->uri), frameL(msg->docuri->uri));

        if (msg->fwdurl) kfree(msg->fwdurl);
        msg->fwdurllen = frameL(msg->docuri->uri);
        msg->fwdurl = str_dup(frameP(msg->docuri->uri), frameL(msg->docuri->uri));

        return 1;
    }

    if (!msg->ploc) return 0;

    /* location / {
     *     path = [ '/', '^~' ];
     *     type  =  server;
     *     index =  [ index.html, index.htm ];
     *     root  =  /opt/httpdoc/;
     * }
     * location {
     *     path = [ '/cache/', '^~' ];
     *     type = proxy
     *     passurl = http://www.abcxxx.com/;
     * }
     * /cache/cdn/view?fid=3782837A0FA83B764E36A377B366CE98&stamp=327239843983
     * url -->
     * http://www.abcxxx.com/cdn/view?fid3782837A0FA83B764E36A377B366CE98&stamp=327239843983
     */

    ret = http_loc_passurl_get(msg, SERV_PROXY, url, urlen);
    if (ret > 0) {
        if (msg->fwdurl) kfree(msg->fwdurl);
        msg->fwdurllen = strlen(url);
        msg->fwdurl = str_dup(url, msg->fwdurllen);

        return 1;
    }

    return 0;
}

int http_proxy_srv_send_start (void * vproxymsg)
{
    HTTPMsg    * proxymsg = (HTTPMsg *)vproxymsg;
    HTTPMgmt   * mgmt = NULL;
    HTTPCon    * proxycon = NULL;
    HTTPSrv    * srv = NULL;

    if (!proxymsg) return -1;

    mgmt = (HTTPMgmt *)proxymsg->httpmgmt;
    if (!mgmt) return -2;

    srv = http_srv_open(mgmt, proxymsg->dstip, proxymsg->dstport, proxymsg->ssl_link, 100);

    proxycon = http_srv_connect(srv);
    if (proxycon) {
        /* upcoming R/W events of proxycon will delivered to current thread.
           for the Read/Write pipeline of 2 HTTP connections */
        iodev_workerid_set(proxycon->pdev, 1);

        http_con_msg_add(proxycon, proxymsg);

        http_proxy_srv_send(proxycon, proxymsg);

    } else {
        http_srv_msg_push(srv, proxymsg);
    }

    return 0;
}

void * http_proxy_srvmsg_open (void * vmsg, char * url, int urllen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMsg    * proxymsg = NULL;
    HeaderUnit * punit = NULL;
    CacheInfo  * cacinfo = NULL;
    int          i, num;
    char         buf[512];
    int          ret = 0;

    if (!msg) return NULL;

    /* firstly, check if the local storage has stored the request content.
       if it has, return it to client. */

    proxymsg = http_msg_fetch(msg->httpmgmt);
    if (!proxymsg) return NULL;

    proxymsg->SetMethod(proxymsg, msg->req_meth, -1);

    proxymsg->SetURL(proxymsg, url, urllen, 1);
    proxymsg->req_url_type = msg->req_url_type;

    sock_addr_get(proxymsg->req_host, proxymsg->req_hostlen, proxymsg->req_port, 0, 
                  proxymsg->dstip, &proxymsg->dstport, NULL);
    proxymsg->dstport = proxymsg->req_port; 

    /* check if the destinated server of forward proxy request is proxy itself */
    if (msg->req_url_type > 0) {
        if (http_listen_check_self(msg->httpmgmt,
                            proxymsg->req_host,
                            proxymsg->req_hostlen,
                            proxymsg->dstip,
                            proxymsg->dstport) > 0)
        {
            /* host is itself, needless to proxy */
            http_msg_close(proxymsg);
            return NULL;
        }
    }

    str_cpy(proxymsg->srcip, msg->srcip);
    proxymsg->srcport = msg->srcport;

    /* duplicate all the request headers into proxy msg */

    num = arr_num(msg->req_header_list);
    for (i = 0; i < num; i++) {
        punit = (HeaderUnit *)arr_value(msg->req_header_list, i);
        if (!punit || !punit->name || punit->namelen < 1) {
            continue;
        }

        http_header_append(proxymsg, 0, HUName(punit), punit->namelen,
                           HUValue(punit), punit->valuelen);
    }

    cacinfo = (CacheInfo *)msg->res_cache_info;
    if (cacinfo) {
        http_header_del(proxymsg, 0, "Range", -1);

        sprintf(buf, "bytes=%lld-", msg->cache_req_off);
        if (msg->cache_req_len > 0 && 
            msg->cache_req_off + msg->cache_req_len < cacinfo->body_length)
            sprintf(buf+strlen(buf), "%lld", msg->cache_req_off + msg->cache_req_len - 1);

        http_header_append(proxymsg, 0, "Range", -1, buf, strlen(buf));
    }
    proxymsg->cacheon = msg->cacheon;

    if (http_header_get(msg, 0, "Connection", -1) == NULL) {
        http_header_append(proxymsg, 0, "Connection", -1, "keep-alive", -1);
    }

    proxymsg->req_body_flag = msg->req_body_flag;
    proxymsg->req_body_length = msg->req_body_length;

    proxymsg->req_multipart = msg->req_multipart;
    proxymsg->req_conn_keepalive = msg->req_conn_keepalive;

    proxymsg->partial_flag = msg->partial_flag;
    for (i = 0; i < vstar_num(msg->partial_list); i++)
        vstar_push(proxymsg->partial_list, vstar_get(msg->partial_list, i));

    ret = http_req_encoding(proxymsg, 0);
    if (ret < 0) {
        http_msg_close(proxymsg);
        return NULL;
    }
 
    msg->proxied = 1;
    proxymsg->proxied = 2;
    proxymsg->proxymsg = msg;

    proxymsg->ploc = msg->ploc;
    proxymsg->phost = msg->phost;

    proxymsg->state = HTTP_MSG_SENDING;

    return proxymsg;
}

int http_proxy_srv_send (void * vsrvcon, void * vsrvmsg)
{
    HTTPCon   * srvcon = (HTTPCon *)vsrvcon;
    HTTPMsg   * srvmsg = (HTTPMsg *)vsrvmsg;
    HTTPMgmt  * mgmt = NULL;
    HTTPCon   * clicon = NULL;
    HTTPMsg   * climsg = NULL;
    HTTPChunk * chunk = NULL;
    int         num = 0;
    int         hdrlen = 0;
    int         bodylen = 0;
    int         rcvslen = 0;
    int         tosend = 0;
    int         sentnum = 0;
    int         cursentbody = 0;
    int         sentbody = 0;
    uint8       justsaveit = 0;
    uint8     * pbgn = NULL;
    int         ret = 0;

    struct iovec  iov[4];
    int           iovcnt = 0;

    if (!srvcon) return -1;
    if (!srvmsg) return -2;

    if (srvcon->snd_state < HTTP_CON_SEND_READY)
        return -100;

    climsg = srvmsg->proxymsg;
    if (!climsg) return -3;

    clicon = climsg->pcon;
    if (!clicon) return -4;

    mgmt = (HTTPMgmt *)climsg->httpmgmt;
    if (!mgmt) return -5;

    if (climsg->proxied != 1) return -10;
    if (srvmsg->proxied != 2) return -11;

    chunk = (HTTPChunk *)srvmsg->req_chunk;

    if (srvmsg != http_con_msg_first(srvcon)) {
        justsaveit = 1;
    }

    if (srvmsg->req_stream_sent < srvmsg->req_header_length) {
        iov[iovcnt].iov_base = frameP(srvmsg->req_stream) + srvmsg->req_stream_sent;
        hdrlen = iov[iovcnt].iov_len = srvmsg->req_header_length - srvmsg->req_stream_sent;
        tosend += hdrlen;
        iovcnt++;
    }

    /* already sent body-length calculating */
    if (srvmsg->req_stream_sent > srvmsg->req_header_length)
        sentbody = srvmsg->req_stream_sent - srvmsg->req_header_length;
    else 
        sentbody = 0;

    /* clicon received bytes from client and delivered to srvcon, but not all data
     * realtime-sent successfully for the reason of network fluctuation.
     * unsent bytes removed from clicon->rcvstream to srvmsg->req_body_stream. 
     * when write-ready of srvcon, this bytes will be sent firstly */
    pbgn = frameP(srvmsg->req_body_stream);
    num = frameL(srvmsg->req_body_stream);
 
    if (srvmsg->req_body_flag == BC_CONTENT_LENGTH &&
        srvmsg->req_body_length - sentbody > 0 && num > 0)
    {
        /* remaining body to be sent */
        bodylen = srvmsg->req_body_length - sentbody;
 
        bodylen = min(num, bodylen);
        if (bodylen > 0) {
            iov[iovcnt].iov_base = pbgn;
            iov[iovcnt].iov_len = bodylen;
            tosend += bodylen;
            iovcnt++;
        }
        sentbody += bodylen;
 
    } else if (srvmsg->req_body_flag == BC_TE && num > 0) {
        bodylen = num;
 
        iov[iovcnt].iov_base = pbgn;
        iov[iovcnt].iov_len = bodylen;
        tosend += bodylen;
        iovcnt++;
 
        sentbody += bodylen;
    }

    pbgn = frameP(clicon->rcvstream);
    num = frameL(clicon->rcvstream);

    if (srvmsg->req_body_flag == BC_CONTENT_LENGTH && 
        srvmsg->req_body_length - sentbody > 0 && num > 0)
    {
        /* remaining body to be sent */
        rcvslen = srvmsg->req_body_length - sentbody;
 
        rcvslen = min(num, rcvslen);
        if (rcvslen > 0) {
            iov[iovcnt].iov_base = pbgn;
            iov[iovcnt].iov_len = rcvslen;
            tosend += rcvslen;
            iovcnt++;
        }
        sentbody += rcvslen;
        climsg->req_stream_recv += rcvslen;

    } else if (srvmsg->req_body_flag == BC_TE && num > 0) {
        ret = http_chunk_add_bufptr(chunk, pbgn, num, &rcvslen);

        if (ret >= 0 && rcvslen > 0) {
            iov[iovcnt].iov_base = pbgn;
            iov[iovcnt].iov_len = rcvslen;
            tosend += bodylen;
            iovcnt++;
        }
        sentbody += rcvslen;
        climsg->req_stream_recv += rcvslen;
    }

    if (!justsaveit && iovcnt > 0) {
        ret = http_con_writev(srvcon, iov, iovcnt, &sentnum, NULL);
        if (ret < 0) {
            http_con_close(srvcon);

            climsg->proxied = 0;
            climsg->SetStatus(climsg, 503, NULL);
            climsg->Reply(climsg);
            return -200;
        }

        srvmsg->req_stream_sent += sentnum;

        time(&srvcon->stamp);
    }

    /* already sent body-length */
    if (srvmsg->req_stream_sent > srvmsg->req_header_length)
        sentbody = srvmsg->req_stream_sent - srvmsg->req_header_length;
    else 
        sentbody = 0;

    if (srvmsg->req_body_flag == BC_CONTENT_LENGTH) {

        if (sentnum > hdrlen) {
            cursentbody = sentnum - hdrlen;
            srvmsg->req_body_iolen += cursentbody;
 
            if (cursentbody >= bodylen) {
                frame_empty(srvmsg->req_body_stream);
 
                cursentbody -= bodylen;
                if (cursentbody >= rcvslen) {
                    /* all bytes in current clicon->rcvstream have been sent */
                    frame_del_first(clicon->rcvstream, rcvslen);
 
                    /* all bytes remaining in 2 buffers are sent out, 
                       check if full response is sent successfully */
                    if (srvmsg->req_body_iolen >= srvmsg->req_body_length)
                        goto succ;
 
                } else {
                    frame_del_first(clicon->rcvstream, cursentbody);
 
                    /* part of rcvstream sent, remaining bytes should be put into res_body_stream
                       for next sending */
                    frame_put_nlast(srvmsg->req_body_stream, frameP(clicon->rcvstream), rcvslen - cursentbody);
                    frame_del_first(clicon->rcvstream, rcvslen - cursentbody);
                }
 
            } else {
                frame_del_first(srvmsg->req_body_stream, cursentbody);
 
                /* put the not-sent bytes in srvcon->rcvstream into climsg->res_body_stream
                   for next sending */
                frame_put_nlast(srvmsg->req_body_stream, pbgn, rcvslen);
                frame_del_first(clicon->rcvstream, rcvslen);
            }
 
        } else {
            /* put the not-sent bytes in clicon->rcvstream into srvmsg->req_body_stream
               for next sending */
            frame_put_nlast(srvmsg->req_body_stream, pbgn, rcvslen);
            frame_del_first(clicon->rcvstream, rcvslen);
        }
 
        if (srvmsg->req_body_iolen + frameL(srvmsg->req_body_stream) < srvmsg->req_body_length) {
            clicon->rcv_state = HTTP_CON_WAITING_BODY;
        } else {
            clicon->rcv_state = HTTP_CON_READY;
        }
 
        if (srvmsg->req_stream_sent >= srvmsg->req_header_length + srvmsg->req_body_length)
            goto succ;

    } else if (srvmsg->req_body_flag == BC_TE) {

        if (sentnum > hdrlen) {
            if (!chunk)
                chunk = (HTTPChunk *)srvmsg->req_chunk;
 
            cursentbody = sentnum - hdrlen;
            srvmsg->req_chunk_iolen += cursentbody;
 
            if (cursentbody >= bodylen) {
                /* all bytes in req_stream_body sent succ */
                frame_empty(srvmsg->req_body_stream);
 
                cursentbody -= bodylen;
                if (cursentbody >= rcvslen) {
                    /* all data in clicon->rcvstream have been sent */
                    frame_del_first(clicon->rcvstream, rcvslen);
 
                    /* all data remaining in 2 buffers are sent out, 
                       check if full request is sent successfully */
                    if (chunk->gotall)
                        goto succ;
 
                } else {
                    /* only partial bytes for TE entity sent */
                    frame_del_first(clicon->rcvstream, cursentbody);
 
                    /* part of rcvstream sent, remaining bytes should be put into req_body_stream
                       for next sending */
                    frame_put_nlast(srvmsg->req_body_stream, frameP(clicon->rcvstream), rcvslen - cursentbody);
                    frame_del_first(clicon->rcvstream, rcvslen - cursentbody);
                }
 
            } else {
                /* only partial bytes in req_stream_body sent out */
                frame_del_first(srvmsg->req_body_stream, cursentbody);
 
                /* put the not-sent bytes in clicon->rcvstream into srvmsg->req_body_stream
                   for next sending */
                frame_put_nlast(srvmsg->req_body_stream, pbgn, rcvslen);
                frame_del_first(clicon->rcvstream, rcvslen);
            }
 
        } else {
            /* put the not-sent bytes in clicon->rcvstream into srvmsg->req_body_stream
               for next sending */
            frame_put_nlast(srvmsg->req_body_stream, pbgn, rcvslen);
            frame_del_first(clicon->rcvstream, rcvslen);
        }
 
        if (chunk->gotall) {
            clicon->rcv_state = HTTP_CON_READY;

            if (srvmsg->req_stream_sent >= srvmsg->req_header_length &&
                frameL(srvmsg->req_body_stream) == 0)
                goto succ;

        } else {
            clicon->rcv_state = HTTP_CON_WAITING_BODY;
        }

    } else {
        clicon->rcv_state = HTTP_CON_READY;

        if (srvmsg->req_stream_sent >= srvmsg->req_header_length)
            goto succ;
    }

    if (srvmsg->req_stream_sent < srvmsg->req_header_length || 
        frameL(srvmsg->req_body_stream) > 0)
    {
        iodev_add_notify(srvcon->pdev, RWF_WRITE);
    }
 
    /* read the blocked data in client-side kernel socket for
       server-side congestion control */
    if (ret > 0 && clicon->read_ignored > 0 &&
        frameL(srvmsg->req_body_stream) < mgmt->proxy_buffer_size)
    {
        iodev_add_notify(clicon->pdev, RWF_READ);
        http_cli_recv(clicon);
    }

    return 0;
 
succ:
    clicon->rcv_state = HTTP_CON_READY;

    srvmsg->reqsent = 1;
    srvcon->reqnum++;

    /* Server-request Message has been sent successfully */
    return 1;
}


int http_proxy_climsg_dup (void * vsrvmsg)
{
    HTTPMsg    * srvmsg = (HTTPMsg *)vsrvmsg;
    HTTPMgmt   * mgmt = NULL;
    HTTPMsg    * climsg = NULL;
    HeaderUnit * punit = NULL;
    int          i, num;
    int          ret = 0;

    if (!srvmsg) return -1;

    climsg = (HTTPMsg *)srvmsg->proxymsg;
    if (!climsg) return -2;

    mgmt = (HTTPMgmt *)srvmsg->httpmgmt;
    if (!mgmt) return -3;

    if (climsg->issued) return 0;

    /* set status code */
    climsg->SetStatus(climsg, srvmsg->res_status, NULL);

    /* duplicate all the response headers into client msg */
 
    num = arr_num(srvmsg->res_header_list);
    for (i = 0; i < num; i++) {
        punit = (HeaderUnit *)arr_value(srvmsg->res_header_list, i);
        if (!punit || !punit->name || punit->namelen < 1) {
            continue;
        }
 
        http_header_append(climsg, 1, HUName(punit), punit->namelen,
                           HUValue(punit), punit->valuelen);
    }

    climsg->res_body_flag = srvmsg->res_body_flag;
    climsg->res_body_length = srvmsg->res_body_length;

    climsg->res_conn_keepalive = srvmsg->res_conn_keepalive;

    climsg->res_store_file = srvmsg->res_store_file;

    srvmsg->cacheon = climsg->cacheon;

    if (http_header_get(climsg, 1, "Server", 6) == NULL)
        http_header_append(climsg, 1, "Server", 6, mgmt->useragent, str_len(mgmt->useragent));
    if (http_header_get(climsg, 1, "Date", 4) == NULL)
        http_header_append_date(climsg, 1, "Date", 4, time(NULL));
    if (http_header_get(climsg, 1, "Accept-Ranges", 13) == NULL)
        http_header_append(climsg, 1, "Accept-Ranges", 13, "bytes", 5);

    if (climsg->cacheon && climsg->res_cache_info) {
        http_cache_response_header(climsg, climsg->res_cache_info);
    }

    ret = http_res_encoding(climsg);
    if (ret < 0) {
        http_msg_close(climsg);
        return -100;
    }
 
    climsg->issued = 1;
    climsg->state = HTTP_MSG_REQUEST_HANDLED;

    return 0;
}


int http_proxy_cli_send (void * vclicon, void * vclimsg)
{
    HTTPCon    * clicon = (HTTPCon *)vclicon;
    HTTPMsg    * climsg = (HTTPMsg *)vclimsg;
    HTTPCon    * srvcon = NULL;
    HTTPMsg    * srvmsg = NULL;
    HTTPMgmt   * mgmt = NULL;
    int          num = 0;
    int          sentnum = 0;
    int          sentbody = 0;
    int          hdrlen = 0;
    int          bodylen = 0;
    int          rcvslen = 0;
    int          cursentbody = 0;
    int          tosend = 0;
    uint8        justsaveit = 0;
    uint8      * pbgn = NULL;
    int          ret = 0;
    HTTPChunk  * chunk = NULL;
 
    struct iovec  iov[4];
    int           iovcnt = 0;

    if (!clicon) return -1;
    if (!climsg) return -2;

    srvmsg = climsg->proxymsg;
    if (!srvmsg) return -3;

    srvcon = srvmsg->pcon;
    if (!srvcon) return -4;

    mgmt = (HTTPMgmt *)climsg->httpmgmt;
    if (!mgmt) return -5;

    if (climsg->proxied != 1) return -10;
    if (srvmsg->proxied != 2) return -11;

    chunk = (HTTPChunk *)climsg->res_chunk;

    /* allow the multiple HTTPMsg in HTTPCon queue and handled in pipeline */
    if (climsg != http_con_msg_first(clicon)) {
        justsaveit = 1;
    }

    if (climsg->res_stream_sent < climsg->res_header_length) {
        iov[iovcnt].iov_base = frameP(climsg->res_stream) + climsg->res_stream_sent;
        hdrlen = iov[iovcnt].iov_len = climsg->res_header_length - climsg->res_stream_sent;
        tosend += hdrlen;
        iovcnt++;
    }
 
    /* already sent body-length */
    if (climsg->res_stream_sent > climsg->res_header_length)
        sentbody = climsg->res_stream_sent - climsg->res_header_length;
    else 
        sentbody = 0;

    /* srvcon received bytes delivered but not all sent successfully, remaining 
     * bytes removed from srvcon->rcvstream to climsg->res_body_stream. 
     * when write-ready of clicon, this part sent firstly */
    pbgn = frameP(climsg->res_body_stream);
    num = frameL(climsg->res_body_stream);
 
    if (climsg->res_body_flag == BC_CONTENT_LENGTH &&
        climsg->res_body_length - sentbody > 0 && num > 0)
    {
        /* remaining body to be sent */
        bodylen = climsg->res_body_length - sentbody;
 
        bodylen = min(num, bodylen);
        if (bodylen > 0) {
            iov[iovcnt].iov_base = pbgn;
            iov[iovcnt].iov_len = bodylen;
            tosend += bodylen;
            iovcnt++;
        }
        sentbody += bodylen;
 
    } else if (climsg->res_body_flag == BC_TE && num > 0) {
        bodylen = num;

        iov[iovcnt].iov_base = pbgn;
        iov[iovcnt].iov_len = bodylen;
        tosend += bodylen;
        iovcnt++;

        sentbody += bodylen;
    }

    pbgn = frameP(srvcon->rcvstream);
    num = frameL(srvcon->rcvstream);
 
    if (climsg->res_body_flag == BC_CONTENT_LENGTH &&
        climsg->res_body_length - sentbody > 0 && num > 0)
    {
        /* remaining body to be sent */
        rcvslen = climsg->res_body_length - sentbody;
 
        rcvslen = min(num, rcvslen);
        if (rcvslen > 0) {
            iov[iovcnt].iov_base = pbgn;
            iov[iovcnt].iov_len = rcvslen;
            tosend += rcvslen;
            iovcnt++;
        }
        sentbody += rcvslen;
        srvmsg->res_stream_recv += rcvslen;
 
    } else if (climsg->res_body_flag == BC_TE && num > 0) {
        if (!chunk) 
            chunk = (HTTPChunk *)climsg->res_chunk;

        /* add num bytes into res_chunk. if tcp-sent bytes is less than num,
         * part bytes has been deleted after tcp-sent. when re-entering here,
         * it is possible that part of num bytes will be re-added again. it will fail!
         */
        ret = http_chunk_add_bufptr(chunk, pbgn, num, &rcvslen);
        if (ret >= 0 && rcvslen > 0) {
            iov[iovcnt].iov_base = pbgn;
            iov[iovcnt].iov_len = rcvslen;
            tosend += rcvslen;
            iovcnt++;
        }
        sentbody += rcvslen;
        srvmsg->res_stream_recv += rcvslen;
    }
 
    if (!justsaveit && iovcnt > 0) {
        ret = http_con_writev(clicon, iov, iovcnt, &sentnum, NULL);
        if (ret < 0) {
            http_con_close(clicon);
            http_con_close(srvcon);
            return -200;
        }
 
        climsg->res_stream_sent += sentnum;

        time(&clicon->stamp);
        time(&srvcon->stamp);
        if (srvcon->srv)
            time(&((HTTPSrv *)(srvcon->srv))->stamp);

    }
 
    /* already sent body-length */
    if (climsg->res_stream_sent > climsg->res_header_length)
        sentbody = climsg->res_stream_sent - climsg->res_header_length;
    else 
        sentbody = 0;

    if (climsg->res_body_flag == BC_CONTENT_LENGTH) {

        if (sentnum > hdrlen) {
            cursentbody = sentnum - hdrlen;
            climsg->res_body_iolen += cursentbody;

            if (cursentbody >= bodylen) {
                if (bodylen > 0)
                    frame_empty(climsg->res_body_stream);

                cursentbody -= bodylen;
                if (cursentbody >= rcvslen) {
                    /* all bytes in current srvcon->rcvstream have been sent */
                    frame_del_first(srvcon->rcvstream, rcvslen);

                    /* all bytes remaining in 2 buffers are sent out, 
                       check if full response is sent successfully */
                    if (climsg->res_body_iolen >= climsg->res_body_length)
                        goto succ;

                } else {
                    frame_del_first(srvcon->rcvstream, cursentbody);

                    /* part of rcvstream sent, remaining bytes should be put into res_body_stream
                       for next sending */
                    frame_put_nlast(climsg->res_body_stream, frameP(srvcon->rcvstream), rcvslen - cursentbody);
                    frame_del_first(srvcon->rcvstream, rcvslen - cursentbody);
                }

            } else {
                frame_del_first(climsg->res_body_stream, cursentbody);

                /* put the not-sent bytes in srvcon->rcvstream into climsg->res_body_stream
                   for next sending */
                frame_put_nlast(climsg->res_body_stream, pbgn, rcvslen);
                frame_del_first(srvcon->rcvstream, rcvslen);
            }

        } else {
            /* put the not-sent bytes in srvcon->rcvstream into climsg->res_body_stream
               for next sending */
            frame_put_nlast(climsg->res_body_stream, pbgn, rcvslen);
            frame_del_first(srvcon->rcvstream, rcvslen);
        }
 
        if (climsg->res_body_iolen + frameL(climsg->res_body_stream) < climsg->res_body_length) {
            srvcon->rcv_state = HTTP_CON_WAITING_BODY;
        } else {
            srvcon->rcv_state = HTTP_CON_READY;
        }
 
        if (climsg->res_stream_sent >= climsg->res_header_length + climsg->res_body_length)
            goto succ;

    } else if (climsg->res_body_flag == BC_TE) {

        if (sentnum > hdrlen) {
            if (!chunk)
                chunk = (HTTPChunk *)climsg->res_chunk;

            cursentbody = sentnum - hdrlen;
            climsg->res_body_iolen += cursentbody;

            if (cursentbody >= bodylen) {
                /* all bytes in res_stream_body sent succ */
                frame_empty(climsg->res_body_stream);
 
                cursentbody -= bodylen;
                if (cursentbody >= rcvslen) {
                    /* all bytes in current srvcon->rcvstream have been sent */
                    frame_del_first(srvcon->rcvstream, rcvslen);
 
                    /* all bytes remaining in 2 buffers are sent out, 
                       check if full response is sent successfully */
                    if (chunk->gotall)
                        goto succ;

                } else {
                    /* only partial bytes for TE entity sent */
                    frame_del_first(srvcon->rcvstream, cursentbody);
 
                    /* part of rcvstream sent, remaining bytes should be put into res_body_stream
                       for next sending */
                    frame_put_nlast(climsg->res_body_stream, frameP(srvcon->rcvstream), rcvslen - cursentbody);
                    frame_del_first(srvcon->rcvstream, rcvslen - cursentbody);
                }

            } else {
                /* only partial bytes in res_stream_body sent out */
                frame_del_first(climsg->res_body_stream, cursentbody);
 
                /* put the not-sent bytes in srvcon->rcvstream into climsg->res_body_stream
                   for next sending */
                frame_put_nlast(climsg->res_body_stream, pbgn, rcvslen);
                frame_del_first(srvcon->rcvstream, rcvslen);
            }

        } else {
            /* put the not-sent bytes in srvcon->rcvstream into climsg->res_body_stream
               for next sending */
            frame_put_nlast(climsg->res_body_stream, pbgn, rcvslen);
            frame_del_first(srvcon->rcvstream, rcvslen);
        }
 
        if (chunk->gotall) {
            srvcon->rcv_state = HTTP_CON_READY;

            if (climsg->res_stream_sent >= climsg->res_header_length &&
                frameL(climsg->res_body_stream) == 0)
                goto succ;

        } else {
            srvcon->rcv_state = HTTP_CON_WAITING_BODY;
        }

    }  else {
        srvcon->rcv_state = HTTP_CON_READY;

        if (climsg->res_stream_sent >= climsg->res_header_length)
            goto succ;
    }
 
    if (climsg->res_stream_sent < climsg->res_header_length || 
        frameL(climsg->res_body_stream) > 0)
    {
        iodev_add_notify(clicon->pdev, RWF_WRITE);
    }

    /* read the blocked data in server-side kernel socket for 
       client-side congestion control */
    if (ret > 0 && srvcon->read_ignored > 0 && 
        frameL(climsg->res_body_stream) < mgmt->proxy_buffer_size)
    {
        iodev_add_notify(srvcon->pdev, RWF_READ);
        http_srv_recv(srvcon);
    }

    return 0;

succ:
    srvcon->rcv_state = HTTP_CON_READY;

    /* Client Message has been sent successfully */
    http_con_msg_del(clicon, climsg);
    clicon->msg = NULL;
    http_msg_close(climsg);

    http_con_msg_del(srvcon, srvmsg);
    srvcon->msg = NULL;
    http_msg_close(srvmsg);

    clicon->transbgn = time(NULL);

    return 1;
}

int http_proxy_srvbody_del (void * vsrvcon, void * vsrvmsg)
{
    HTTPCon    * srvcon = (HTTPCon *)vsrvcon;
    HTTPMsg    * srvmsg = (HTTPMsg *)vsrvmsg;
    int          num = 0;
    int          bodylen = 0;
    uint8      * pbgn = NULL;
    int          ret = 0;
    HTTPChunk  * chunk = NULL;

    if (!srvcon) return -1;
    if (!srvmsg) return -2;

    if (srvmsg->proxied != 2) return -11;

    if (srvmsg != http_con_msg_first(srvcon))
        return -100;

    pbgn = frameP(srvcon->rcvstream);
    num = frameL(srvcon->rcvstream);
 
    if (srvmsg->res_body_flag == BC_CONTENT_LENGTH) {
        bodylen = srvmsg->res_body_length - srvmsg->res_stream_sent;

        if (bodylen <= num) {
            frame_del_first(srvcon->rcvstream, bodylen);

            srvmsg->res_stream_sent += bodylen;
            return 1; //body removed completely

        } else {
            frame_del_first(srvcon->rcvstream, num);

            srvmsg->res_stream_sent += num;

            return 0; //body is not enough
        }
 
    } else if (srvmsg->res_body_flag == BC_TE) {
        chunk = (HTTPChunk *)srvmsg->res_chunk;
 
        ret = http_chunk_add_bufptr(srvmsg->res_chunk, pbgn, num, &bodylen);
        if (ret >= 0 && bodylen > 0) {
            frame_del_first(srvcon->rcvstream, bodylen);

            srvmsg->res_stream_sent += bodylen;
        }

        if (chunk->gotall) {
            return 1;
        } else {
            return 0;
        }
    }

    return 1;
}

void * http_proxy_connect_tunnel (void * vcon, void * vmsg)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HTTPCon    * tunnelcon = NULL;
    char         dstip[41];
    int          dstport = 0;

    if (!pcon || !msg) return NULL;

    if (pcon->httptunnel && pcon->tunnelcon)
        return pcon->tunnelcon;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return NULL;

    /* set the tunnel flag for client-side HTTPCon */
    pcon->httptunnel = 1;
    pcon->tunnelcon = NULL;

    sock_addr_get(msg->req_host, msg->req_hostlen, msg->req_port, 0,
                  dstip, &dstport, NULL);
    dstport = msg->req_port;
 
    /* check if the destinated server of http connect request is itself */
    if (http_listen_check_self(msg->httpmgmt, 
                      msg->req_host,
                      msg->req_hostlen,
                      dstip, dstport) > 0)
    {
        pcon->tunnelself = 1;
        return NULL;
    }

    tunnelcon = http_con_open(NULL, dstip, dstport, 0);
    if (tunnelcon) {
        iodev_workerid_set(tunnelcon->pdev, 1);

        tunnelcon->httptunnel = 2;

        tunnelcon->tunnelcon = pcon;
        tunnelcon->tunnelconid = pcon->conid;

        pcon->tunnelcon = tunnelcon;
        pcon->tunnelconid = tunnelcon->conid;

        return tunnelcon;
    }

    return NULL;
}

int http_tunnel_srv_send (void * vclicon, void * vsrvcon)
{
    HTTPCon     * clicon = (HTTPCon *)vclicon;
    HTTPCon     * srvcon = (HTTPCon *)vsrvcon;
    int           sentnum = 0;
    int           ret = 0;
    struct iovec  iov[4];
    int           iovcnt = 0;

    if (!clicon) return -1;
    if (!srvcon) return -2;

    if (clicon->httptunnel != 1 && clicon->tunnelcon != srvcon)
        return -10;

    if (srvcon->httptunnel != 2 && srvcon->tunnelcon != clicon)
        return -11;

    if (frameL(clicon->rcvstream) <= 0)
        return 0;

    if (srvcon->snd_state < HTTP_CON_SEND_READY) {
        iodev_add_notify(srvcon->pdev, RWF_WRITE);
        return 0;
    }

    iov[iovcnt].iov_base = frameP(clicon->rcvstream);
    iov[iovcnt].iov_len = frameL(clicon->rcvstream);
    iovcnt++;

    ret = http_con_writev(srvcon, iov, iovcnt, &sentnum, NULL);
    if (ret < 0) {
        return -200;
    }

    time(&srvcon->stamp);

    frame_del_first(clicon->rcvstream, sentnum);

    if (frameL(clicon->rcvstream) > 0) {
        iodev_add_notify(srvcon->pdev, RWF_WRITE);
    }

    return sentnum;
}

int http_tunnel_cli_send (void * vsrvcon, void * vclicon)
{
    HTTPCon     * srvcon = (HTTPCon *)vsrvcon;
    HTTPCon     * clicon = (HTTPCon *)vclicon;
    HTTPMgmt    * mgmt = NULL;
    int           sentnum = 0;
    int           ret = 0;
    struct iovec  iov[4];
    int           iovcnt = 0;

    if (!srvcon) return -1;
    if (!clicon) return -2;

    mgmt = (HTTPMgmt *)srvcon->mgmt;
    if (!mgmt) return -3;

    if (srvcon->httptunnel != 2 && srvcon->tunnelcon != clicon)
        return -10;

    if (clicon->httptunnel != 1 && clicon->tunnelcon != srvcon)
        return -11;

    if (frameL(srvcon->rcvstream) <= 0)
        return 0;

    if (clicon->snd_state < HTTP_CON_SEND_READY) {
        iodev_add_notify(clicon->pdev, RWF_WRITE);
        return 0;
    }

    iov[iovcnt].iov_base = frameP(srvcon->rcvstream);
    iov[iovcnt].iov_len = frameL(srvcon->rcvstream);
    iovcnt++;

    ret = http_con_writev(clicon, iov, iovcnt, &sentnum, NULL);
    if (ret < 0) {
        return -200;
    }

    time(&clicon->stamp);
    time(&srvcon->stamp);

    frame_del_first(srvcon->rcvstream, sentnum);

    if (frameL(srvcon->rcvstream) > 0) {
        iodev_add_notify(clicon->pdev, RWF_WRITE);
    }

    /* read the blocked data in server-side kernel socket for 
       client-side congestion control */
    if (ret > 0 && srvcon->read_ignored > 0 && 
        frameL(srvcon->rcvstream) < mgmt->proxy_buffer_size)
    {
        iodev_add_notify(srvcon->pdev, RWF_READ);
        http_srv_recv(srvcon);
    }

    return sentnum;
}


int http_proxy_cli_cache_send (void * vclicon, void * vclimsg)
{
    HTTPCon     * clicon = (HTTPCon *)vclicon;
    HTTPMsg     * climsg = (HTTPMsg *)vclimsg;
    CacheInfo   * cacinfo = NULL;
    int64         reqpos = 0;
    int64         bodysize = 0;
    int64         restlen = 0;

    int64         datapos = 0;
    int64         datalen = 0;
    int64         ilen = 0;
    int           ret = 0;
    static int    CHUNKLEN = 1024*1024;

    if (!clicon) return -1;
    if (!climsg) return -2;
 
    cacinfo = (CacheInfo *)climsg->res_cache_info;
    if (!cacinfo) {
        return http_proxy_cli_send(clicon, climsg);
    }

    /* allow the multiple HTTPMsg in HTTPCon queue and handled in pipeline */
    if (climsg != http_con_msg_first(clicon)) {
        return -100;
    }

    if (climsg->issued <= 0) {
        return 0;
    }

    bodysize = chunk_size(climsg->res_body_chunk, 0);
    bodysize -= climsg->res_header_length;
    
    reqpos = climsg->cache_req_start + bodysize;

    if (climsg->res_body_flag == BC_CONTENT_LENGTH) {
        /* calculate length of remaining data to send */
        restlen = climsg->res_body_length - bodysize;
        if (restlen <= 0) goto sendnow;

        ret = frag_pack_contain(cacinfo->frag, reqpos, -1, &datapos, &datalen, NULL, NULL);
        if (ret >= 2) {
            /* the contiguous data length is greater than remaining length */
            if (datalen > restlen) datalen = restlen;

            ret = chunk_add_file(climsg->res_body_chunk, cacinfo->cache_tmp, datapos, datalen, 1);

            if (chunk_size(climsg->res_body_chunk, 0) >= climsg->res_body_length + climsg->res_header_length) {
                chunk_set_end(climsg->res_body_chunk);
            }

        } else {
            /* no data existing in the position of the cache, need to request to origin server */
            if (climsg->proxymsg == NULL &&
                frag_pack_complete(cacinfo->frag) <= 0 && 
                http_request_in_cache(climsg) <= 0)
            {
                http_proxy_srv_cache_send(climsg);
            }
        }

    } else if (climsg->res_body_flag == BC_TE) {
        ret = frag_pack_contain(cacinfo->frag, reqpos, -1, &datapos, &datalen, NULL, NULL);
        if (ret >= 2) {
            for (ilen = 0; datalen > 0; ) {
                if (datalen > CHUNKLEN) {
                    ret = chunk_add_file(climsg->res_body_chunk, cacinfo->cache_tmp, datapos + ilen, CHUNKLEN, 0);
                    ilen += CHUNKLEN;
                    datalen -= CHUNKLEN;
                } else {
                    ret = chunk_add_file(climsg->res_body_chunk, cacinfo->cache_tmp, datapos + ilen, datalen, 0);
                    ilen += datalen;
                    datalen = 0;
                }
                if (chunk_size(climsg->res_body_chunk, 1) > 50*1024*1024) break;
            }

            if (datalen == 0 && http_chunk_gotall(climsg->res_chunk)) {
                /* available data from position of Raw cache file are all added into chunk,
                   all response body in proxy request to origin are received. */
                chunk_set_end(climsg->res_body_chunk);
            }

        } else {
            /* no data existing in the position of the cache, need to request to origin server */
            if (climsg->proxymsg == NULL &&
                frag_pack_complete(cacinfo->frag) <= 0 && 
                http_request_in_cache(climsg) <= 0)
            {
                http_proxy_srv_cache_send(climsg);
            }
        }
    }

sendnow:
    bodysize = chunk_size(climsg->res_body_chunk, climsg->res_body_flag == BC_TE ? 1 : 0);

    if (climsg->res_stream_sent < bodysize)
        http_cli_send(clicon);

    return 1;
}

int http_proxy_srv_cache_store (void * vsrvcon, void * vsrvmsg)
{
    HTTPCon    * srvcon = (HTTPCon *)vsrvcon;
    HTTPMsg    * srvmsg = (HTTPMsg *)vsrvmsg;
    HTTPCon    * clicon = NULL;
    HTTPMsg    * climsg = NULL;
    HTTPMgmt   * mgmt = NULL;
    CacheInfo  * cacinfo = NULL;
    char       * pbody = NULL;
    int          bodylen = 0;
    int          wlen = 0;
    int64        filepos = 0;
    int64        restlen = 0;
    int          ret, rmlen = 0;
    uint8        justsaveit = 0;

    if (!srvcon) return -1;
    if (!srvmsg) return -2;
 
    climsg = srvmsg->proxymsg;
    if (!climsg) return -3;
 
    clicon = climsg->pcon;
    if (!clicon) return -4;
 
    mgmt = (HTTPMgmt *)climsg->httpmgmt;
    if (!mgmt) return -5;
 
    if (climsg->proxied != 1) return -10;
    if (srvmsg->proxied != 2) return -11;
 
    cacinfo = (CacheInfo *)climsg->res_cache_info;
    if (!cacinfo) {
        return http_proxy_cli_send(clicon, climsg);
    }
    
    /* allow the multiple HTTPMsg in HTTPCon queue and handled in pipeline */
    if (climsg != http_con_msg_first(clicon)) {
        justsaveit = 1;
    }
 
    pbody = frameP(srvcon->rcvstream);
    bodylen = frameL(srvcon->rcvstream);
 
    if (climsg->res_body_flag == BC_CONTENT_LENGTH) {
        restlen = climsg->res_body_length - climsg->res_body_iolen;
        if (restlen <= 0) {
            /* got all body content of the current request, but possibly not all the file content */
            chunk_set_end(climsg->res_body_chunk);

            climsg->proxymsg = NULL;

            srvcon->rcv_state = HTTP_CON_READY;

            http_con_msg_del(srvcon, srvmsg);
            srvcon->msg = NULL;
            http_msg_close(srvmsg);

            goto clisend;
        }

        srvcon->rcv_state = HTTP_CON_WAITING_BODY;

        if (bodylen <= 0) goto clisend;

        if (restlen <= bodylen)
            bodylen = restlen;

        filepos = lseek(native_file_fd(climsg->res_file_handle), 0, SEEK_CUR);
        wlen = native_file_write(climsg->res_file_handle, pbody, bodylen);
        if (wlen > 0) {
            frame_del_first(srvcon->rcvstream, wlen);
            climsg->res_body_iolen += wlen;

            cache_info_add_frag(cacinfo, filepos, wlen, 0);
        }

        if (climsg->res_body_iolen >= climsg->res_body_length) {
            /* got all body content of the current request, but possibly not all the file content */
            climsg->proxymsg = NULL;

            srvcon->rcv_state = HTTP_CON_READY;

            http_con_msg_del(srvcon, srvmsg);
            srvcon->msg = NULL;
            http_msg_close(srvmsg);
        }

    } else if (climsg->res_body_flag == BC_TE) {
        if (http_chunk_gotall(climsg->res_chunk)) {
            /* got all body content of the current request, but possibly not all the file content */
            chunk_set_end(climsg->res_body_chunk);

            climsg->proxymsg = NULL;

            srvcon->rcv_state = HTTP_CON_READY;

            http_con_msg_del(srvcon, srvmsg);
            srvcon->msg = NULL;
            http_msg_close(srvmsg);

            goto clisend;
        }

        srvcon->rcv_state = HTTP_CON_WAITING_BODY;
        if (bodylen <= 0) goto clisend;

        ret = http_chunk_add_bufptr(climsg->res_chunk, pbody, bodylen, &rmlen);
        if (ret < 0) return -30;

        if (rmlen <= 0) goto clisend;

        filepos = lseek(native_file_fd(climsg->res_file_handle), 0, SEEK_CUR);

        /* parsed body content without containing hex-length\r\n will be writen into cache file */
        wlen = restlen = chunk_rest_size(http_chunk_obj(climsg->res_chunk), 0);
 
        climsg->res_body_iolen += restlen;
        climsg->res_body_length += restlen;

        chunk_readto_file(http_chunk_obj(climsg->res_chunk),
                          native_file_fd(climsg->res_file_handle), 0, -1, 0);

        chunk_remove(http_chunk_obj(climsg->res_chunk), climsg->res_body_length, 0);
 
        frame_del_first(srvcon->rcvstream, rmlen);
 
        if (http_chunk_gotall(climsg->res_chunk)) {
            /* got all body content of the current request, but possibly not all the file content */
            climsg->proxymsg = NULL;

            /* add the frag-segment into file, check if all the contents are gotton */
            cache_info_add_frag(cacinfo, filepos, restlen, 1);

            srvcon->rcv_state = HTTP_CON_READY;

            http_con_msg_del(srvcon, srvmsg);
            srvcon->msg = NULL;
            http_msg_close(srvmsg);

            goto clisend;

        } else {
            cache_info_add_frag(cacinfo, filepos, restlen, 0);
        }
    }
 
clisend:

    if (!justsaveit) {
        http_proxy_cli_cache_send(clicon, climsg);
    }

    return 0;
}

void * http_proxy_srv_cache_send (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMsg    * srvmsg = NULL;
    HeaderUnit * punit = NULL;
    CacheInfo  * cacinfo = NULL;
    HTTPCon    * srvcon = NULL;
    HTTPSrv    * srv = NULL;
    int          i, num;
    char         buf[512];
    int          ret = 0;
 
    if (!msg) return NULL;
 
    srvmsg = http_msg_fetch(msg->httpmgmt);
    if (!srvmsg) return NULL;
 
    srvmsg->SetMethod(srvmsg, "GET", 3);
 
    srvmsg->SetURL(srvmsg, msg->fwdurl, msg->fwdurllen, 1);
    srvmsg->req_url_type = msg->req_url_type;
 
    sock_addr_get(srvmsg->req_host, srvmsg->req_hostlen, srvmsg->req_port, 0,
                  srvmsg->dstip, &srvmsg->dstport, NULL);
    srvmsg->dstport = srvmsg->req_port;
 
    str_cpy(srvmsg->srcip, msg->srcip);
    srvmsg->srcport = msg->srcport;
 
    /* duplicate all the request headers into proxy msg */
 
    num = arr_num(msg->req_header_list);
    for (i = 0; i < num; i++) {
        punit = (HeaderUnit *)arr_value(msg->req_header_list, i);
        if (!punit || !punit->name || punit->namelen < 1) {
            continue;
        }
 
        http_header_append(srvmsg, 0, HUName(punit), punit->namelen,
                           HUValue(punit), punit->valuelen);
    }
 
    cacinfo = (CacheInfo *)msg->res_cache_info;
    if (cacinfo) {
        http_header_del(srvmsg, 0, "Range", -1);
 
        sprintf(buf, "bytes=%lld-", msg->cache_req_off);
        if (msg->cache_req_len > 0 &&
            msg->cache_req_off + msg->cache_req_len < cacinfo->body_length)
            sprintf(buf+strlen(buf), "%lld", msg->cache_req_off + msg->cache_req_len - 1);
 
        http_header_append(srvmsg, 0, "Range", -1, buf, strlen(buf));
    }
 
    if (http_header_get(msg, 0, "Connection", -1) == NULL) {
        http_header_append(srvmsg, 0, "Connection", -1, "keep-alive", -1);
    }
 
    http_header_del(srvmsg, 0, "Content-Length", -1);
    http_header_del(srvmsg, 0, "Content-Type", -1);
    http_header_del(srvmsg, 0, "Transfer-Encoding", 17);

    srvmsg->req_body_flag = BC_NONE;
    srvmsg->req_body_length = 0;
 
    srvmsg->req_multipart = 0;
    srvmsg->req_conn_keepalive = 1;
 
    ret = http_req_encoding(srvmsg, 0);
    if (ret < 0) {
        http_msg_close(srvmsg);
        return NULL;
    }
 
    srvmsg->proxied = 2;
    srvmsg->proxymsg = msg;
 
    srvmsg->ploc = msg->ploc;
    srvmsg->phost = msg->phost;
 
    srvmsg->state = HTTP_MSG_SENDING;
 
    /* now bind the HTTPMsg to one HTTPCon allocated by HTTPSrv, and start sending it */
    srv = http_srv_open(msg->httpmgmt, srvmsg->dstip, srvmsg->dstport, srvmsg->ssl_link, 15);
    if (!srv) {
        http_msg_close(srvmsg);
        return NULL;
    }
 
    msg->proxymsg = srvmsg;

    srvcon = http_srv_connect(srv);
    if (!srvcon) {
        http_srv_msg_push(srv, srvmsg);
    } else {
        http_con_msg_add(srvcon, srvmsg);
 
        http_srv_send(srvcon);
    }

    return srvmsg;
}
 
