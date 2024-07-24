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
#include "http_con.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_cli_io.h"
#include "http_srv_io.h"
#include "http_resloc.h"
#include "http_request.h"
#include "http_response.h"
#include "http_srv.h"
#include "http_chunk.h"
#include "http_ssl.h"
#include "http_cache.h"
#include "http_cc.h"
#include "http_fcgi_io.h"
#include "http_handle.h"
#include "http_proxy.h"

extern char * g_http_version;
extern HTTPMgmt * gp_httpmgmt;


int http_proxy_handle (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    int       ret = 0;

    if (!msg) return -1;

    ret = http_proxy_examine(msg);
    if (ret < 0) return ret;

    return http_proxy_launch(msg);
}


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

            if (msg->fwdurl) k_mem_free(msg->fwdurl, msg->alloctype, msg->kmemblk);
            msg->fwdurllen = frameL(msg->docuri->uri);
            msg->fwdurl = k_mem_str_dup(frameP(msg->docuri->uri), frameL(msg->docuri->uri),
                                        msg->alloctype, msg->kmemblk);

            return 1;
        }
        msg->proxied = 0;
    }

    hl = (HTTPListen *)msg->hl;
    if (!hl) return 0;

    if (msg->req_url_type > 0 && !msg->ploc && hl->forwardproxy == 1) {
        /* Web server is also served as proxy for the requesting client,
           the url in request line is absolute address and have no Loc instance. */

        str_secpy(url, urlen, frameP(msg->uri->uri), frameL(msg->uri->uri));

        if (msg->fwdurl) k_mem_free(msg->fwdurl, msg->alloctype, msg->kmemblk);
        msg->fwdurllen = frameL(msg->uri->uri);
        msg->fwdurl = k_mem_str_dup(frameP(msg->uri->uri), frameL(msg->uri->uri),
                                    msg->alloctype, msg->kmemblk);

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
        if (msg->fwdurl) k_mem_free(msg->fwdurl, msg->alloctype, msg->kmemblk);
        msg->fwdurllen = ret; //strlen(url);
        msg->fwdurl = k_mem_str_dup(url, msg->fwdurllen,
                                    msg->alloctype, msg->kmemblk);

        return 1;
    }

    return 0;
}

int http_proxy_examine (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    char      url[4096];

    if (!msg) return -1;

    if (msg->req_methind == HTTP_METHOD_CONNECT)
        return -50;

    /* check the request if it's to be proxyed to other origin server */
    if (http_proxy_check(msg, url, sizeof(url)-1) <= 0)
        return -100;

    if (http_proxy_cache_open(msg) >= 3) {
        /* cache file exists in local directory */
        return -200;
    }

    msg->proxied = 1;
 
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

    proxymsg->workerid = msg->workerid;

    proxymsg->SetMethod(proxymsg, msg->req_meth, -1);

    proxymsg->SetURL(proxymsg, url, urllen, 1);
    proxymsg->req_url_type = msg->req_url_type;

    str_cpy(proxymsg->req_ver, msg->req_ver);
    proxymsg->req_ver_major = msg->req_ver_major;
    proxymsg->req_ver_minor = msg->req_ver_minor;

    proxymsg->dstport = proxymsg->req_port;

    str_cpy(proxymsg->srcip, msg->srcip);
    proxymsg->srcport = msg->srcport;

    /* duplicate all the request headers into proxy msg */

    num = arr_num(msg->req_header_list);
    for (i = 0; i < num; i++) {
        punit = (HeaderUnit *)arr_value(msg->req_header_list, i);
        if (!punit || !punit->name || punit->namelen < 1) {
            continue;
        }

        if (strncasecmp(HUName(punit), "User-Agent", 10) == 0) {
            str_secpy(buf, sizeof(buf)-21, HUValue(punit), punit->valuelen);
            snprintf(buf + strlen(buf), sizeof(buf)-1-strlen(buf), " via eJet/%s", g_http_version);
            http_header_append(proxymsg, 0, HUName(punit), punit->namelen, buf, strlen(buf));

        } else {
            http_header_append(proxymsg, 0, HUName(punit), punit->namelen,
                               HUValue(punit), punit->valuelen);
        }
    }

    cacinfo = (CacheInfo *)msg->res_cache_info;
    if (cacinfo) {
        http_header_del(proxymsg, 0, "Range", -1);

#if defined(_WIN32) || defined(_WIN64)
        sprintf(buf, "bytes=%I64d-", msg->cache_req_off);
#else
        sprintf(buf, "bytes=%lld-", msg->cache_req_off);
#endif
        if (msg->cache_req_len > 0 && 
            msg->cache_req_off + msg->cache_req_len < cacinfo->body_length)
#if defined(_WIN32) || defined(_WIN64)
            sprintf(buf+strlen(buf), "%I64d", msg->cache_req_off + msg->cache_req_len - 1);
#else
            sprintf(buf+strlen(buf), "%lld", msg->cache_req_off + msg->cache_req_len - 1);
#endif

        http_header_append(proxymsg, 0, "Range", -1, buf, strlen(buf));
    }
    proxymsg->cacheon = msg->cacheon;

    if (http_header_get(msg, 0, "Connection", -1) == NULL) {
        http_header_append(proxymsg, 0, "Connection", -1, "keep-alive", -1);
    }

    proxymsg->req_gotall_body = msg->req_gotall_body;

    /* Using req_body_chunk to store body with the format of Content-Length or
       Transfer-Encoding-chunked. There is no parsing for the chunked body */
    proxymsg->req_body_flag = msg->req_body_flag;
    proxymsg->req_body_length = msg->req_body_length;
    proxymsg->req_body_iolen = msg->req_body_iolen;

    proxymsg->req_stream_recv = msg->req_stream_recv;

    proxymsg->req_multipart = msg->req_multipart;
    proxymsg->req_conn_keepalive = msg->req_conn_keepalive;

    proxymsg->partial_flag = msg->partial_flag;
    for (i = 0; i < vstar_num(msg->partial_list); i++)
        vstar_push(proxymsg->partial_list, vstar_get(msg->partial_list, i));

    /* copy client-side request body to proxymsg */
    if (msg->req_body_length > 0 && msg->req_body_length == chunk_size(msg->req_body_chunk, 0)) {
        chunk_copy(proxymsg->req_body_chunk, msg->req_body_chunk, NULL, NULL);
    } else if (msg->req_file_handle) {
        chunk_add_filefd(proxymsg->req_body_chunk,
                         native_file_fd(msg->req_file_handle),
                         0, -1);
    } else {
        chunk_add_bufptr(proxymsg->req_body_chunk,
                         frameP(msg->req_body_stream),
                         frameL(msg->req_body_stream), NULL, NULL);
    }

    ret = http_req_build(proxymsg, 1);
    if (ret < 0) {
        http_msg_close(proxymsg);
        return NULL;
    }
 
    if (msg->req_gotall_body) {
        chunk_set_end(proxymsg->req_body_chunk);
    }

    msg->proxied = 1;
    msg->proxymsg = proxymsg;
    msg->proxymsgid = proxymsg->msgid;

    proxymsg->proxied = 2;
    proxymsg->proxymsg = msg;
    proxymsg->proxymsgid = msg->msgid;

    proxymsg->state = HTTP_MSG_SENDING;

    return proxymsg;
}

int http_proxy_launch (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    HTTPMsg * proxymsg = NULL;

    if (!msg) return -1;

    if (msg->proxied != 1) return -60;

    if (!msg->fwdurl || msg->fwdurllen <= 0) return -70;

#if defined _DEBUG
  print_request(msg, stdout);
#endif

    /* It is necessary to solve the problem of calling this function repeatedly. */

    if ((proxymsg = msg->proxymsg) == NULL) {
        /* If the proxy message is created, ignore this step. create one proxy HTTPMsg object,
           with headers X-Forwarded-For and X-Real-IP added in script */
        proxymsg = http_proxy_srvmsg_open(msg, msg->fwdurl, msg->fwdurllen);
        if (proxymsg == NULL) {
            msg->proxymsg = NULL;
            return -300;
        }
    }

    if (strlen(proxymsg->dstip) > 0 && proxymsg->pcon && 
        http_con_msg_exist(proxymsg->pcon, proxymsg) >= 0)
    {
        /* If destIP address is resolved and the proxymsg is bound to one HTTP connection,
           no subsequent operation is required. */
        return 0;
    }

    return http_srv_msg_send(proxymsg);
}


int http_proxy_srv_send (void * vsrvcon, void * vsrvmsg)
{
    HTTPCon   * srvcon = (HTTPCon *)vsrvcon;
    HTTPMsg   * srvmsg = (HTTPMsg *)vsrvmsg;
    HTTPCon   * clicon = NULL;
    HTTPMsg   * climsg = NULL;
    HTTPChunk * chunk = NULL;
    frame_t   * frm = NULL;

    uint8       isend = 0;
    int         ret;
    int         rcvslen = 0;
    uint8     * pbgn = NULL;
    int         num = 0;

    /* Before the TCP connection on the server side has been successfully
       established, the client-side request data may be received. At this
       time, these client-side data will be transferred to the body_chunk
       in the HTTPMsg on the server side. srvcon is allowed to be NULL. */

    if (!srvmsg) return -1;

    if (srvmsg->proxied != 2) {
        if (srvcon)
            return http_srv_send(srvmsg->httpmgmt, srvcon->conid);
        return -2;
    }

    climsg = srvmsg->proxymsg;
    if (!climsg) return -3;
 
    clicon = climsg->pcon;
    if (!clicon) return -4;
 
    if (climsg->proxied != 1) return -10;

    frm = clicon->rcvstream;
 
    pbgn = frameP(frm);
    num = frameL(frm);

    if (climsg->req_gotall_body || num <= 0) {
        if (srvcon)
            return http_srv_send(srvmsg->httpmgmt, srvcon->conid);
        return 0;
    }

    EnterCriticalSection(&clicon->excCS);
    if ((num = frameL(clicon->rcvstream)) > 0) {
        arr_push(srvmsg->req_rcvs_list, clicon->rcvstream);
        clicon->rcvstream = frame_alloc(0, clicon->alloctype, clicon->kmemblk);
    }
    LeaveCriticalSection(&clicon->excCS);
 
    if (climsg->req_body_flag == BC_CONTENT_LENGTH &&
        climsg->req_body_length - srvmsg->req_body_iolen > 0 && num > 0)
    {
        /* remaining body to be sent */
        rcvslen = climsg->req_body_length - srvmsg->req_body_iolen;
        rcvslen = min(num, rcvslen);
 
        climsg->req_body_iolen += rcvslen;
        climsg->req_stream_recv += rcvslen;

        srvmsg->req_body_iolen += rcvslen;
        srvmsg->req_stream_recv += rcvslen;
 
        isend = srvmsg->req_body_iolen >= climsg->req_body_length;
 
        if (rcvslen > 0) {
            chunk_add_bufptr(srvmsg->req_body_chunk, pbgn, rcvslen, frm, NULL);
        }
 
    } else if (climsg->req_body_flag == BC_TE && num > 0) {
        if (climsg->req_chunk == NULL) {
            climsg->req_chunk = http_chunk_alloc(climsg->alloctype, climsg->kmemblk);
        }
        chunk = (HTTPChunk *)climsg->req_chunk;
 
        ret = http_chunk_add_bufptr(chunk, pbgn, num, &rcvslen);
 
        isend = chunk->gotall;
 
        if (ret >= 0 && rcvslen > 0) {
            chunk_copy(http_chunk_obj(chunk), srvmsg->req_body_chunk, frm, NULL);
        }

        climsg->req_body_iolen += chunk_rest_size(http_chunk_obj(chunk), 0);
        climsg->req_body_length += chunk_rest_size(http_chunk_obj(chunk), 0);
        climsg->req_stream_recv += rcvslen;

        srvmsg->req_body_iolen += chunk_rest_size(http_chunk_obj(chunk), 0);
        srvmsg->req_body_length += chunk_rest_size(http_chunk_obj(chunk), 0);
        srvmsg->req_stream_recv += rcvslen;

        chunk_remove(http_chunk_obj(chunk), srvmsg->req_body_length, 0);

    } else if (climsg->req_body_flag == BC_NONE || climsg->req_body_length == 0) {
        isend = 1;
    }
 
    if (isend && num > rcvslen) {
        frame_put_nfirst(clicon->rcvstream, pbgn + rcvslen, num - rcvslen);
    }
 
    if (isend) {
        srvmsg->req_gotall_body = 1;
        climsg->req_gotall_body = 1;
        clicon->rcv_state = HTTP_CON_READY;
        chunk_set_end(srvmsg->req_body_chunk);

    } else {
        clicon->rcv_state = HTTP_CON_WAITING_BODY;
    }
 
    if (srvcon)
        return http_srv_send(srvcon->mgmt, srvcon->conid);
    return 0;
}


int http_proxy_climsg_dup (void * vsrvmsg, void * vclimsg)
{
    HTTPMsg    * srvmsg = (HTTPMsg *)vsrvmsg;
    HTTPMsg    * climsg = (HTTPMsg *)vclimsg;
    HTTPMgmt   * mgmt = NULL;
    HeaderUnit * punit = NULL;
    int          i, num;
    int          ret = 0;
    char         buf[256];

    if (!srvmsg) return -1;

    mgmt = (HTTPMgmt *)srvmsg->httpmgmt;
    if (!mgmt) return -2;

    if (!climsg) {
        climsg = http_msg_mgmt_get(mgmt, srvmsg->proxymsgid);
        if (!climsg) return -3;
    }

    if (climsg->res_encoded) return 0;

    /* set status code */
    climsg->SetStatus(climsg, srvmsg->res_status, NULL);

    /* duplicate all the response headers into client msg */
 
    num = arr_num(srvmsg->res_header_list);
    for (i = 0; i < num; i++) {
        punit = (HeaderUnit *)arr_value(srvmsg->res_header_list, i);
        if (!punit || !punit->name || punit->namelen < 1) {
            continue;
        }
 
        if (strncasecmp(HUName(punit), "Server", 6) == 0 && strncasecmp(HUValue(punit), "eJet/", 5) != 0) {
            str_secpy(buf, sizeof(buf)-21, HUValue(punit), punit->valuelen);
            snprintf(buf + strlen(buf), sizeof(buf)-1-strlen(buf), " via eJet/%s", g_http_version);
            http_header_append(climsg, 0, HUName(punit), punit->namelen, buf, strlen(buf));

        } else {
            http_header_append(climsg, 1, HUName(punit), punit->namelen,
                               HUValue(punit), punit->valuelen);
        }
    }

    climsg->res_mime = srvmsg->res_mime;
    climsg->res_mimeid = srvmsg->res_mimeid;

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
 
    climsg->res_encoded = 1;
    climsg->state = HTTP_MSG_REQUEST_HANDLED;

    return 0;
}

int http_proxy_cli_send (void * vsrvcon, void * vsrvmsg, void * vclicon, void * vclimsg)
{
    HTTPCon    * srvcon = (HTTPCon *)vsrvcon;
    HTTPMsg    * srvmsg = (HTTPMsg *)vsrvmsg;
    HTTPCon    * clicon = (HTTPCon *)vclicon;
    HTTPMsg    * climsg = (HTTPMsg *)vclimsg;
    HTTPChunk  * chunk = NULL;
    frame_t    * frm = NULL;
 
    uint8        isend = 0;
    int          ret;
    int          rcvslen = 0;
    uint8      * pbgn = NULL;
    int          num = 0;

    if (!climsg) return -1;

    if (!clicon) {
        clicon = http_mgmt_con_get(climsg->httpmgmt, climsg->conid);
        if (!clicon) return -4;
    }
 
    if (!srvmsg) {
        srvmsg = http_msg_mgmt_get(climsg->httpmgmt, climsg->proxymsgid);
        if (!srvmsg) return -3;
    }

    if (!srvcon) {
        srvcon = http_mgmt_con_get(climsg->httpmgmt, srvmsg->conid);
        if (!srvcon) return -4;
    }
 
    if (climsg->proxied != 1) return -10;
    if (srvmsg->proxied != 2) return -11;
 
    frm = srvcon->rcvstream;
 
    pbgn = frameP(frm);
    num = frameL(frm);

    if (srvmsg->res_gotall_body || num <= 0)
        return http_cli_send(clicon->mgmt, clicon->conid);

    EnterCriticalSection(&srvcon->excCS);
    if ((num = frameL(srvcon->rcvstream)) > 0) {
        arr_push(climsg->res_rcvs_list, srvcon->rcvstream);
        srvcon->rcvstream = frame_alloc(0, srvcon->alloctype, srvcon->kmemblk);
    }
    LeaveCriticalSection(&srvcon->excCS);

    if (srvmsg->res_body_flag == BC_CONTENT_LENGTH &&
        srvmsg->res_body_length - climsg->res_body_iolen > 0 && num > 0)
    {
        /* remaining body to be sent */
        rcvslen = srvmsg->res_body_length - climsg->res_body_iolen;
        rcvslen = min(num, rcvslen);
 
        srvmsg->res_body_iolen += rcvslen;
        climsg->res_body_iolen += rcvslen;
        srvmsg->res_stream_recv += rcvslen;
 
        isend = climsg->res_body_iolen >= srvmsg->res_body_length ? 1 : 0;
 
        if (rcvslen > 0) {
            chunk_add_bufptr(climsg->res_body_chunk, pbgn, rcvslen, frm, NULL);
        }
 
    } else if (srvmsg->res_body_flag == BC_TE && num > 0) {
 
        if (climsg->res_chunk == NULL)
            climsg->res_chunk = http_chunk_alloc(climsg->alloctype, climsg->kmemblk);

        chunk = (HTTPChunk *)climsg->res_chunk;
 
        ret = http_chunk_add_bufptr(chunk, pbgn, num, &rcvslen);
 
        isend = chunk->gotall;
 
        if (ret >= 0 && rcvslen > 0) {
            chunk_copy(http_chunk_obj(chunk), climsg->res_body_chunk, frm, NULL);
        }

        srvmsg->res_body_iolen += chunk_rest_size(http_chunk_obj(chunk), 0);
        srvmsg->res_body_length += chunk_rest_size(http_chunk_obj(chunk), 0);
        srvmsg->res_stream_recv += rcvslen;

        climsg->res_body_iolen += chunk_rest_size(http_chunk_obj(chunk), 0);
        climsg->res_body_length += chunk_rest_size(http_chunk_obj(chunk), 0);
        climsg->res_stream_recv += rcvslen;
 
        chunk_remove(http_chunk_obj(chunk), climsg->res_body_length, 0);

    } else if (srvmsg->res_body_flag == BC_NONE || srvmsg->res_body_length == 0) {
        isend = 1;
    }
 
    if (isend && num > rcvslen) {
        frame_put_nfirst(srvcon->rcvstream, pbgn + rcvslen, num - rcvslen);
    }
 
    if (isend) {
        srvmsg->res_gotall_body = 1;
        climsg->res_gotall_body = 1;

        /* all data from origin server are received. srvmsg can be closed now! */
        http_con_msg_del(srvcon, srvmsg);
        srvcon->msg = NULL;
        http_msg_close(srvmsg);

        srvcon->rcv_state = HTTP_CON_READY;
        chunk_set_end(climsg->res_body_chunk);

    } else {
        srvcon->rcv_state = HTTP_CON_WAITING_BODY;
    }
 
    if (srvcon->workerid == clicon->workerid)
        return http_cli_send(clicon->mgmt, clicon->conid);
    else
        return http_cli_send_probe(clicon->mgmt, clicon->conid);
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

        if (srvmsg->res_chunk == NULL) {
            srvmsg->res_chunk = http_chunk_alloc(srvmsg->alloctype, srvmsg->kmemblk);
        }     
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

    if (!pcon || !msg) return NULL;

    if (pcon->httptunnel && pcon->tunnelcon)
        return pcon->tunnelcon;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return NULL;

    /* set the tunnel flag for client-side HTTPCon */
    pcon->httptunnel = 1;
    pcon->tunnelcon = NULL;

    if (pcon->tunnelhost) {
        k_mem_free(pcon->tunnelhost, pcon->alloctype, pcon->kmemblk);
        pcon->tunnelhost = NULL;
    }
    if (msg->uri)
        pcon->tunnelhost = k_mem_str_dup(frameP(msg->uri->uri), frameL(msg->uri->uri),
                                         pcon->alloctype, pcon->kmemblk);

    msg->dstport = msg->req_port;

    /* check if the destinated server of http connect request is itself */
    if (http_listen_check_self(msg->httpmgmt, 
                      msg->req_host,
                      msg->req_hostlen,
                      msg->dstip, msg->dstport) > 0)
    {
        pcon->tunnelself = 1;
        return NULL;
    }

    tunnelcon = http_con_open(NULL, msg->dstip, msg->dstport, 0, iodev_workerid(pcon->pdev)); //pcon->workerid);
    if (tunnelcon) {
        tunnelcon->httptunnel = 2;

        tunnelcon->tunnelcon = pcon;
        tunnelcon->tunnelconid = pcon->conid;

        if (tunnelcon->tunnelhost) {
            k_mem_free(tunnelcon->tunnelhost, tunnelcon->alloctype, tunnelcon->kmemblk);
            tunnelcon->tunnelhost = NULL;
        }
        if (msg->uri)
            tunnelcon->tunnelhost = k_mem_str_dup(frameP(msg->uri->uri), frameL(msg->uri->uri),
                                                  tunnelcon->alloctype, tunnelcon->kmemblk);

        pcon->tunnelcon = tunnelcon;
        pcon->tunnelconid = tunnelcon->conid;

        /* clear the number received from or sent to the request side after tunnel built */
        pcon->total_recv = pcon->total_sent = 0;

        return tunnelcon;
    }

    return NULL;
}

int http_tunnel_srv_send (void * vclicon, void * vsrvcon)
{
    HTTPCon     * clicon = (HTTPCon *)vclicon;
    HTTPCon     * srvcon = (HTTPCon *)vsrvcon;
    HTTPMgmt    * mgmt = NULL;
    int           sentnum = 0;
    int           ret = 0;
    struct iovec  iov[4];
    int           iovcnt = 0;

    if (!clicon) return -1;
    if (!srvcon) return -2;

    mgmt = (HTTPMgmt *)clicon->mgmt;
    if (!mgmt) return -3;

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
    if (sentnum > 0) srvcon->total_sent += sentnum;

    if (ret < 0) {
        return -200;
    }

    time(&srvcon->stamp);

    frame_del_first(clicon->rcvstream, sentnum);

    if (frameL(clicon->rcvstream) > 0) {
        iodev_add_notify(srvcon->pdev, RWF_WRITE);
    }

    /* if HTTPCon of Origin side is slower than that of Client side,
       transporting speed limit of client side should be adopted.
            Client ----X----> eJet ========> Origin
       now check if canceling the speed limit of client side:
    */
    if (sentnum > 0)
        http_srv_send_cc(mgmt, srvcon->conid);

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
    if (sentnum > 0) clicon->total_sent += sentnum;

    if (ret < 0) {
        return -200;
    }

    time(&clicon->stamp);
    time(&srvcon->stamp);

    frame_del_first(srvcon->rcvstream, sentnum);

    if (frameL(srvcon->rcvstream) > 0) {
        iodev_add_notify(clicon->pdev, RWF_WRITE);
    }

    /* If the data transmission speed on the client side's HTTPCon is
       slower than that of the origin-side, the transmission speed of
       the origin-side should be limited.
            Client <-------- eJet <====X==== Origin
       Now check whether to cancel the speed limit of origin-side: */

    if (sentnum > 0)
        http_cli_send_cc(mgmt, clicon->conid);

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
        return http_proxy_cli_send(NULL, NULL, clicon, climsg);
    }

    /* allow the multiple HTTPMsg in HTTPCon queue and handled in pipeline */
    if (climsg != http_con_msg_first(clicon)) {
        return -100;
    }

    if (climsg->res_encoded == 0) {
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
        http_cli_send(clicon->mgmt, clicon->conid);

    return 1;
}

int http_proxy_srv_cache_store (void * vsrvcon, void * vsrvmsg, void * vclicon, void * vclimsg)
{
    HTTPCon    * srvcon = (HTTPCon *)vsrvcon;
    HTTPMsg    * srvmsg = (HTTPMsg *)vsrvmsg;
    HTTPCon    * clicon = (HTTPCon *)vclicon;
    HTTPMsg    * climsg = (HTTPMsg *)vclimsg;
    HTTPMgmt   * mgmt = NULL;
    CacheInfo  * cacinfo = NULL;
    char       * pbody = NULL;
    int          bodylen = 0;
    int          wlen = 0;
    int64        filepos = 0;
    int64        restlen = 0;
    int          ret, rmlen = 0;
    uint8        justsaveit = 0;

    if (!srvmsg) return -1;

    mgmt = (HTTPMgmt *)srvmsg->httpmgmt;
    if (!mgmt) return -2;
 
    if (!srvcon) {
        srvcon = http_mgmt_con_get(mgmt, srvmsg->conid);
        if (!srvcon) return -3;
    }
 
    if (!climsg) {
        climsg = http_msg_mgmt_get(mgmt, srvmsg->proxymsgid);
        if (!climsg) return -4;
    }
 
    if (!clicon) {
        clicon = http_mgmt_con_get(mgmt, climsg->conid);
        if (!clicon) return -5;
    }
 
    if (climsg->proxied != 1) return -10;
    if (srvmsg->proxied != 2) return -11;
 
    cacinfo = (CacheInfo *)climsg->res_cache_info;
    if (!cacinfo) {
        return http_proxy_cli_send(srvcon, srvmsg, clicon, climsg);
    }

    /* allow the multiple HTTPMsg in HTTPCon queue but handled in pipeline */
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

            climsg->res_gotall_body = 1;
            srvmsg->res_gotall_body = 1;

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

#if defined(_WIN32) || defined(_WIN64)
        filepos = native_file_offset(climsg->res_file_handle);
#else
        filepos = lseek(native_file_fd(climsg->res_file_handle), 0, SEEK_CUR);
#endif

        wlen = native_file_write(climsg->res_file_handle, pbody, bodylen);
        if (wlen > 0) {
            frame_del_first(srvcon->rcvstream, wlen);
            climsg->res_body_iolen += wlen;

            cache_info_add_frag(cacinfo, filepos, wlen, 0);
        }

        if (climsg->res_body_iolen >= climsg->res_body_length) {
            /* got all body content of the current request, but possibly not all the file content */
            climsg->proxymsg = NULL;

            climsg->res_gotall_body = 1;
            srvmsg->res_gotall_body = 1;

            srvcon->rcv_state = HTTP_CON_READY;

            http_con_msg_del(srvcon, srvmsg);
            srvcon->msg = NULL;
            http_msg_close(srvmsg);
        }

    } else if (climsg->res_body_flag == BC_TE) {
        if (climsg->res_chunk == NULL) {
            climsg->res_chunk = http_chunk_alloc(climsg->alloctype, climsg->kmemblk);
        }     

        if (http_chunk_gotall(climsg->res_chunk)) {
            /* got all body content of the current request, but possibly not all the file content */
            chunk_set_end(climsg->res_body_chunk);

            climsg->proxymsg = NULL;

            climsg->res_gotall_body = 1;
            srvmsg->res_gotall_body = 1;

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

#if defined(_WIN32) || defined(_WIN64)
        filepos = native_file_offset(climsg->res_file_handle);
#else
        filepos = lseek(native_file_fd(climsg->res_file_handle), 0, SEEK_CUR);
#endif

        /* parsed body content without containing hex-length\r\n will be writen into cache file */
        wlen = restlen = chunk_rest_size(http_chunk_obj(climsg->res_chunk), 0);
 
        climsg->res_body_iolen += restlen;
        climsg->res_body_length += restlen;

        chunk_write_file(http_chunk_obj(climsg->res_chunk),
                          native_file_fd(climsg->res_file_handle), 0, -1, 0);

        chunk_remove(http_chunk_obj(climsg->res_chunk), climsg->res_body_length, 0);
 
        frame_del_first(srvcon->rcvstream, rmlen);
 
        if (http_chunk_gotall(climsg->res_chunk)) {
            /* got all body content of the current request, but possibly not all the file content */
            climsg->proxymsg = NULL;

            climsg->res_gotall_body = 1;
            srvmsg->res_gotall_body = 1;

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
    int          i, num;
    char         buf[512];
    int          ret = 0;
 
    if (!msg) return NULL;
 
    srvmsg = http_msg_fetch(msg->httpmgmt);
    if (!srvmsg) return NULL;
 
    srvmsg->SetMethod(srvmsg, "GET", 3);
 
    srvmsg->SetURL(srvmsg, msg->fwdurl, msg->fwdurllen, 1);
    srvmsg->req_url_type = msg->req_url_type;
 
    str_cpy(srvmsg->req_ver, msg->req_ver);
    srvmsg->req_ver_major = msg->req_ver_major;
    srvmsg->req_ver_minor = msg->req_ver_minor;

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
 
        if (strncasecmp(HUName(punit), "User-Agent", 10) == 0) {
            str_secpy(buf, sizeof(buf)-21, HUValue(punit), punit->valuelen);
            snprintf(buf + strlen(buf), sizeof(buf)-1-strlen(buf), " via eJet/%s", g_http_version);
            http_header_append(srvmsg, 0, HUName(punit), punit->namelen, buf, strlen(buf));
 
        } else {
            http_header_append(srvmsg, 0, HUName(punit), punit->namelen,
                               HUValue(punit), punit->valuelen);
        }
    }
 
    cacinfo = (CacheInfo *)msg->res_cache_info;
    if (cacinfo) {
        http_header_del(srvmsg, 0, "Range", -1);

#if defined(_WIN32) || defined(_WIN64)
        sprintf(buf, "bytes=%I64d-", msg->cache_req_off);
#else
        sprintf(buf, "bytes=%lld-", msg->cache_req_off);
#endif
        if (msg->cache_req_len > 0 &&
            msg->cache_req_off + msg->cache_req_len < cacinfo->body_length)
#if defined(_WIN32) || defined(_WIN64)
            sprintf(buf+strlen(buf), "%I64d", msg->cache_req_off + msg->cache_req_len - 1);
#else
            sprintf(buf+strlen(buf), "%lld", msg->cache_req_off + msg->cache_req_len - 1);
#endif

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
 
    ret = http_req_build(srvmsg, 0);
    if (ret < 0) {
        http_msg_close(srvmsg);
        return NULL;
    }
 
    srvmsg->proxied = 2;
    srvmsg->proxymsg = msg;
 
    srvmsg->state = HTTP_MSG_SENDING;

    msg->proxymsg = srvmsg;

    if (http_srv_msg_send(srvmsg) < 0)
        return NULL;

    return srvmsg;
}

