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
#include <signal.h>

#include "http_header.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_con.h"
#include "http_request.h"
#include "http_cgi.h"
#include "http_resloc.h"
#include "http_form.h"
#include "http_proxy.h"
#include "http_cache.h"
#include "http_fcgi_io.h"
#include "http_handle.h"

int sys_status_print (void * vmsg);
int default_handle_request (void * vmsg);

extern void * g_kmempool;
extern void * g_buddha;


int http_msg_dispatch (void * vcon, void * vmsg)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    int        ret = -70;

    if (!pcon) return -1;
    if (!msg) return -2;

    if (msg->res_encoded) return 0;

    if (msg->proxied) {
        if (http_con_msg_first(pcon) == msg)
            ret = http_proxy_launch(msg);

    } else if (msg->fastcgi) {
        if (http_con_msg_first(pcon) == msg)
            ret = http_fcgi_launch(msg);

    } else {
        ret = http_msg_handle(pcon, msg);
    }

    return ret;
}


int http_msg_handle (void * vcon, void * vmsg)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    int        ret = 0;

    if (!pcon) return -1;
    if (!msg) return -2;

#if defined _DEBUG
  print_request(msg, stdout);
#endif

    if (msg->res_encoded) return 0;

    msg->state = HTTP_MSG_REQUEST_HANDLING;

    switch (msg->req_methind) {
    case HTTP_METHOD_CONNECT:
        return http_connect_process(pcon, msg);

    case HTTP_METHOD_DELETE:
    case HTTP_METHOD_GET:
    case HTTP_METHOD_HEAD:
    case HTTP_METHOD_OPTIONS:
    case HTTP_METHOD_POST:
    case HTTP_METHOD_PUT:
    case HTTP_METHOD_TRACE:
        return http_request_process(pcon, msg);

    default:
        msg->SetStatus(msg, 405, NULL);
        ret = msg->Reply(msg);
        return ret;
    }

    return 1;
}

int http_tunnel_dns_resolve_cb (void * vmgmt, ulong msgid, char * name, int len, void * cache, int status)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg    * msg = NULL;
    HTTPCon    * pcon = NULL;
    HTTPCon    * tunnelcon = NULL;
    int          ret = 0;

    if (!mgmt) return -1;

    msg = http_msg_mgmt_get(mgmt, msgid);
    if (!msg) return -2;

    pcon = (HTTPCon *)msg->pcon;
    if (!pcon) return -3;

    if (status == DNS_ERR_IPV4 || status == DNS_ERR_IPV6) {
        str_secpy(msg->dstip, sizeof(msg->dstip)-1, name, len);

    } else if ((ret = dns_cache_getip(cache, 0, msg->dstip, sizeof(msg->dstip)-1) <= 0)) {
        msg->SetStatus(msg, 400, NULL);
        return msg->Reply(msg);
    }

    msg->dstport = msg->req_port;

    pcon->tunnel_state = HTTP_TUNNEL_CONING;
    tunnelcon = http_proxy_connect_tunnel(pcon, msg);
    if (tunnelcon == NULL) {
        if (pcon->tunnelself == 0) {
            pcon->tunnel_state = HTTP_TUNNEL_FAIL;
            if (msg->res_encoded <= 0)
                msg->SetStatus(msg, 406, NULL);
        } else {
            pcon->tunnel_state = HTTP_TUNNEL_SUCC;
            if (msg->res_encoded <= 0)
                msg->SetStatus(msg, 200, "Connection Established");
        }
        if (msg->res_encoded <= 0) ret = msg->Reply(msg);
        return ret;
    }

    if (tunnelcon->snd_state >= HTTP_CON_SEND_READY) {
        pcon->tunnel_state = HTTP_TUNNEL_SUCC;

        if (msg->res_encoded <= 0) {
            msg->SetStatus(msg, 200, "Connection Established");
            msg->Reply(msg);
        }
    }

    return 0;
}

int http_connect_process (void * vcon, void * vmsg)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HTTPListen * hl = NULL;

    if (!pcon) return -1;
    if (!msg) return -2;

    if (pcon->httptunnel == 1 || msg != http_con_msg_first(pcon)) {
        http_con_msg_del(pcon, msg);
        http_msg_close(msg);
        return 0;
    }

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -3;

    hl = (HTTPListen *)pcon->hl;
    if (!hl) return -4;

    /* if system configuraiton of current HTTP Listen does not allow forward proxy */
    if (hl->forwardproxy == 0) {
        /* CONNECT method is base upon Proxy mechanism */
        msg->SetStatus(msg, 403, "Proxy is Forbidden");
        return msg->Reply(msg);
    }

    /* system configuration does not allow CONNECT tunnel */
    if (mgmt->proxy_tunnel == 0) {
        msg->SetStatus(msg, 405, "CONNECT method not allowed");
        return msg->Reply(msg);
    }

    if (dns_query(mgmt->pcore, msg->req_host, msg->req_hostlen,
                  http_tunnel_dns_resolve_cb, mgmt, msg->msgid) < 0)
    {
        if (msg->res_encoded <= 0) {
            msg->SetStatus(msg, 400, NULL);
            return msg->Reply(msg);
        }
    }

    return 0;
}

int http_request_process (void * vcon, void * vmsg)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPListen * hl = NULL;
    HTTPLoc    * ploc = NULL;
    HTTPMgmt   * mgmt = NULL;
    CacheInfo  * cacinfo = NULL;
    char         path[1024];
    int          i, fret, ret = -100;

    if (!pcon) return -1;
    if (!msg) return -2;

    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -3;

    hl = (HTTPListen *)pcon->hl;
    if (!hl) return -4;

    if (msg->cacheon && msg->res_file_cache >= 3) {
        cacinfo = msg->res_cache_info;

        if (msg->res_file_cache == 3) {
            ret = msg->AddResFile(msg, msg->res_file_name, 0, -1);

        } else if (cacinfo != NULL) {
            ret = msg->AddResFile(msg, cacinfo->cache_tmp, 0, -1);

        } else ret = -100;

        if (ret < 0)
            msg->SetStatus(msg, 404, NULL);
        else 
            msg->SetStatus(msg, 200, NULL);

        if (cacinfo && ret >= 0) {
            http_cache_response_header(msg, cacinfo);
            msg->SetResContentTypeID(msg, cacinfo->mimeid);
        }

        return msg->Reply(msg);
    }

    /* if system configuraiton of current HTTP Listen does not allow forward proxy */
    if (msg->req_url_type > 0 && hl->forwardproxy == 0) {
        msg->SetStatus(msg, 403, "Proxy is Forbidden");
        return msg->Reply(msg);
    }

    /* if request is absolute URI and Location instance is NULL,
       re-instanstiating is executed again. */
    if (msg->req_url_type > 0 && msg->ploc == NULL) {
        http_req_set_docuri(msg, frameP(msg->uri->uri), frameL(msg->uri->uri), 0, 0);
    }

    msg->GetFileOnly(msg, path, sizeof(path)-1); 

    if (str_casecmp(path, mgmt->uptimestr) == 0) {
        return sys_status_print(msg);
    }

    ploc = (HTTPLoc *)msg->ploc;

    fret = msg->GetRealFile(msg, path, sizeof(path) - 1);

    if (msg->res_encoded == 0 && ploc && (ploc->type & SERV_CALLBACK) && ploc->cbfunc) {
        msg->cbobj = ploc->cbobj;
        ret = (*ploc->cbfunc)(ploc->cbobj, msg, ploc->tplfile ? ploc->tplfile : path);
    }

    if (msg->res_encoded == 0 && hl->cbfunc) {
        msg->cbobj = hl->cbobj;
        ret = (*hl->cbfunc)(hl->cbobj, msg, path);
    }

    if (msg->res_encoded == 0 && mgmt->req_handler) {
        msg->cbobj = mgmt->req_cbobj;
        ret = (*mgmt->req_handler)(mgmt->req_cbobj, msg, path);
    }

    /* if the upper callback handled and replied the request, the msg already recycled.
     * some default handlings should be done by determining if the msg got correctly dealt with */

    if (ret < 0 && msg->res_encoded <= 0) {
#if defined(_WIN32) || defined(_WIN64)
        if (strstr(path, "..\\")) {
#else
        if (strstr(path, "../")) {
#endif
            msg->SetStatus(msg, 404, NULL);          
            return msg->Reply(msg);
        }

        if (fret > 0 && file_is_regular(path)) {
            if (msg->AddResFile(msg, path, 0, -1) < 0)
                msg->SetStatus(msg, 404, NULL);
            else
                msg->SetStatus(msg, 200, NULL);
            return msg->Reply(msg);

        } else if (file_is_dir(path)) {
            if (!ploc) {
                msg->SetStatus(msg, 404, NULL);          
                return msg->Reply(msg);
            }

            ret = strlen(path);
            for (i = 0; i < (int)ploc->indexnum; i++) {
                sprintf(path + ret, "%s", ploc->index[i]);

                if (file_is_regular(path)) {
                    if (msg->AddResFile(msg, path, 0, -1) < 0)
                        msg->SetStatus(msg, 404, NULL);
                    else
                        msg->SetStatus(msg, 200, NULL);
                    return msg->Reply(msg);
                }
            }

            /* read the current directory to reply. */
            if (ploc->show_file_list) { 
                ret = msg->DisplayDirectory(msg);
                if (ret >= 0) return 0;
            }
        } 

        msg->SetStatus(msg, 404, NULL);
        return msg->Reply(msg);
    }

    return ret;
}


int sys_status_print (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    frame_p      frame = NULL;

    if (!msg) return -5;

    mgmt = (HTTPMgmt *)msg->httpmgmt;

    frame = frame_new(64*1024);

    frame_append(frame, "<html>");
    frame_append(frame, "<head>\n");
    frame_append(frame, "<title>");
    frame_put_nlast(frame, msg->req_host, msg->req_hostlen);
    frame_appendf(frame, "</title>\n");
    frame_append(frame, "</head>\n<body>\n");
    frame_append(frame, "<pre>\n");

    http_print(mgmt, frame, NULL);
    epcore_print(mgmt->pcore, frame, NULL);

    if (g_kmempool)
        kempool_print(g_kmempool, frame, NULL,
                      GetQueryKeyExist(msg, "memalloc"),
                      GetQueryKeyExist(msg, "mempool"),
                      GetQueryKeyExist(msg, "size"), "GlbKemPool", 0);

    if (g_buddha) frame_appendf(frame,"\r\n%s\r\n", g_buddha);

    frame_append(frame, "</pre></body>\n");
    frame_append(frame, "</html>");

    AddResContent(msg, frameP(frame), frameL(frame));

    frame_free(frame);

    AddResHdr(msg, "Cache-Control", -1, "no-cache", -1);
    SetStatus(msg, 200, NULL);
    SetResContentType (msg, "text/html", -1);
    Reply(msg);

    return 0;
}

int default_handle_request (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    frame_p      frame = NULL;
    time_t       curt;
    struct tm    st;
    int          ret = 0;

    HeaderUnit   * unit = NULL;
    int            i, num;

    if (!msg) return -5;

    time(&curt);
    st = *localtime(&curt);

    frame = frame_alloc(8192, msg->alloctype, msg->kmemblk);

    frame_append(frame, "<html>\r\n");
    frame_append(frame, "<head>\r\n");
    frame_appendf(frame, "<title>%s</title>\r\n", g_http_build);
    frame_append(frame, "</head>\r\n");
    frame_append(frame, "<body>\r\n");
    frame_append(frame, "\r\n");
    frame_appendf(frame, "<h2><p align='center'><b>%s</b></p></h2>\r\n", g_http_build);
    frame_appendf(frame, "<i>%04d-%02d-%02d %02d:%02d:%02d</i>\r\n",
                        st.tm_year+1900, st.tm_mon+1, st.tm_mday,
                        st.tm_hour, st.tm_min, st.tm_sec);
    frame_append(frame, "<hr>\r\n");
    frame_appendf(frame, "  <b>SourceAddr:</b> %s : %d<br/>\r\n", msg->srcip, msg->srcport);
    if (msg->req_host && msg->req_hostlen > 0) {
        frame_put_nlast(frame, "  <b>RemoteHost:</b> ", -1);
        frame_put_nlast(frame, msg->req_host, msg->req_hostlen);
        frame_appendf(frame, " : %d<br/>\r\n", msg->req_port);
    } else {
        frame_appendf(frame, "  <b>RemoteHost:</b>  : %d<br/>\r\n", msg->req_port);
    }
    
    frame_append(frame, "<font color=#DF0000><b>\r\n");
    if (msg->req_path && msg->req_pathlen > 0) {
        frame_appendf(frame, "  %s ", msg->req_meth);
        frame_put_nlast(frame, msg->req_path, msg->req_pathlen);
    } else {
        frame_appendf(frame, "  %s <NULL>", msg->req_meth);
    }

    if (msg->req_querylen > 0 && msg->req_query) {
        frame_put_last(frame, '?');
        frame_put_nlast(frame, msg->req_query, msg->req_querylen);
    }
    frame_appendf(frame, " %s<br/>\r\n", msg->req_ver);
    frame_append(frame, "</b></font>\r\n");

    /* printf the request header */
    num = arr_num(msg->req_header_list);
    for (i = 0; i < num; i++) {
        unit = (HeaderUnit *)arr_value(msg->req_header_list, i);
        if (!unit) continue;

        frame_append(frame, "\r\n");

        if (unit->namelen > 0) {
            frame_put_nlast(frame, "<b> ", -1);
            frame_put_nlast(frame, HUName(unit), unit->namelen);
            frame_put_nlast(frame, ":<b> ", -1);
        } else frame_appendf(frame, "<b>   :</b> ");
        frame_append(frame, "\r\n");

        if (unit->valuelen > 0) {
            frame_put_nlast(frame, HUValue(unit), unit->valuelen);
            frame_put_nlast(frame, "<br/>\r\n", -1);
        } else frame_appendf(frame, "<br/>\r\n");
    }


    frame_append(frame, "\r\n");
    frame_append(frame, "</body>\r\n");
    frame_append(frame, "</html>\r\n");

    AddResContent(msg, frameP(frame), frameL(frame));

    frame_free(frame);

    SetStatus(msg, 200, NULL);
    SetResContentType (msg, "text/html", 9);
    ret = Reply(msg);

    return ret;
}

