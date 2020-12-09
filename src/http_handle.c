/*
 * Copyright (c) 2003-2020 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include <signal.h>

#include "http_header.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_con.h"
#include "http_request.h"
#include "http_cgi.h"
#include "http_listen.h"
#include "http_form.h"
#include "http_proxy.h"
#include "http_cache.h"
#include "http_handle.h"


int http_msg_handle (void * vcon, void * vmsg)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    int        ret = 0;

    if (!pcon) return -1;
    if (!msg) return -2;

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
    return 0;
}

int http_connect_process (void * vcon, void * vmsg)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HTTPCon    * tunnelcon = NULL;
    HTTPListen * hl = NULL;

    if (!pcon) return -1;
    if (!msg) return -2;

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

    tunnelcon = http_proxy_connect_tunnel(pcon, msg);
    if (tunnelcon == NULL && pcon->tunnelself == 0) {
        msg->SetStatus(msg, 406, NULL);
        return msg->Reply(msg);
    }

    msg->SetStatus(msg, 200, "Connection Established");
    return msg->Reply(msg);
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
    int          i, ret = -100;
    ulong        msgid = 0;

    if (!pcon) return -1;
    if (!msg) return -2;

    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -3;

    hl = (HTTPListen *)pcon->hl;
    if (!hl) return -4;

    msgid = msg->msgid;

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

    if (!(ploc = (HTTPLoc *)msg->ploc)) {
        msg->SetStatus(msg, 404, NULL);          
        return msg->Reply(msg);
    }

    if (msg->issued <= 0 && mgmt->req_handler) {
        ret = (*mgmt->req_handler)(mgmt->req_cbobj, msg);
    }

    if (msg->issued <= 0 && hl->cbfunc) {
        ret = (*hl->cbfunc)(hl->cbobj, msg);
    }

    /* if the upper callback handled and replied the request, the msg already recycled.
     * some default handlings should be done by determining if the msg got correctly dealt with */

    if (ret < 0 && http_msg_mgmt_get(mgmt, msgid) == msg && msg->issued <= 0) {
        ret = msg->GetRealFile(msg, path, sizeof(path));

        if (strstr(path, "../")) {
            msg->SetStatus(msg, 404, NULL);          
            return msg->Reply(msg);
        }

        if (ret > 0 && file_is_regular(path)) {
            if (msg->AddResFile(msg, path, 0, -1) < 0)
                msg->SetStatus(msg, 404, NULL);
            else
                msg->SetStatus(msg, 200, NULL);
            return msg->Reply(msg);

        } else if (file_is_dir(path)) {
            ret = strlen(path);
            for (i = 0; i < ploc->indexnum; i++) {
                sprintf(path + ret, "%s", ploc->index[i]);

                if (file_is_regular(path)) {
                    if (msg->AddResFile(msg, path, 0, -1) < 0)
                        msg->SetStatus(msg, 404, NULL);
                    else
                        msg->SetStatus(msg, 200, NULL);
                    return msg->Reply(msg);
                }
            }

            /* read the current directory to reply.
               Caution: uncommenting following fractions is dangerous for 
                        exposure of file system. please watch your step! */
            /*ret = msg->DisplayDirectory(msg);
            if (ret >= 0) return 0;*/
        }
    }

    if (http_msg_mgmt_get(mgmt, msgid) == msg && msg->issued <= 0) {
        msg->SetStatus(msg, 404, NULL);
        return msg->Reply(msg);
    }

    return ret;
}

