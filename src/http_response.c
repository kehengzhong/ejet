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
#include "http_header.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_response.h"
#include "http_status.h"
#include "http_request.h"
#include "http_resloc.h"
#include "http_con.h"
#include "http_script.h"

extern HTTPMgmt * gp_httpmgmt;

int http_res_getstatus (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    return msg->res_status;
}

/* Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
 */
int http_res_status_decode (void * vmsg, char * pline, int linelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    char    * pval = NULL;
    char    * pend = NULL;
    char    * poct = NULL;

    if (!msg) return -1;
    if (!pline || linelen <= 0) return -2;

    poct = pline; pend = poct + linelen;

    /* parse for the field Response HTTP Version */
    pval = skipOver(poct, pend-poct, " \t\r\n", 4);
    if (pval >= pend) return -100;
    poct = skipTo(pval, pend-pval, " \t\r", 3);

    str_secpy(msg->res_ver, sizeof(msg->res_ver)-1, pval, poct - pval);

    /* parse for the field Response Status Code */
    pval = skipOver(poct, pend-poct, " \t\r\n", 4);
    if (pval >= pend) return -200;
    poct = skipTo(pval, pend-pval, " \t\r", 3);

    str_atoi(pval, poct - pval, &msg->res_status);

    /* parse for the field Response Reason Phrase */
    pval = skipOver(poct, pend-poct, " \t\r\n", 4);
    if (pval >= pend) return -300;
    poct = skipTo(pval, pend-pval, "\r\n", 2);

    str_secpy(msg->res_reason, sizeof(msg->res_reason)-1, pval, poct - pval);

    return 0;
}


int http_res_status_encode (void * vmsg, frame_p frame)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!frame) return -5;

    frame_appendf(frame, "%s %d %s\r\n", msg->res_ver, msg->res_status, msg->res_reason);

    return 0;
}


int http_res_statusline_set (void * vmsg, char * ver, int verlen, int status, char * defreason)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    int        ret = 0;
    char     * reason = NULL;

    if (!msg) return -1;

    mgmt = (HTTPMgmt *)msg->httpmgmt;

    if (!ver || verlen <= 0) {
        ver = mgmt->httpver1;
        verlen = strlen(mgmt->httpver1);
    }

    str_secpy(msg->res_ver, sizeof(msg->res_ver)-1, ver, verlen);

    ret = http_get_status2(mgmt, status, &reason);

    msg->res_status = status;

    if (defreason && strlen(defreason) > 0) {
        str_secpy(msg->res_reason, sizeof(msg->res_reason)-1, defreason, strlen(defreason));
    } else if (ret < 0 || !reason || strlen(reason) <= 0) { /* unknown status code */
        str_cpy(msg->res_reason, "unknown");
    } else {
        str_secpy(msg->res_reason, sizeof(msg->res_reason)-1, reason, strlen(reason));
    }

    return 0;
}


int http_res_parse_header (void * vmsg, int has_statusline)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
    char       * pover = NULL;
    char       * pcolon = NULL;
    char       * pend  = NULL;
    char       * poct  = NULL;
    int          ret = 0;

    char       * name = NULL;
    char       * value = NULL;
    int          namelen, valuelen;

    if (!msg) return -1;
    if (!msg->res_header_stream) return 0;

    poct = frameP(msg->res_header_stream);
    pover = poct + frameL(msg->res_header_stream);

    if (has_statusline) {
        poct = skipOver(poct, pover-poct, " \t\r\n", 4);
        if (!poct || poct >= pover) return -100;
    
        pend = memchr(poct, '\n', pover-poct);
        if (!pend) return -100;  /* has no line-terminal char */
    
        ret = http_res_status_decode(msg, poct, pend-poct);
    } else {
        pend = poct;
    }

    while (poct < pover) {
        poct = skipOver(pend, pover-pend, " \t\r\n", 4);
        if (poct >= pover) break;

        pend = memchr(poct, '\n', pover - poct);
        if (!pend || pend >= pover) break;

        poct = skipOver(poct, pend-poct, " \t", 2);
        if (!poct || poct >= pend) continue;

        name = value = NULL; namelen = valuelen = 0;

        name = poct;

        pcolon = skipTo(poct, pend-poct, ":", 1);
        if (!pcolon || pcolon>=pend) continue;

        poct = rskipOver(pcolon-1, pcolon-name, " \t", 2);

        if (poct >= name) namelen = poct-name+1;
        else continue;

        poct = skipOver(pcolon+1, pend-pcolon-1, " \t\r", 3);
        if (poct >= pend) continue;

        value = poct;
        poct = rskipOver(pend-1, pend-poct, " \t\r", 3);
        if (poct >= value) valuelen = poct-value+1;
        else { value = NULL; valuelen = 0; }

        http_header_add(msg, 1, name, namelen, value, valuelen);
    }

    /* determine the body content format */

    /* determine if the response body is encoded in the format of chunked */
    punit = http_header_get(msg, 1, "Transfer-Encoding", 17);
    if (punit) {
        if (punit->valuelen != 7 ||
            strncasecmp("chunked", HUValue(punit), 7) != 0)
        {
            msg->res_body_flag = BC_TE_INVALID;
        } else {
            msg->res_body_flag = BC_TE;
        }
    } else {
        /* determine if the response body is counted in the format of Content-Length */
        punit = http_header_get(msg, 1, "Content-Length", 14);
        if (punit) {
            msg->res_body_flag = BC_CONTENT_LENGTH;
            msg->res_body_length = 0;
            for (ret = 0; ret < punit->valuelen && !isdigit(*(HUValue(punit)+ret)); ret++);
            for (; ret<punit->valuelen && isdigit(*(HUValue(punit)+ret)); ret++) {
                msg->res_body_length *= 10;
                msg->res_body_length += *(HUValue(punit)+ret) - '0';
            }
        } else {
            msg->res_body_flag = BC_UNKNOWN;
        }
    }

    /* determine if the response connection is keep-alive */
    punit = http_header_get(msg, 1, "Connection", -1);
    if (punit) {
        if (punit->valuelen == 10 && strncasecmp("keep-alive", HUValue(punit), 10) == 0) {
            msg->res_conn_keepalive = 1;
        } else {
            msg->res_conn_keepalive = 0;
        }
    } else {
        msg->res_conn_keepalive = 0;
    }

    /* set content-type value of HTTPMsg instance */
    punit = http_header_get(msg, 1, "Content-Type", -1);
    if (punit) {
        mime_type_get_by_mime(http_msg_get_mimemgmt(msg), HUValue(punit), NULL, &msg->res_mimeid, NULL);
        mime_type_get_by_mimeid(http_msg_get_mimemgmt(msg), msg->res_mimeid, &msg->res_mime, NULL, NULL);
    }

    return 1;
}


int http_res_body_compress (void * vmsg, char * zipstr, int zipstrlen)
{
    return 0;
}

int http_res_errpage (void * vmsg)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    HTTPHost     * phost = NULL;
    char         * errfile = NULL;
    char           path[2048];
    frame_t      * frm = NULL;
    char         * reason = NULL;
    char         * desc = NULL;
    int            ind = 0;

    if (!msg) return -1;

    if (msg->res_status < 400 || chunk_size(msg->res_body_chunk, 0) > 0)
        return 0;

    if (msg->phost) {
        phost = msg->phost;

        if (msg->res_status < 500) {
            ind = msg->res_status - 400;
            if (ind < 20)
                errfile = phost->errpage.err400[ind];

        } else {
            ind = msg->res_status - 500;
            if (ind < 20)
                errfile = phost->errpage.err500[ind];
        }

        if (errfile && strlen(errfile) > 0) {
            if (phost->errpage.root)
                snprintf(path, sizeof(path)-1, "%s/%s", phost->errpage.root, errfile);
            else
                snprintf(path, sizeof(path)-1, "%s", errfile);

            if (msg->AddResFile(msg, path, 0, -1) >= 0) {
                msg->res_body_length = chunk_size(msg->res_body_chunk, 0);
                msg->SetResContentLength(msg, msg->res_body_length);
            }
        }
    }

    if (chunk_size(msg->res_body_chunk, 0) <= 0) {
        http_get_status2(msg->httpmgmt, msg->res_status, &reason);
        if (!reason) reason = "";

        frm = frame_alloc(512, msg->alloctype, msg->kmemblk);
        frame_append(frm, "<html>\n<head><title>");

        switch (msg->res_status) {
        case 400:
            reason = "Bad Request";
            desc = " was not understood on this server";
            break;
        case 401:
            reason = "Unauthorized";
            desc = " was unauthorized on this server";
            break;
        case 402:
            reason = "Payment required";
            desc = " requires payment";
            break;
        case 403:
            reason = "Forbidden";
            desc = " was forbidden, operation is understood but refused on this server";
            break;
        case 404:
            reason = "Not Found";
            desc = " was not found on this server";
            break;
        case 405:
            reason = "Method not allowed";
            desc = " uses unallowed Method on this server";
            break;
        case 406:
            reason = "Not Acceptable";
            desc = " was not acceptable on this server";
            break;
        case 500:
            desc = " caused internal server error";
            break;
        case 501:
            desc = " was not implemented on this server";
            break;
        case 502:
            desc = " failed for bad gateway";
            break;
        case 503:
            desc = " was unavailable on this server";
            break;
        case 504:
            desc = " failed for gateway timeout";
            break;
        case 505:
            desc = " failed for unsupported HTTP version";
            break;
        default:
            desc = "";
            break;
        }

        frame_appendf(frm, "%d %s", msg->res_status, reason);
        frame_appendf(frm, "</title></head>\n<body bgcolor=\"white\">\n<center><h1>");
        frame_appendf(frm, "%d %s", msg->res_status, reason);
        frame_appendf(frm, "</h1></center>\n<p align=center>");
        frame_appendf(frm, "The requested URL <font color=blue>%s</font>",
                       msg->absuri ? frameS(msg->absuri->uri): "NUL");
        frame_appendf(frm, "%s", desc);

        frame_appendf(frm, ".</p>\n<hr><center>eJet/%s<br><i>", g_http_version);
        frame_html_escape(g_http_author, -1, frm);
        frame_append(frm, "</i></center>\n</body>\n</html>");

        msg->AddResContent(msg, frameP(frm), frameL(frm));

        msg->SetResContentType(msg, "text/html", -1);
        msg->SetResContentLength(msg, frameL(frm));

        frame_free(frm);
    }

    return 0;
}

int http_res_encoding (void * vmsg)
{       
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    HTTPMgmt     * mgmt = NULL;
    HeaderUnit   * punit = NULL;
    HeaderUnit   * acchu = NULL;
    HTTPHost     * phost = NULL;
    char           buf[2048];
    int            i, num;
    time_t         gmtval;

    if (!msg) return -1;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) mgmt = gp_httpmgmt;
    if (!mgmt) return -2;

    if (msg->res_stream == NULL)
        msg->res_stream = frame_alloc(256, msg->alloctype, msg->kmemblk);
    else
        frame_empty(msg->res_stream);

    if (mgmt->res_check) {
        msg->GetRealFile(msg, buf, sizeof(buf)-1);
        (*mgmt->res_check)(mgmt->res_checkobj, msg, buf);
    }

    /* now execute reply-scripts defined in configure file. */
    http_reply_script_exec(msg);

    if (msg->res_status >= 400 && chunk_size(msg->res_body_chunk, 0) <= 0)
        http_res_errpage(msg);

    if (msg->proxied) { //proxy msg
        http_header_del(msg, 1, "Date", 4);
        gmtval = time(NULL);
        http_header_append_date(msg, 1, "Date", 4, gmtval);
    }

    /* building response line */
    frame_appendfp(&msg->res_stream, "%s %d %s\r\n", msg->res_ver, msg->res_status, msg->res_reason);

    if (msg->res_body_flag == BC_CONTENT_LENGTH || msg->res_body_flag == BC_TE) {
        phost = msg->phost;
 
        if (msg->proxied && phost && phost->gzip > 0 && msg->res_status == 200) {
            /* check if the client support content-encoding */
            acchu = http_header_get(msg, 0, "Accept-Encoding", 15);
            if (!acchu) goto go_on_execute;

            /* check the response content type */
            punit = http_header_get(msg, 1, "Content-Type", 12);
            if (!punit || strncasecmp(HUValue(punit), "text/", 5)) 
                goto go_on_execute;

            /* if the body is encoded, just ignore */
            punit = http_header_get(msg, 1, "Content-Encoding", 16);
            if (punit) goto go_on_execute;

            //http_res_body_compress(msg, HUValue(acchu), acchu->valuelen);
        }

go_on_execute:
        if (msg->res_body_flag == BC_CONTENT_LENGTH) {
            if (http_header_get(msg, 1, "Content-Length", 14) == NULL) {
                if (msg->res_body_length <= 0)
                    msg->res_body_length = chunk_size(msg->res_body_chunk, 0);
                http_header_append_int64(msg, 1, "Content-Length", 14, msg->res_body_length);
            }
        } else {
            if (http_header_get(msg, 1, "Transfer-Encoding", -1) == NULL) {
                http_header_append(msg, 1, "Transfer-Encoding", 17, "chunked", 7);
            }
        }
    }

    if (msg->flag304) {
        msg->res_body_length = 0;
        http_header_del(msg, 1, "Transfer-Encoding", 17);
        http_header_del(msg, 1, "Content-Length", 14);
        http_header_del(msg, 1, "Content-Type", 12);
        http_header_append_int64(msg, 1, "Content-Length", 14, 0);
    }

    /* append all the headers */
    num = arr_num(msg->res_header_list);
    for (i = 0; i < num; i++) {

        punit = arr_value(msg->res_header_list, i);
        if (!punit || !punit->name || punit->namelen < 1) {
            continue;
        }

        frame_put_nlast(msg->res_stream, HUName(punit), punit->namelen);
        frame_append(msg->res_stream, ": ");
        if (HUValue(punit) && punit->valuelen > 0)
            frame_put_nlast(msg->res_stream, HUValue(punit), punit->valuelen);

        frame_append(msg->res_stream, "\r\n");
    }

    /* append the trailer line of the http response header: a blank line */
    frame_append(msg->res_stream, "\r\n");

    msg->res_header_length = frameL(msg->res_stream);

    chunk_prepend_bufptr(msg->res_body_chunk, frameP(msg->res_stream),
                         frameL(msg->res_stream), NULL, NULL, 1);

    return 0;
}


int print_response (void * vmsg, FILE * fp)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    HeaderUnit   * unit = NULL;
    char           buf[2048];
    int            i, num;
    char         * poct = NULL;

    if (!msg) return -1;

    /* printf the response status line */
    if (fp == stdout || fp == stderr)
        fprintf(fp, "\n-------------Response ConID=%lu reqnum=%d MsgID=%ld  reqfd=%d "
                    "srcaddr=%s:%d ---------------\n",
               http_con_id(msg->pcon), http_con_reqnum(msg->pcon), msg->msgid,
               iodev_fd(http_con_iodev(msg->pcon)), msg->srcip, msg->srcport);

    /* print res_line:  HTTP/1.1 200 OK */
    fprintf(fp, "  %s %d %s\n", msg->res_ver, msg->res_status, msg->res_reason);

    /* printf the response header */
    num = arr_num(msg->res_header_list);
    for (i = 0; i < num; i++) {
        unit = arr_value(msg->res_header_list, i);
        if (!unit) continue;

        poct = HUName(unit);
        if (unit->namelen > 0) {
            str_secpy(buf, sizeof(buf)-1, poct, unit->namelen);
            fprintf(fp, "  %s: ", buf);
        } else fprintf(fp, "   : ");

        poct = HUValue(unit);
        if (unit->valuelen > 0) {
            str_secpy(buf, sizeof(buf)-1, poct, unit->valuelen);
            fprintf(fp, "%s\n", buf);
        } else fprintf(fp, "\n");
    }

    /* printf the response body */
    if (msg->res_body_length > 0) {
        int64  sndlen = 0;

        chunk_read_ptr(msg->res_body_chunk, msg->res_header_length, -1, (void **)&poct, &sndlen, 0);
        fprintf(fp, "response body %lld bytes, chunk len=%lld:\n", msg->res_body_length, sndlen);

        if (sndlen > 256) sndlen = 256;
        printOctet(fp, poct, 0, sndlen, 2);
    }

    if (msg->res_file_cache > 0) {
        printf("response body stored %lld bytes in file:\n", msg->res_body_length);
        if (msg->res_file_cache == 1)
            printf("  TempCacheFile: %s\n", msg->res_file_name);
        if (msg->res_file_cache == 2)
            printf("  ExternalFile: %s\n", msg->res_store_file);
    }

    print_hashtab(msg->res_header_table, fp);

    if (fp == stdout || fp == stderr)
        fprintf(fp, "------------------------end of the response: id=%ld "
                    "--------------------\n", msg->msgid);

    fflush(fp);

    return 0;
}

