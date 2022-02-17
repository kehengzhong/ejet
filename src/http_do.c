/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
 
#include "http_header.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_chunk.h"
#include "http_srv.h"
#include "http_srv_io.h"
#include "http_con.h"
#include "http_request.h"

static char * hdr_accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
static char * hdr_accept_charset = "utf-8, iso-8859-1, utf-16, *;q=0.7";
static char * hdr_accept_lang = "zh-CN, en-US";


int http_redirect_request (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    HTTPCon * pcon = NULL;
    char    * p = NULL;
    int       len = 0;
    frame_p   uri;
 
    if (!msg) return -1;
 
    if (++msg->redirecttimes >= 6) {
        msg->SetStatus(msg, 417, NULL);
        msg->DelResHdr(msg, "Location", 8);
        msg->DelResHdr(msg, "Content-Length", -1);
        msg->DelResHdr(msg, "Transfer-Encoding", -1);
        msg->DelResHdr(msg, "Content-Type", -1);

        tolog(1, "eJet - Redirect: HTTP auto-redirect '%s' too many times.\n",
              http_uri_string(msg->uri));

        return -100;
    }

    /* 301/302 response may redirect to another origin server.
       msg->pcon is connected to original server and not used to send the msg */

    msg->GetResHdrP(msg, "Location", 8, &p, &len);
    if (!p || len < 1) {
        tolog(1, "eJet - Redirect: invalid Location returned from request '%s'.\n",
              http_uri_string(msg->uri));

        return -100;
    }
 
    if (strncasecmp(p, "http://", 7) != 0 &&
        strncasecmp(p, "https://", 8) != 0 &&
        *p != '/')
    {
        uri = frame_new(512);
        frame_put_nlast(uri, msg->uri->baseuri, msg->uri->baseurilen);
        if (frame_read(uri, frameL(uri)-1) != '/')
            frame_put_last(uri, '/');
        frame_put_nlast(uri, p, len);

        msg->SetURL(msg, frameP(uri), frameL(uri), 1);
        frame_free(uri);
    } else {
        msg->SetURL(msg, p, len, 1);
    }

    msg->dstport = msg->req_port;
 
    /* the original Cookie should be removed before encoding */
    http_header_del(msg, 0, "Cookie", -1);

    http_chunk_zero(msg->req_chunk);
    chunk_zero(msg->req_body_chunk);
 
    while (arr_num(msg->req_rcvs_list) > 0)
        frame_free(arr_pop(msg->req_rcvs_list));
    arr_zero(msg->req_rcvs_list);

    http_msg_init_res(msg);

    /* detach the msg from original httpcon */
    pcon = msg->pcon;
    http_con_msg_del(msg->pcon, msg);
    if (pcon) {
        /* debug http_con on 2020-10-20 */
        http_con_close(pcon);
    }

    http_req_encoding(msg, 1);
    msg->issued = 1;
 
    chunk_set_end(msg->req_body_chunk);

    if (http_srv_msg_dns(msg, http_srv_msg_dns_cb) < 0) {
        http_msg_close(msg);
        return -200;
    }

    return 0;
}
 
 
int do_http_request (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    char    * fname = NULL;
    char    * mime = NULL;
 
    if (!msg) return -1;
 
    if (msg->req_body_flag == BC_CONTENT_LENGTH) {
 
        if (http_header_get(msg, 0, "Content-Type", -1) == NULL) {
 
            if (chunk_is_file(msg->req_body_chunk, NULL, NULL, NULL, &fname)) {
 
                mime = http_get_mime(msg->httpmgmt, fname, NULL);
                msg->SetReqContentType(msg, mime, strlen(mime));
 
            } else {
                msg->SetReqContentType(msg, "application/octet-stream", -1);
            }
        }
    }
 
    http_req_encoding(msg, 1);
    msg->issued = 1;
 
    chunk_set_end(msg->req_body_chunk);

    /* store current threadid as workerid, in order to set workerid for
       new-created TCP iodev_t, assuring that ePump IO events delivered
       to current worker thread. */
    msg->workerid = get_threadid();

    if (http_srv_msg_dns(msg, http_srv_msg_dns_cb) < 0) {
        http_msg_close(msg);
        return -100;
    }

    return 0;
}
 
void * do_http_get_msg (void * vmgmt, char * url, int urllen,
                        void * resfunc, void * para, void * cbval,
                        void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                        char * resfile, long resoff)
{
    HTTPMgmt     * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg      * msg = NULL;
 
    if (!mgmt || !url) return NULL;
    if (urllen < 0) urllen = strlen(url);
    if (urllen < 8) return NULL;
 
    msg = http_msg_fetch(mgmt);
    if (!msg) return NULL;
 
    msg->SetMethod(msg, "GET", 3);
    msg->SetURL(msg, url, urllen, 1);
 
    str_secpy(msg->req_ver, sizeof(msg->req_ver)-1, "HTTP/1.1", 8);
    msg->req_ver_major = 1;
    msg->req_ver_minor = 1;

    msg->req_body_flag = BC_NONE;
 
    msg->dstport = msg->req_port;
 
    msg->SetResponseNotify(msg, resfunc, para, cbval, resfile, resoff,
                           rcvprocfunc, rcvpara, rcvcbval);
 
    http_header_append(msg, 0, "Accept", -1, hdr_accept, strlen(hdr_accept));
    http_header_append(msg, 0, "Accept-Charset", -1, hdr_accept_charset, strlen(hdr_accept_charset));
    http_header_append(msg, 0, "Accept-Language", -1, hdr_accept_lang, strlen(hdr_accept_lang));
    http_header_append(msg, 0, "Connection", -1, "keep-alive", -1);
    http_header_append(msg, 0, "User-Agent", -1, mgmt->useragent, strlen(mgmt->useragent));
 
    return msg;
}
 
 
void * do_http_get (void * vmgmt, char * url, int urllen,
                    void * resfunc, void * para, void * cbval,
                    void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                    char * resfile, long resoff)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg  * msg = NULL;
 
    if (!mgmt) return NULL;
 
    msg = do_http_get_msg(mgmt, url, urllen, resfunc, para, cbval,
                          rcvprocfunc, rcvpara, rcvcbval, resfile, resoff);
    if (!msg) return NULL;
 
    if (do_http_request(msg) < 0) {
        http_msg_close(msg);
        msg = NULL;
    }
 
    return msg;
}
 
void * do_http_post_msg (void * vmgmt, char * url, int urllen, char * mime,
                         char * body, int bodylen,
                         char * fname, long offset, long length,
                         void * resfunc, void * para, void * cbval,
                         void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                         void * sndprocfunc, void * sndpara, uint64 sndcbval,
                         char * resfile, long resoff)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg  * msg = NULL;
 
    if (!mgmt || !url) return NULL;
    if (urllen < 0) urllen = strlen(url);
    if (urllen < 8) return NULL;
    if (body && bodylen < 0) bodylen = strlen(body);
 
    msg = http_msg_fetch(mgmt);
    if (!msg) return NULL;
 
    if ((body && bodylen > 0) || (fname && strlen(fname) > 0)) {
        if (msg->req_body_chunk == NULL) {
            msg->req_body_chunk = chunk_new(8192);
        }
        chunk_zero(msg->req_body_chunk);

        msg->req_body_flag = BC_CONTENT_LENGTH;
    }
 
    msg->SetMethod(msg, "POST", 4);
    msg->SetURL(msg, url, urllen, 1);
 
    str_secpy(msg->req_ver, sizeof(msg->req_ver)-1, "HTTP/1.1", 8);
    msg->req_ver_major = 1;
    msg->req_ver_minor = 1;

    msg->req_body_flag = BC_CONTENT_LENGTH;
 
    msg->dstport = msg->req_port;
 
    msg->SetResponseNotify(msg, resfunc, para, cbval, resfile, resoff,
                           rcvprocfunc, rcvpara, rcvcbval);
 
    http_header_append(msg, 0, "Accept", -1, hdr_accept, strlen(hdr_accept));
    http_header_append(msg, 0, "Accept-Charset", -1, hdr_accept_charset, strlen(hdr_accept_charset));
    http_header_append(msg, 0, "Accept-Language", -1, hdr_accept_lang, strlen(hdr_accept_lang));
    http_header_append(msg, 0, "Connection", -1, "keep-alive", -1);
 
    if (http_header_get(msg, 0, "User-Agent", -1) == NULL)
        http_header_append(msg, 0, "User-Agent", -1, mgmt->useragent, strlen(mgmt->useragent));
 
    if (body && bodylen > 0)
        msg->AddReqContent(msg, body, bodylen);
 
    if (fname && strlen(fname) > 0)
        msg->AddReqFile(msg, fname, offset, length);
 
    if (sndprocfunc) {
        msg->req_send_procnotify = sndprocfunc;
        msg->req_send_procnotify_para = sndpara;
        msg->req_send_procnotify_cbval = sndcbval;
    }
 
    if (mime) msg->SetReqContentType(msg, mime, strlen(mime));
 
    return msg;
}
 
void * do_http_post (void * vmgmt, char * url, int urllen, char * mime,
                     char * body, int bodylen,
                     char * fname, long offset, long length,
                     void * resfunc, void * para, void * cbval,
                     void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                     void * sndprocfunc, void * sndpara, uint64 sndcbval,
                     char * resfile, long resoff)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg  * msg = NULL;
 
    if (!mgmt) return NULL;
 
    msg = do_http_post_msg(mgmt, url, urllen, mime, body, bodylen,
                           fname, offset, length,
                           resfunc, para, cbval,
                           rcvprocfunc, rcvpara, rcvcbval,
                           sndprocfunc, sndpara, sndcbval,
                           resfile, resoff);
    if (!msg) return NULL;
 
    if (do_http_request(msg) < 0) {
        http_msg_close(msg);
        msg = NULL;
    }
 
    return msg;
}

