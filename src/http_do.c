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
        uri = frame_alloc(512, msg->alloctype, msg->kmemblk);
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
        http_con_close(msg->httpmgmt, msg->conid);
    }

    http_req_build(msg, 1);
    msg->req_encoded = 1;
 
    chunk_set_end(msg->req_body_chunk);

    return http_srv_msg_send(msg);
}
 
 
int http_net_active (void * vmgmt, int oldstate)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv    * srv = NULL;
    int          i, num;
    rbtnode_t  * rbtn = NULL;
    int          nolinked = 0;
    int          linked = 0;
 
    if (!mgmt) return oldstate;
 
    EnterCriticalSection(&mgmt->srvCS);
 
    num = rbtree_num(mgmt->srv_tree);
    rbtn = rbtree_min_node(mgmt->srv_tree);
 
    for (i = 0; i < num && rbtn; i++) {
        srv = (HTTPSrv *)RBTObj(rbtn);
        rbtn = rbtnode_next(rbtn);
        if (!srv) continue;
 
        if (srv->active)
            linked++;
        else if (!srv->active)
            nolinked++;
    }
 
    LeaveCriticalSection(&mgmt->srvCS);
 
    if (nolinked > 0) return 0;
    if (linked > 0) return 1;
 
    return oldstate;
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
 
    http_req_build(msg, 1);
    msg->req_encoded = 1;
 
    chunk_set_end(msg->req_body_chunk);

    /* The R/W events generated by the newly created HTTPCon for sending the current
       HTTPMsg will be dispatched to the current worker thread for processing. Store
       the current threadid in msg->workerid, so that the workerid of the iodev_t
       device of the subsequently created HTTPCon will be set to msg->workerid */
    msg->workerid = get_threadid();

    return http_srv_msg_send(msg);
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
 
 
void * load_http_get_msg (void * vmgmt, char * url, int urllen,
                        void * resfunc, void * para, void * cbval,
                        void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                        char * resfile, long resoff, uint64 start, uint64 size,
                        char * route, char * opaque)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg  * msg = NULL;
    char       buf[512];
    char     * agent = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36";
 
 
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
    //http_header_append(msg, 0, "User-Agent", -1, mgmt->useragent, strlen(mgmt->useragent));
    http_header_append(msg, 0, "User-Agent", -1, agent, strlen(agent));
 
#if defined(_WIN32) || defined(_WIN64)
    sprintf(buf, "bytes=%I64u-%I64u", start, start+size);
#else
    sprintf(buf, "bytes=%llu-%llu", start, start+size);
#endif
    http_header_append(msg, 0, "Range", -1, buf, strlen(buf));
 
    if (route) http_header_append(msg, 0, "Route-Via", -1, route, strlen(route));
    if (opaque) http_header_append(msg, 0, "OriginNode", -1, opaque, strlen(opaque));
 
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
        msg = NULL;
    }
 
    return msg;
}
 
void * origin_http_get (void * vmgmt, char * url, int urllen,
                        void * resfunc, void * para, void * cbval,
                        void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                        char * resfile, long resoff, uint64 start,
                        uint64 size, char * route, char * opaque)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg  * msg = NULL;
 
    if (!mgmt) return NULL;
 
    msg = load_http_get_msg(mgmt, url, urllen, resfunc, para, cbval,
                            rcvprocfunc, rcvpara, rcvcbval,
                            resfile, resoff, start, size, route, opaque);
    if (!msg) return NULL;
 
    if (do_http_request(msg) < 0) {
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
            msg->req_body_chunk = chunk_alloc(8192, msg->alloctype, msg->kmemblk);
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
        msg = NULL;
    }
 
    return msg;
}


void * do_http_connect_msg (void * vmgmt, char * url, int urllen,
                        void * resfunc, void * para, void * cbval,
                        void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                        char * resfile, long resoff)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg  * msg = NULL;

    if (!mgmt || !url) return NULL;
    if (urllen < 0) urllen = strlen(url);
    if (urllen < 8) return NULL;

    msg = http_msg_fetch(mgmt);
    if (!msg) return NULL;

    msg->SetMethod(msg, "CONNECT", 7);
    msg->SetURL(msg, url, urllen, 1);

    str_secpy(msg->req_ver, sizeof(msg->req_ver)-1, "HTTP/1.1", 8);
    msg->req_ver_major = 1;
    msg->req_ver_minor = 1;

    msg->req_body_flag = BC_NONE;

    msg->SetResponseNotify(msg, resfunc, para, cbval, resfile, resoff,
                           rcvprocfunc, rcvpara, rcvcbval);

    http_header_append(msg, 0, "Connection", -1, "keep-alive", -1);
    http_header_append(msg, 0, "Proxy-Connection", -1, "keep-alive", -1);
    http_header_append(msg, 0, "User-Agent", -1, mgmt->useragent, strlen(mgmt->useragent));

    return msg;
}

