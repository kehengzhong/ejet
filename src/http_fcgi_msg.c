/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "http_mgmt.h"
#include "http_msg.h"
#include "http_header.h"
#include "http_chunk.h"
#include "http_variable.h"

#include "http_fcgi_srv.h"
#include "http_fcgi_con.h"
#include "http_fcgi_msg.h"
 

int fcgi_header_type_valid (uint8 type, int resp)
{
    if (!resp) {
        switch (type) {
        case FCGI_BEGIN_REQUEST:
        case FCGI_ABORT_REQUEST:
        case FCGI_PARAMS:
        case FCGI_STDIN:
        case FCGI_GET_VALUES:
        case FCGI_UNKNOWN_TYPE:
            return 1;
        default:
            return 0;
        }
    }

    switch (type) {
    case FCGI_END_REQUEST:
    case FCGI_STDOUT:
    case FCGI_STDERR:
    case FCGI_GET_VALUES_RESULT:
    case FCGI_UNKNOWN_TYPE:
        return 1;
    default:
        return 0;
    }

    return 0;
}

int fcgi_header_decode (void * p, int len, FcgiHeader * hdr)
{
    uint8  * pbyte = (uint8 *)p;
    int      i = 0;
    uint16   val = 0;

    if (!pbyte) return -1;
    if (len < 8) return -2;
    if (!hdr) return -3;

    hdr->version = pbyte[i++];
    hdr->type = pbyte[i++];

    val = pbyte[i++];
    val <<= 8;
    val += pbyte[i++];
    hdr->reqid = val;

    val = pbyte[i++];
    val <<= 8;
    val += pbyte[i++];
    hdr->contlen = val;

    hdr->padding = pbyte[i++];
    hdr->reserved = pbyte[i++];

    return i;
}


int http_fcgimsg_cmp_fcgimsg (void * a, void *b)
{
    FcgiMsg  * msga = (FcgiMsg *)a;
    FcgiMsg  * msgb = (FcgiMsg *)b;

    if (!msga) return -1;
    if (!msgb) return 1;

    return msga->msgid - msgb->msgid;
}

int http_fcgimsg_cmp_msgid (void * a, void *b)
{
    FcgiMsg  * msg = (FcgiMsg *)a;
    uint16     msgid = *(uint16 *)b;

    return msg->msgid - msgid;
}

ulong http_fcgimsg_hash_msgid (void * key)
{
    ulong hash = *(uint16 *)key;

    return hash;
}
 

int http_fcgimsg_init (void * vmsg)
{
    FcgiMsg  * msg = (FcgiMsg *)vmsg;

    if (!msg) return -1;

    msg->msgid = 0;

    msg->httpmsg = NULL;

    msg->req_body_flag = 0;
    msg->req_body_length = 0;
    msg->req_body_iolen = 0;

    msg->req_stream_sent = 0;
    msg->reqsent = 0;

    if (msg->req_rcvs_list == NULL) {
        msg->req_rcvs_list = arr_new(4);
    }
    arr_zero(msg->req_rcvs_list);

    if (msg->req_body_chunk == NULL) {
        msg->req_body_chunk = chunk_new(8192);
    }
    chunk_zero(msg->req_body_chunk);

    msg->fcgi_role = FCGI_RESPONDER;
    msg->fcgi_keep_alive = 1; //1;

    if (msg->fcgi_request == NULL)
        msg->fcgi_request = frame_new(512);
    frame_empty(msg->fcgi_request);

    msg->req_header_length = 0;

    http_fcgimsg_stdin_init(msg);

    memset(msg->fcgi_abort, 0, sizeof(msg->fcgi_abort));

    msg->app_status = 0;
    msg->proto_status = 0;
    msg->got_all_header = 0;
    msg->got_end_request = 0;

    memset(&msg->cgihdr, 0, sizeof(msg->cgihdr));

    msg->conid = 0;
    msg->pcon = NULL;

    msg->stamp = time(&msg->createtime);

    return 0;
}

int http_fcgimsg_free (void * vmsg)
{
    FcgiMsg  * msg = (FcgiMsg *)vmsg;

    if (!msg) return -1;

    if (msg->req_rcvs_list) {
        arr_pop_free(msg->req_rcvs_list, frame_free);
        msg->req_rcvs_list = NULL;
    }

    if (msg->req_body_chunk) {
        chunk_free(msg->req_body_chunk);
        msg->req_body_chunk = NULL;
    }

    frame_delete(&msg->fcgi_request);

    return 0;
}

void * http_fcgimsg_fetch (void * vsrv)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    HTTPMgmt * mgmt = NULL;
    FcgiMsg  * msg = NULL;

    if (!srv) return NULL;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return NULL;

    msg = mpool_fetch(mgmt->fcgimsg_pool);
    if (!msg) {
        msg = kzalloc(sizeof(*msg));
        http_fcgimsg_init(msg);
    }

    msg->msgid = http_fcgisrv_get_msgid(srv);
    msg->srv = srv;

    http_fcgisrv_msg_add(srv, msg);

    return msg;
}

int http_fcgimsg_recycle (void * vmsg)
{
    FcgiMsg   * msg = (FcgiMsg *)vmsg;
    FcgiSrv   * srv = NULL;
    HTTPMgmt  * mgmt = NULL;

    if (!msg) return -1;

    srv = (FcgiSrv *)msg->srv;
    if (!srv) {
        return http_fcgimsg_free(msg);
    }

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) {
        return http_fcgimsg_free(msg);
    }

    while (arr_num(msg->req_rcvs_list) > 0)
        frame_free(arr_pop(msg->req_rcvs_list));
    arr_zero(msg->req_rcvs_list);

    chunk_zero(msg->req_body_chunk);

    frame_empty(msg->fcgi_request);

    mpool_recycle(mgmt->fcgimsg_pool, msg);

    return 0;
}

void * http_fcgimsg_open  (void * vsrv, void * vhttpmsg)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    HTTPMsg  * httpmsg = (HTTPMsg *)vhttpmsg;
    FcgiMsg  * msg = NULL;

    if (!srv || !httpmsg) return NULL;

    msg = http_fcgimsg_fetch(srv);
    if (!msg) return NULL;

    msg->httpmsg = httpmsg;

    msg->req_body_flag = httpmsg->req_body_flag;
    msg->req_body_length = httpmsg->req_body_length;
    msg->req_body_iolen = 0;

    msg->req_stream_sent = 0;
    msg->reqsent = 0;

    http_fcgimsg_request_encode(msg);
    http_fcgimsg_abort_encode(msg);

    chunk_prepend_bufptr(msg->req_body_chunk, frameP(msg->fcgi_request),
                         frameL(msg->fcgi_request), NULL, NULL, 1);

    return msg;
}

int http_fcgimsg_close (void * vmsg)
{
    FcgiMsg  * msg = (FcgiMsg *)vmsg;

    if (!msg) return -1;

    if (http_fcgisrv_msg_del(msg->srv, msg->msgid) != msg) {
        return -100;
    }

    return http_fcgimsg_recycle(msg);
}

int http_fcgimsg_abort (void * vmsg)
{
    FcgiMsg  * msg = (FcgiMsg *)vmsg;

    if (!msg) return -1;


    return 0;
}


void fcgi_header_encode (frame_p frm, uint8 type, uint16 reqid, uint16 contlen)
{
    uint8 padding = 0;

    frame_put_last(frm, FCGI_PROTO_VERSION);
    frame_put_last(frm, type);

    /* request id */
    frame_put_last(frm, ((reqid >> 8) & 0xFF));
    frame_put_last(frm, (reqid & 0xFF));

    /* content-length */
    frame_put_last(frm, ((contlen >> 8) & 0xFF));
    frame_put_last(frm, (contlen & 0xFF));

    padding = contlen % 8;
    if (padding > 0) padding = 8 - padding;
    frame_put_last(frm, padding);

    frame_put_last(frm, 0x00);
}

int fcgi_header_encode2(uint8 * pbyte, uint8 type, uint16 reqid, uint16 contlen)
{
    int   len = 0;
    uint8 padding = 0;
 
    pbyte[len++] = FCGI_PROTO_VERSION;
    pbyte[len++] = type;
 
    /* request id */
    pbyte[len++] = (reqid >> 8) & 0xFF;
    pbyte[len++] = reqid & 0xFF;
 
    /* content-length */
    pbyte[len++] = (contlen >> 8) & 0xFF;
    pbyte[len++] = contlen & 0xFF;
 
    padding = contlen % 8;
    if (padding > 0) padding = 8 - padding;
    pbyte[len++] = padding;
 
    pbyte[len++] = 0x00;
    return len;
}

void fcgi_param_header_copy (frame_p frm, void * pbyte, int len, int isname)
{
    int   i;
    uint8 * p = (uint8 *)pbyte;

    if (!p || len <= 0) return;

    for (i = 0; i < len; i++) {
        if (isname) {
            if (p[i] == '-')
                frame_put_last(frm, '_');
            else
                frame_put_last(frm, adf_toupper(p[i]));

        } else {
                frame_put_last(frm, p[i]);
        }
    }
}

void fcgi_param_nvlen_encode (frame_p frm, int len)
{
    if (len < 0x80) {
        frame_put_last(frm, (uint8)len);
    } else {
        frame_put_last(frm, (uint8)( (len >> 24) | 0x80 ) );
        frame_put_last(frm, (uint8)(len >> 16));
        frame_put_last(frm, (uint8)(len >> 8));
        frame_put_last(frm, (uint8)len);
    }
}

void fcgi_http_header_param_encode (frame_p frm, HTTPMsg * httpmsg)
{
    int          i, num;
    HeaderUnit * punit = NULL;
    char         key[168];

    strcpy(key, "HTTP_");

    num = arr_num(httpmsg->req_header_list);
    for (i = 0; i < num; i++) {
        punit = (HeaderUnit *)arr_value(httpmsg->req_header_list, i);
        if (!punit || !punit->name || punit->namelen < 1) {
            continue;
        }

        str_secpy(key + 5, sizeof(key) - 6, HUName(punit), punit->namelen);

        fcgi_param_nvlen_encode(frm, punit->namelen + 5);
        fcgi_param_nvlen_encode(frm, punit->valuelen);
        fcgi_param_header_copy(frm, key, punit->namelen + 5, 1);
        fcgi_param_header_copy(frm, HUValue(punit), punit->valuelen, 0);
    }
}

void fcgi_predefined_param_encode (frame_p frm, HTTPMsg * httpmsg)
{
    HTTPMgmt  * mgmt = NULL;
    int         i, num, ret;
    void      * jpara = NULL;

    char      * name = NULL;
    int         namelen = 0;
    char      * value = NULL;
    int         valuelen = 0;
    char        buf[512];

    if (!httpmsg) return;

    mgmt = (HTTPMgmt *)httpmsg->httpmgmt;
    if (!mgmt) return;

    ret = json_mget_obj(mgmt->cnfjson, "http.fastcgi.params", -1, &jpara);
    if (ret <= 0 || !jpara) return;

    num = json_num(jpara);
    for (i = 0; i < num; i++) {
         ret = json_iter(jpara, i, 0, (void **)&name, &namelen, (void **)&value, &valuelen, NULL);
         if (ret < 0) continue;

         if (!name || namelen <= 0) continue;

         if (strcasecmp(name, "Content_Length") == 0) {
             if (httpmsg->req_body_length == 0) {
                 buf[0] = '\0';
                 valuelen = 0;
             } else {
#if defined(_WIN32) || defined(_WIN64)
                 sprintf(buf, "%I64d", httpmsg->req_body_length);
#else
                 sprintf(buf, "%lld", httpmsg->req_body_length);
#endif
                 valuelen = strlen(buf);
             }

         } else  {
             if (value && valuelen) {
                 valuelen = http_var_copy(httpmsg, value, valuelen, buf, sizeof(buf)-1,
                                          NULL, 0, NULL, 0);
             }
         }

        fcgi_param_nvlen_encode(frm, namelen);
        fcgi_param_nvlen_encode(frm, valuelen);
        fcgi_param_header_copy(frm, name, namelen, 1);
        fcgi_param_header_copy(frm, buf, valuelen, 0);
    }

    return;
}

int http_fcgimsg_request_encode (void * vmsg)
{
    FcgiMsg  * msg = (FcgiMsg *)vmsg;
    int        para_pos = 0;
    int        body_pos = 0;
    int        paralen = 0;
    int        padding = 0;

    if (!msg) return -1;

    /* encode begin-request header */
    fcgi_header_encode(msg->fcgi_request, FCGI_BEGIN_REQUEST, 0x01/*msg->msgid*/, 8);

    /* encode begin-request body */
    frame_put_last(msg->fcgi_request, ((msg->fcgi_role >> 8) & 0xFF));
    frame_put_last(msg->fcgi_request, (msg->fcgi_role & 0xFF));
    if (msg->fcgi_keep_alive) 
        frame_put_last(msg->fcgi_request, 0x01);
    else
        frame_put_last(msg->fcgi_request, 0x00);
    frame_append_nbytes(msg->fcgi_request, 0x00, 5);

    para_pos = frameL(msg->fcgi_request);

    /* reserved 8 bytes for FCGI-PARAM header */
    frame_append_nbytes(msg->fcgi_request, 0x00, 8);

    /* predefined PARAMs in configuration file encoded as FCGI_PARAM body */
    fcgi_predefined_param_encode(msg->fcgi_request, msg->httpmsg);

    /* HTTPMsg header encoded as FCGI_PARAM body */
    fcgi_http_header_param_encode(msg->fcgi_request, msg->httpmsg);

    body_pos = frameL(msg->fcgi_request) - 8;
    paralen = body_pos - para_pos;

    padding = paralen % 8;
    if (padding > 0) padding = 8 - padding;
    frame_append_nbytes(msg->fcgi_request, 0x00, padding);

    /* re-encoded the FCGI_PARAMS header based on the actual PARAMS body length */
    fcgi_header_encode2((uint8 *)frameP(msg->fcgi_request) + para_pos, FCGI_PARAMS, 1/*msg->msgid*/, paralen);

    /* encode one 0-body_length FCGI_PARAMS headers */
    fcgi_header_encode(msg->fcgi_request, FCGI_PARAMS, /*msg->msgid*/1, 0);

    msg->req_header_length = frameL(msg->fcgi_request);

    return msg->req_header_length;
}

int http_fcgimsg_abort_encode (void * vmsg)
{
    FcgiMsg  * msg = (FcgiMsg *)vmsg;

    if (!msg) return -1;

    return fcgi_header_encode2(msg->fcgi_abort, FCGI_ABORT_REQUEST, /*msg->msgid*/1, 0);
}


void fcgi_stdin_encode (frame_p frm, uint16 msgid, HTTPMsg * httpmsg)
{
    static int  MAXCONT = 65528; //8-byte alignment assuring that no padding is appended
    int64       len = 0;
    int64       pos = 0;
    int         i, num = 0;
    uint16      contlen = 0;
    uint8     * pbody = NULL;

    pbody = frameP(httpmsg->req_body_stream);

    len = httpmsg->req_body_length;
    num = (len + MAXCONT - 1) / MAXCONT;

    for (i = 0; i < num; i++) {
        if (i == num - 1) contlen = len % MAXCONT;
        else contlen = MAXCONT;

        fcgi_header_encode(frm, FCGI_STDIN, msgid, contlen);
        frame_put_nlast(frm, pbody + pos, contlen);

        pos += contlen;
    }

    fcgi_header_encode(frm, FCGI_STDIN, msgid, 0);
}

int http_fcgimsg_stdin_init (void * vmsg)
{
    FcgiMsg  * msg = (FcgiMsg *)vmsg;

    if (!msg) return -1;

    msg->fcgi_stdin_num = 0;
    memset(msg->fcgi_stdin_header, 0, sizeof(msg->fcgi_stdin_header));
    memset(msg->fcgi_stdin_body, 0, sizeof(msg->fcgi_stdin_body));
    memset(msg->fcgi_stdin_body_len, 0, sizeof(msg->fcgi_stdin_body_len));

    memset(msg->fcgi_stdin_padding, 0, sizeof(msg->fcgi_stdin_padding));
    memset(msg->fcgi_stdin_padding_len, 0, sizeof(msg->fcgi_stdin_padding_len));

    return 0;
}

int http_fcgimsg_stdin_encode (void * vmsg, void * pbyte, int bytelen, int end)
{
    FcgiMsg    * msg = (FcgiMsg *)vmsg;
    static int   MAXCONT = 65528; //8-byte alignment assuring that no padding is appended
    static uint8 padarr[8] = {0};
    int          i, pos = 0;
    int          num = 0;
    uint16       contlen = 0;
    int          padding = 0;

    if (!msg) return -1;

    num = (bytelen + MAXCONT - 1) / MAXCONT;
 
    for (i = 0, pos = 0; i < num && msg->fcgi_stdin_num < 32; i++) {
        if (i == num - 1) contlen = bytelen % MAXCONT;
        else contlen = MAXCONT;
 
        fcgi_header_encode2(msg->fcgi_stdin_header[msg->fcgi_stdin_num], FCGI_STDIN, /*msg->msgid*/1, contlen);

        msg->fcgi_stdin_body_len[msg->fcgi_stdin_num] = contlen;
        msg->fcgi_stdin_body[msg->fcgi_stdin_num] = (uint8 *)pbyte + pos;

        padding = contlen % 8;
        if (padding > 0) padding = 8 - padding;
        msg->fcgi_stdin_padding_len[msg->fcgi_stdin_num] = padding;
        msg->fcgi_stdin_padding[msg->fcgi_stdin_num] = padarr;

        msg->fcgi_stdin_num++;
 
        pos += contlen;
    }
 
    if (end) 
        http_fcgimsg_stdin_end_encode(msg);

    return pos;
}

int http_fcgimsg_stdin_end_encode (void * vmsg)
{
    FcgiMsg    * msg = (FcgiMsg *)vmsg;

    if (!msg) return -1;

    fcgi_header_encode2(msg->fcgi_stdin_header[msg->fcgi_stdin_num], FCGI_STDIN, /*msg->msgid*/1, 0);
    msg->fcgi_stdin_body_len[msg->fcgi_stdin_num] = 0;
    msg->fcgi_stdin_body[msg->fcgi_stdin_num] = NULL;
    msg->fcgi_stdin_num++;

    return 0;
}

int http_fcgimsg_stdin_body_sentnum (void * vmsg, int sentlen)
{
    FcgiMsg * msg = (FcgiMsg *)vmsg;
    int       i = 0;
    int       sentbody = 0;
    int       acclen = 0;

    if (!msg) return 0;

    for (i = 0, sentbody = 0; i < msg->fcgi_stdin_num; i++) {
        acclen += 8;  //header length 8 bytes
        if (acclen >= sentlen) return sentbody;

        acclen += msg->fcgi_stdin_body_len[i];
        if (acclen >= sentlen) {
            sentbody += msg->fcgi_stdin_body_len[i] - (acclen - sentlen);
            return sentbody;
        }
        sentbody += msg->fcgi_stdin_body_len[i];

        acclen += msg->fcgi_stdin_padding_len[i]; 
        if (acclen >= sentlen) return sentbody;
    }

    return sentbody;
}

int http_fcgimsg_pre_crash (void * vmsg, int status)
{
    FcgiMsg    * msg = (FcgiMsg *)vmsg;
    HTTPMsg    * httpmsg = NULL;

    if (!msg) return -1;
    if (!msg->httpmsg) return -2;

    httpmsg = (HTTPMsg *)msg->httpmsg;

    if (!msg->got_end_request && !httpmsg->issued) {
        httpmsg->fastcgi = 0;
        httpmsg->fcgimsg = NULL;

        httpmsg->SetStatus(httpmsg, status, NULL);
        httpmsg->Reply(httpmsg);
    }

    msg->httpmsg = NULL;

    return 0;
}


int http_fcgimsg_stdin_encode_chunk (void * vmsg, void * pbyte, int bytelen, void * porig, int end)
{
    FcgiMsg    * msg = (FcgiMsg *)vmsg;
    static int   MAXCONT = 65528; //8-byte alignment assuring that no padding is appended
    static uint8 padarr[8] = {0};
    uint8        hdrbuf[16];
    int          i, pos = 0;
    int          num = 0;
    uint16       contlen = 0;
    int          padding = 0;
 
    if (!msg) return -1;
 
    num = (bytelen + MAXCONT - 1) / MAXCONT;
 
    for (i = 0, pos = 0; i < num; i++) {
        if (i == num - 1) contlen = bytelen % MAXCONT;
        else contlen = MAXCONT;
 
        fcgi_header_encode2(hdrbuf, FCGI_STDIN, /*msg->msgid*/1, contlen);
        chunk_add_buffer(msg->req_body_chunk, hdrbuf, 8);

        chunk_add_bufptr(msg->req_body_chunk, (uint8 *)pbyte + pos, contlen, porig, NULL);
 
        padding = contlen % 8;
        if (padding > 0) padding = 8 - padding;
        chunk_add_buffer(msg->req_body_chunk, padarr, padding);
 
        pos += contlen;
    }
 
    if (end)
        http_fcgimsg_stdin_end_encode_chunk(msg);
 
    return pos;
}
 
int http_fcgimsg_stdin_end_encode_chunk (void * vmsg)
{
    FcgiMsg    * msg = (FcgiMsg *)vmsg;
    uint8        hdrbuf[16];
 
    if (!msg) return -1;
 
    fcgi_header_encode2(hdrbuf, FCGI_STDIN, /*msg->msgid*/1, 0);
    chunk_add_buffer(msg->req_body_chunk, hdrbuf, 8);

    /* set the current size as the end-size of chunk object */
    chunk_set_end(msg->req_body_chunk);

    return 0;
}
 
