/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_FASTCGI_MSG_H_
#define _HTTP_FASTCGI_MSG_H_

#include "http_msg.h"
#include "http_fcgi_srv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* About specification of FastCGI, please refer to 
   http://www.mit.edu/~yandros/doc/specs/fcgi-spec.html */

#define FCGI_PROTO_VERSION       0x01
#define FCGI_CONTENT_MAX         65535

/* Values for type component of FCGI_Header */
#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE            (FCGI_UNKNOWN_TYPE)


/* Values for role component of FCGI_BeginRequestBody */
#define FCGI_RESPONDER           1
#define FCGI_AUTHORIZER          2
#define FCGI_FILTER              3

/* Values for protocolStatus component of FCGI_EndRequestBody */
#define FCGI_REQUEST_COMPLETE    0
#define FCGI_CANT_MPX_CONN       1
#define FCGI_OVERLOADED          2
#define FCGI_UNKNOWN_ROLE        3

/* Variable names for FCGI_GET_VALUES / FCGI_GET_VALUES_RESULT records */
#define FCGI_MAX_CONNS      "FCGI_MAX_CONNS"
#define FCGI_MAX_REQS       "FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS     "FCGI_MPXS_CONNS"


typedef struct fastcgi_header {
    uint8           version;
    uint8           type;
    uint16          reqid;
    uint16          contlen;
    uint8           padding;
    uint8           reserved;

    /* parsing state of receiving FastCGI stream */
    uint8           wait_more_data;
    uint16          data_to_read;
    uint16          body_to_read;
    uint8           padding_to_read;

} FcgiHeader, fcgi_header_t;


typedef struct fastcgi_msg_s {

    uint16            msgid;

    HTTPMsg         * httpmsg;

    int               req_body_flag;   //BC_CONTENT_LENGTH or BC_TE
    int64             req_body_length;
    int64             req_body_iolen;
 
    int64             req_stream_sent; //total sent length including header and body
    uint8             reqsent;         //0-not sent or in sending  1-already sent
 
    /* by adopting zero-copy for higher performance, frame buffers of HTTPCon, which stores
       octets from sockets,  will be moved to following list, for further parsing or handling.
       the overhead of memory copy will be lessened significantly. */
    arr_t           * req_rcvs_list;
 
    /* the fragmented data blocks to be sent to CGI-Server are stored in chunk_t */
    chunk_t         * req_body_chunk;

    unsigned          fcgi_role       : 16;
    unsigned          fcgi_keep_alive : 1;

    /* encoded octent stream for fastcgi request :
        begin_request_header(01 01 00 01 00 08 00 00) (8 bytes)
        begin_request_body  (00 01 00 00 00 00 00 00) (8 bytes)

        fcgi_params_header  (01 04 00 01 XX XX YY 00) (8 bytes)
        ..................   (XXXX paralen bytes)
        padding 0            (YY bytes for 8-byte alignment)
        fcgi_params_header  (01 04 00 01 00 00 00 00) (8 bytes, 0-length params content)
     */
    frame_p           fcgi_request;

    int               req_header_length;


    /* if HTTP request body exists and body length is big enough, it may take 1 or more
        FCGI_STDIN requests that each body length is not greater than 65535. 
        we prepare at most 32 FCGI_STDIN for the segments of streamed HTTP request body.

        fcgi_stdin_header   (01 05 00 01 XX XX YY 00) (8 bytes, if exists request body )
        ..................   (content-length XXXX bytes's request body)
        padding 0            (YY bytes for 8-byte alignment)
        fcgi_stdin_header   (01 05 00 01 00 00 00 00) (8 bytes, 0-length stdin content)
     */
    int               fcgi_stdin_num;
    uint8             fcgi_stdin_header[32][8];
    uint8           * fcgi_stdin_body[32];
    int               fcgi_stdin_body_len[32];
    uint8           * fcgi_stdin_padding[32];
    int               fcgi_stdin_padding_len[32];

    /* encoded octent stream for fastcgi abort :
        abort request(01 02 00 01 00 00 00 00) (8 bytes)
     */
    uint8             fcgi_abort[8];

    /* received octet stream from cgi-server:
        fcgi_stdout_header  (01 06 00 01 XX XX YY 00) (8 bytes)
        .................    (content-length XXXX bytes' response header and body)
        padding 0            (YY bytes fro 8-byte alignment)
        end request header  (01 03 00 01 00 08 00 00) (8 bytes)
        end request body    (00 00 00 00 00 08 00 00) (8 bytes)
     */
    uint32            app_status;
    uint8             proto_status;
    uint8             got_all_header;
    uint8             got_end_request;

    FcgiHeader        cgihdr;

    ulong             conid;
    void            * pcon;

    time_t            createtime;
    time_t            stamp;

    FcgiSrv         * srv;

} FcgiMsg, fcgi_msg_t;


int    fcgi_header_type_valid (uint8 type, int resp);
int    fcgi_header_decode (void * p, int len, FcgiHeader * hdr);

int    http_fcgimsg_cmp_fcgimsg (void * a, void *b);
int    http_fcgimsg_cmp_msgid   (void * a, void *b);
ulong  http_fcgimsg_hash_msgid  (void * key);

int    http_fcgimsg_init    (void * vmsg);
int    http_fcgimsg_free    (void * vmsg);

void * http_fcgimsg_fetch   (void * vsrv);
int    http_fcgimsg_recycle (void * vmsg);

void * http_fcgimsg_open  (void * vsrv, void * vhttpmsg);
int    http_fcgimsg_close (void * vmsg);

int    http_fcgimsg_abort (void * vmsg);

int    http_fcgimsg_request_encode (void * vmsg);
int    http_fcgimsg_abort_encode   (void * vmsg);

int    http_fcgimsg_stdin_init         (void * vmsg);
int    http_fcgimsg_stdin_encode       (void * vmsg, void * pbyte, int bytelen, int end);
int    http_fcgimsg_stdin_end_encode   (void * vmsg);
int    http_fcgimsg_stdin_body_sentnum (void * vmsg, int sentlen);

int http_fcgimsg_pre_crash (void * vmsg, int status);

int http_fcgimsg_stdin_encode_chunk     (void * vmsg, void * pbyte, int bytelen, void * porig, int end);
int http_fcgimsg_stdin_end_encode_chunk (void * vmsg);

#ifdef __cplusplus
}
#endif

#endif

