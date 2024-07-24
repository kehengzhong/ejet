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

#ifndef _HTTP_MSG_H_
#define _HTTP_MSG_H_

#include "http_uri.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int RecvAllNotify  (void * vmsg, void * para, void * cbval, int status);
typedef int TearDownNotify (void * vmsg, void * para);


#define REUSE_BUF_THRESHOLD  64*1024

/* HTTP Method Constants Definition */
#define HTTP_METHOD_NONE       0
#define HTTP_METHOD_CONNECT    1
#define HTTP_METHOD_DELETE     2
#define HTTP_METHOD_GET        3
#define HTTP_METHOD_HEAD       4
#define HTTP_METHOD_VERSION_10 5
#define HTTP_METHOD_VERSION_11 6
#define HTTP_METHOD_OPTIONS    7
#define HTTP_METHOD_POST       8
#define HTTP_METHOD_PUT        9
#define HTTP_METHOD_TRACE      10


/* how to count or recognize the Request/Response Body Content
 * define several cases to identify the body */
#define BC_NONE            0
#define BC_CONTENT_LENGTH  1
#define BC_TE              2
#define BC_TE_INVALID      3
#define BC_UNKNOWN         4
#define BC_TUNNEL          5


/* HTTPMsg state definition when acting as HTTPServer, HTTPProxy, HTTPGateway */
#define HTTP_MSG_NULL                      0
#define HTTP_MSG_REQUEST_RECVING           1
#define HTTP_MSG_REQUEST_HANDLING          2
#define HTTP_MSG_REQUEST_HANDLED           3
#define HTTP_MSG_RESPONSE_SENDING          4
#define HTTP_MSG_REQUEST_SENDING           5
#define HTTP_MSG_REQUEST_SENT              6
#define HTTP_MSG_RESPONSE_RECVING          7
#define HTTP_MSG_RESPONSE_HANDLING         8
#define HTTP_MSG_OVER                      17

/* HTTPMsg state definition when acting as HTTPClient */
#define HTTP_MSG_SENDING                   10
#define HTTP_MSG_SENT                      11
#define HTTP_MSG_RECVING_RESP              12
#define HTTP_MSG_RECV_END                  13


/* http partial request header format as following: 
   Range: bytes=0-499  #given range from 0 to 499, total 500 bytes
   Range: bytes=500-   #given range from 500 to end, total bytes: size-500
   Range: bytes=-200   #indicate the last 200 bytes, total bytes: 200
   Range: bytes=500-550,601-999  #given 2 ranges, total bytes: 550-500+1 + 999-601+1
*/
typedef struct http_partial_s {
    /* 1 - bytes=0-499,700-900
       2 - bytes=500-
       3 - bytes=-200 
       0 - unknown     */
    uint8       partflag; 
    int64       start;
    int64       end;
    int64       length;
    int64       fsize;
} http_partial_t;


typedef struct http_msg {
    void             * res[2];

    void             * kmemblk;

    /* global unique identifier for HTTPMsg */
    ulong              msgid;
    uint8              msgtype  : 3;  /* 0-sending request  1-receiving request */
    uint8              recycled : 3;  /* 0-in use  1-recycled */
    uint8              alloctype: 2;  //0-default kalloc/kfree 1-os-specific malloc/free 2-kmempool alloc/free 3-kmemblk alloc/free 

    void             * hl;
    void             * hc;
    void             * phost;
    void             * ploc;
    int                locinst_times;

    void             * cbobj;

    hashtab_t        * script_var_tab;

    /* instanced variables from HTTPLoc, HTTPHost when HTTPMsg is created */
    int                matchnum;
    ckstr_t            matchstr[16];

    char             * root;

    /* current message handling state */
    int                state;
    btime_t            createtime;
    time_t             stamp;

    /* source address and destination address, IP:Port quadruple */
    char               srcip[41];
    int                srcport;
    char               dstip[41];
    int                dstport;

    uint8              ssl_link;

    /* The flag used to determine whether the current HTTP message is sent to the server. */
    uint8              reqsent : 4;

    /* eJet serves as web server, the flag indicates whether all data including the request
       header and body are received or not. */
    uint8              req_gotall_body: 4;

    uint8              redirecttimes;

    uint8              req_url_type;  //0-relative 1-absolute
    http_uri_t       * uri;
    http_uri_t       * absuri;
    http_uri_t       * docuri;
    uint64             pathhash;
    uint64             urihash;

    /* following variables hold information of HTTP request line. When serving as server,
       the values of these variables come from the decoding of the HTTP request line.
       When serving as a client, the caller assigns values to these variables and
       builds a request line based on them. */
    int                req_methind;
    char               req_meth[16];
    char               req_ver[16];
    int                req_ver_major;
    int                req_ver_minor;

    /* The following pointer and length variables are extracted from a certain position
       in the uri, and are used to quickly access various information contained in the URI. */
    char             * req_scheme;
    int                req_schemelen;
    char             * req_host;
    int                req_hostlen;
    uint16             req_port;
    char             * req_path;
    int                req_pathlen;
    char             * req_query;
    int                req_querylen;

    char             * req_line;
    int                req_line_len;
    char             * req_content_type;
    int                req_contype_len;
    char             * req_useragent;
    int                req_useragent_len;
    char             * req_cookie;
    int                req_cookie_len;

    /* The following variables are used to track the transfer and receive status of
       the HTTP request header and body */
    int64              req_header_length;
    int64              req_body_length;
    int64              req_body_iolen;

    /* The HTTP request message sent by the client consumes a certain amount of
       memory, no matter how big the message body is. When a certain threshold is
       exceeded, eJet uses a temporary cache file to store message body data. */
    uint8              req_multipart;
    uint8              req_file_cache;
    char             * req_file_name;
    void             * req_file_handle;

    /* 0-no body 1-Content-Length body 2-Transfer-Encoding body 3-Invalid Transfer-Encoding body
       4-Unknown format body 5-HTTP Tunnel*/
    uint8              req_body_flag;  

    uint8              req_conn_keepalive;

    /* When decoding HTTP request messages, HeaderUnit based on key-value structure
      is used to manage and store each request header and Cookie. Multiple request
      headers are organized and managed by hash table and dynamic array. */
    hashtab_t        * req_header_table;
    arr_t            * req_header_list;
    hashtab_t        * req_cookie_table;

    /* HTTP request is decoded into two parts: request header and request body. 
       The octet stream of request header is stored in req_header_stream, while
       the octet stream of request body is stored in req_body_stream. When the
       HTTP request is output, the request header and the request body are encoded
       and stored in the req_stream. */
    frame_p            req_header_stream;
    frame_p            req_body_stream;
    frame_p            req_stream;

    void             * req_chunk;
    chunk_t          * req_body_chunk;
    int64              req_stream_sent;
    int64              req_stream_recv;

    /* When eJet serves as a proxy or FastCGI gateway, the client may continuously send the
       request data in the form of stream, which needs to be forwarded to the origin server
       in real time. Zero copy technology for high performance is adopted to reduce the number
       of copies of data in memory. All the data sent by the client over the HTTP connection
       is stored in the rcvstream in HTTPCon object. When forwarded to the origin server, the
       rcvstream as a data buffer is moved away and stored in the req_rcvs_list list. It is
       not removed and released from the req_rcvs_list until the forwarding is successful. */
    arr_t            * req_rcvs_list;

    /* When the content type of HTTP Post message body is multi-part format, all parts of
       the content are parsed and stored in the following objects */
    arr_t            * req_formlist;
    void             * req_form_json;
    void             * req_form_kvobj;
    void             * req_query_kvobj;

    /* HTTPCon object instance used by HTTP read-write requests and responses, and worker
       threadid handling the read-write event. */
    void             * pcon;
    ulong              conid;
    ulong              workerid;

    /* redirect the request to a new URL with status code 302/301 */
    uint8              redirected;

    /* indicate current HTTPMsg is proxied to another origin server */
    uint8              proxied : 4;  //0-no proxy 1-original request  2-proxing request
    uint8              cacheon : 4;
    struct http_msg  * proxymsg;
    ulong              proxymsgid;

    /* indicate the msg is Fast-CGI to Fast-CGI Processor Manager server */
    uint8              fastcgi;  //0-no fastcgi 1-send to FastCGI server
    void             * fcgimsg;
    uint8              fcgi_resend;

    char             * fwdurl;
    int                fwdurllen;

    /* Determines whether the proxy is adopted when the current HTTPMsg is sent to the Origin server */
    char             * proxy;
    int                proxyport;

    //0-no partial,
    uint8              partial_flag;
    void             * partial_list;

    /* The value 1 of res_encoded flag means that both the response header and the response body of
       the HTTP request message have been collected and encoded into the output stream -> res_body_chunk. */
    uint8              flag304     : 4;   //not modified content, just return 304
    uint8              req_encoded : 2;
    uint8              res_encoded : 2;

    /* the first line of response contains following information. */
    char               res_ver[16];
    int                res_status;
    char               res_reason[36];

    char             * res_mime;
    uint32             res_mimeid;

    /* the number of header/body octets received from server or high layer */
    int64              res_header_length;
    int64              res_body_length;
    int64              res_body_iolen;

    /* In the proxy mode, the content returned from the origin server may be cached
       to serve the same subsequent HTTP request. Cache policy is decided by configuration
       file, which determines the location of content storage, cache file name, cache
       expiration, etc. */
    char             * res_file_name;
    void             * res_file_handle;

    uint8              res_file_cache;
    int64              cache_req_start;
    int64              cache_req_off;
    int64              cache_req_len;

    void             * res_cache_info;

    /* 0-no body 1-Content-Length body 2-Transfer-Encoding body 3-Invalid Transfer-Encoding body
       4-Unknown format body 5-HTTP Tunnel*/
    uint8              res_body_flag;  

    /* eJet serves as web client, the flag indicates whether all data including the response
       header and body are received or not. */
    uint8              res_gotall_body: 4;

    uint8              res_conn_keepalive : 4;

    /* Decoding the octet stream in res_header_stream generates all HTTP response headers
       encapsulated in HeaderUnits, which are managed by hash table and dynamic array. */
    hashtab_t        * res_header_table;
    arr_t            * res_header_list;

    /* frame_p is a dynamic memory management data structure. The upper layer callback
       module or origin server generates HTTP response header and body after completing
       handling. All HTTP response headers are managed by HeaderUnits which point to the
       actual data in res_header_stream. As a temporary cache, res_body_stream stores part
       response data. The HTTP response data stream returned to the client comes from
       res body chunk, whose first entity buffer, that is res_stream, contains all the
       encoded response headers and part or all of the response bodies. */
    frame_p            res_header_stream;
    frame_p            res_body_stream;
    frame_p            res_stream;

    /* The response bodies with various formats including memory buffers and files are decoded
       and stored in res_body_chunk. res_chunk is used to decode http chunk block. */
    void             * res_chunk;
    chunk_t          * res_body_chunk;
    int64              res_stream_sent;
    int64              res_stream_recv;

    /* The function of res_rcvs_list is the same as that of req_rcvs_list, except that the
       data flow is reversed.
       When eJet serves as a proxy or FastCGI gateway, the origin server may continuously reply
       response data in the form of stream, which needs to be forwarded to the client in real 
       time. Zero copy technology for high performance is adopted to reduce the number of copies
       of data in memory. All the data received from the origin over HTTP/FastCGI connection
       is stored in the rcvstream in HTTPCon/FcgiCon object. When forwarded to the client, the
       rcvstream as a data buffer is moved away and stored in the res_rcvs_list list. It is
       not removed and released from the res_rcvs_list until the forwarding is successful. */
    arr_t            * res_rcvs_list;


    /* system management instance */
    void             * httpsrv;
    void             * pcore;
    void             * httpmgmt;

    /* notify upper-layer application that TCP connection tears down */
    TearDownNotify   * tear_down_notify;
    void             * tear_down_para;

    RecvAllNotify    * resnotify;
    uint8              resnotify_called;
    void             * resnotify_para;
    void             * resnotify_cbval;

    char             * res_store_file;
    int64              res_store_offset;

    ProcessNotify    * res_recv_procnotify;
    void             * res_recv_procnotify_para;
    uint64             res_recv_procnotify_cbval;

    ProcessNotify    * req_send_procnotify;
    void             * req_send_procnotify_para;
    uint64             req_send_procnotify_cbval;


    int    (*SetTearDownNotify)(void * vmsg, void * func, void * para);
    int    (*SetResponseNotify)(void * vmsg, void * func, void * para, void * cbval,
                                char * storefile, int64 offset,
                                void * procnotify, void * notifypara, uint64 notifycbval);
    
    int    (*SetResStoreFile)      (void * vmsg, char * storefile, int64 offset);
    int    (*SetResRecvAllNotify)  (void * vmsg, void * func, void * para, void * cbval);
    int    (*SetResRecvProcNotify) (void * vmsg, void * procnotify, void * para, uint64 cbval); 
    int    (*SetReqSendProcNotify) (void * vmsg, void * procnotify, void * para, uint64 cbval); 

    char * (*GetMIME)        (void * vmsg, char * extname, uint32 * mimeid);
    void * (*GetMIMEMgmt)    (void * vmsg);

    void * (*GetEPump)       (void * vmsg);
    void * (*GetHTTPMgmt)    (void * vmsg);

    void * (*GetCBObj)       (void * vmsg);
    void * (*GetMgmtObj)     (void * vmsg);
    void * (*GetMsgObj)      (void * vmsg);
    void * (*GetIODev)       (void * vmsg);

    frame_p (*GetFrame)      (void * vmsg);
    int     (*RecycleFrame)  (void * vmsg, frame_p frame);

    void * (*Fetch)          (void * vmsg);
    int    (*Init)           (void * vmsg);
    int    (*InitReq)        (void * vmsg);
    int    (*InitRes)        (void * vmsg);
    int    (*Recycle)        (void * vmsg);
    int    (*Close)          (void * vmsg);

    int    (*CacheType)      (void * vmsg, int respornot);
    char * (*CacheFile)      (void * vmsg, int respornot);

    char * (*GetSrcIP)       (void * vmsg);
    int    (*GetSrcPort)     (void * vmsg);
    ulong  (*GetMsgID)       (void * vmsg);

    int    (*GetMethodInd)   (void * vmsg);
    char * (*GetMethod)      (void * vmsg);
    int    (*SetMethod)      (void * vmsg, char * meth, int methlen);

    char * (*GetURL)         (void * vmsg);
    int    (*SetURL)         (void * vmsg, char * url, int len, int decode);
    char * (*GetDocURL)      (void * vmsg);
    int    (*SetDocURL)      (void * vmsg, char * url, int len, int decode, int instbrk);

    int    (*GetBaseURL)     (void * vmsg, char ** p, int * plen);
    char * (*GetAbsURL)      (void * vmsg);
    char * (*GetRelativeURL) (void * vmsg);

    int    (*GetSchemeP)      (void * vmsg, char ** pscheme, int * plen);
    int    (*GetScheme)       (void * vmsg, char * pscheme, int len);
    int    (*GetHostP)        (void * vmsg, char ** phost, int * plen);
    int    (*GetHost)         (void * vmsg, char * phost, int len);
    int    (*GetPort)         (void * vmsg);

    char * (*GetRootPath)     (void * vmsg);

    int    (*GetPathP)        (void * vmsg, char ** ppath, int * plen);
    int    (*GetPath)         (void * vmsg, char * path, int len);
    int    (*GetPathOnly)     (void * vmsg, char * path, int len);
    int    (*GetFileOnly)     (void * vmsg, char * file, int len);
    int    (*GetFileExt)      (void * vmsg, char * fileext, int len);
    int    (*GetRealPath)     (void * vmsg, char * path, int len);
    int    (*GetRealFile)     (void * vmsg, char * path, int len);
    int    (*GetLocFile)      (void * vmsg, char * p, int len, char * f, int flen, char * d, int dlen);

    int    (*GetQueryP)       (void * vmsg, char ** pquery, int * plen);
    int    (*GetQuery)        (void * vmsg, char * query, int len);
    int    (*GetQueryValueP)  (void * vmsg, char * key, char ** pval, int * vallen);
    int    (*GetQueryValue)   (void * vmsg, char * key, char * val, int vallen);
    int    (*GetQueryUint)    (void * vmsg, char * key, uint32 * val);
    int    (*GetQueryInt)     (void * vmsg, char * key, int * val);
    int    (*GetQueryUlong)   (void * vmsg, char * key, ulong * val); 
    int    (*GetQueryLong)    (void * vmsg, char * key, long * val); 
    int    (*GetQueryInt64)   (void * vmsg, char * key, int64 * val);
    int    (*GetQueryUint64)  (void * vmsg, char * key, uint64 * val);
    int    (*GetQueryKeyExist)(void * vmsg, char * key);

    int    (*GetReqContentP)    (void * vmsg, void ** pform, int * plen);
    int    (*GetReqContent)     (void * vmsg, void * form, int len);

    int    (*GetReqFormJsonValueP)  (void * vmsg, char * key, char ** ppval, int * vallen);
    int    (*GetReqFormJsonValue)   (void * vmsg, char * key, char * pval, int vallen);
    int    (*GetReqFormJsonKeyExist)(void * vmsg, char * key);

    int    (*GetReqFormDecodeValue) (void * vmsg, char * key, char * pval, int vallen);

    int    (*GetReqFormValueP)  (void * vmsg, char * key, char ** ppval, int * vallen);
    int    (*GetReqFormValue)   (void * vmsg, char * key, char * pval, int vallen);
    int    (*GetReqFormUint)    (void * vmsg, char * key, uint32 * val);
    int    (*GetReqFormInt)     (void * vmsg, char * key, int * val);
    int    (*GetReqFormUlong)   (void * vmsg, char * key, ulong * val);
    int    (*GetReqFormLong)    (void * vmsg, char * key, long * val);
    int    (*GetReqFormUint64)  (void * vmsg, char * key, uint64 * val);
    int    (*GetReqFormKeyExist)(void * vmsg, char * key);

    int    (*GetReqHdrNum)      (void * vmsg);
    int    (*GetReqHdrIndP)     (void * vmsg, int i, char ** pn, int * nlen, char ** pv, int * vlen);
    int    (*GetReqHdrInd)      (void * vmsg, int i, char * pn, int nlen, char * pv, int vlen);
    int    (*GetReqHdrP)        (void * vmsg, char * n, int nlen, char ** pval, int * vlen);
    int    (*GetReqHdr)         (void * vmsg, char * name, int nlen, char * val, int vlen);

    int    (*GetReqHdrInt)      (void * vmsg, char * name, int namelen);
    long   (*GetReqHdrLong)     (void * vmsg, char * name, int namelen);
    ulong  (*GetReqHdrUlong)    (void * vmsg, char * name, int namelen);
    int64  (*GetReqHdrInt64)    (void * vmsg, char * name, int namelen);
    uint64 (*GetReqHdrUint64)   (void * vmsg, char * name, int namelen);

    int    (*GetReqContentTypeP)(void * vmsg, char ** ptype, int * typelen);
    int    (*GetReqContentType) (void * vmsg, char * type, int typelen);
    int    (*GetReqContentLength)(void * vmsg);
    int    (*GetReqEtag) (void * vmsg, char * etag, int etaglen);
    int    (*GetCookieP) (void * vmsg, char * name, int nlen, char ** pv, int * vlen);
    int    (*GetCookie)  (void * vmsg, char * name, int nlen, char * val, int vlen);

    int    (*ParseReqMultipartForm) (void * vmsg, arr_t * formdatalist);
    int    (*DisplayDirectory)      (void * vmsg);

    int    (*AddReqHdr)      (void * vmsg, char * na, int nlen, char * val, int vlen);
    int    (*AddReqHdrInt)   (void * vmsg, char * name, int namelen, int value);
    int    (*AddReqHdrUint32)(void * vmsg, char * name, int namelen, uint32 value);
    int    (*AddReqHdrLong)  (void * vmsg, char * name, int namelen, long value);
    int    (*AddReqHdrUlong) (void * vmsg, char * name, int namelen, ulong value);
    int    (*AddReqHdrInt64) (void * vmsg, char * name, int namelen, int64 value);
    int    (*AddReqHdrUint64)(void * vmsg, char * name, int namelen, uint64 value);
    int    (*AddReqHdrDate)  (void * vmsg, char * name, int namelen, time_t dtime);
    int    (*DelReqHdr)      (void * vmsg, char * name, int namelen);

    int    (*SetReqContentType)   (void * vmsg, char * type, int typelen);
    int    (*SetReqContentLength) (void * vmsg, int64 len);
    int    (*SetReqContent)       (void * vmsg, void * body, int bodylen);
    int    (*SetReqFileContent)   (void * vmsg, char * filename);

    int    (*AddReqContent)       (void * vmsg, void * body, int64 bodylen);
    int    (*AddReqContentPtr)    (void * vmsg, void * body, int64 bodylen);
    int    (*AddReqFile)          (void * vmsg, char * filename, int64 startpos, int64 len);
    int    (*AddReqAppCBContent)  (void * vmsg, void * prewrite, void * prewobj, int64 offset, int64 length,
                                   void * movefunc, void * movepara, void * endwrite, void * endwobj);

    int    (*GetStatus)         (void * vmsg, char * reason, int * reasonlen);
    int    (*GetResHdrNum)      (void * vmsg);
    int    (*GetResHdrIndP)     (void * vmsg, int i, char **pn, int * nlen, char **pv, int * vlen);
    int    (*GetResHdrInd)      (void * vmsg, int i, char *pn, int nlen, char *pv, int vlen);
    int    (*GetResHdrP)        (void * vmsg, char * n, int nlen, char ** pval, int * vlen);
    int    (*GetResHdr)         (void * vmsg, char * name, int nlen, char * val, int vlen);

    int    (*GetResHdrInt)      (void * vmsg, char * name, int namelen);
    long   (*GetResHdrLong)     (void * vmsg, char * name, int namelen);
    ulong  (*GetResHdrUlong)    (void * vmsg, char * name, int namelen);
    int64  (*GetResHdrInt64)    (void * vmsg, char * name, int namelen);
    uint64 (*GetResHdrUint64)   (void * vmsg, char * name, int namelen);

    int    (*GetResContentTypeP)(void * vmsg, char ** ptype, int * typelen);
    int    (*GetResContentType) (void * vmsg, char * type, int typelen);
    int    (*GetResContentTypeID)(void * vmsg, uint32 * mimeid, char ** pext);
    int64  (*GetResContentLength)(void * vmsg);

    int    (*GetResContent)  (void * vmsg, void * body, int bodylen);
    int    (*GetResContentP) (void * vmsg, int64 pos, void ** pbody, int64 * bodylen);

    int    (*SetStatus)      (void * vmsg, int code, char * reason);
    int    (*AddResHdr)      (void * vmsg, char * na, int nlen, char * val, int vlen);
    int    (*AddResHdrInt)   (void * vmsg, char * name, int namelen, int value);
    int    (*AddResHdrUint32)(void * vmsg, char * name, int namelen, uint32 value);
    int    (*AddResHdrLong)  (void * vmsg, char * name, int namelen, long value);
    int    (*AddResHdrUlong) (void * vmsg, char * name, int namelen, ulong value);
    int    (*AddResHdrInt64)(void * vmsg, char * name, int namelen, int64 value);
    int    (*AddResHdrUint64)(void * vmsg, char * name, int namelen, uint64 value);
    int    (*AddResHdrDate)  (void * vmsg, char * name, int namelen, time_t dtime);
    int    (*DelResHdr)      (void * vmsg, char * name, int namelen);

    int    (*SetResEtag) (void * vmsg, char * etag, int etaglen);
    int    (*SetCookie)  (void * vmsg, char * name, char * value, 
                             time_t expire, char * path, char * domain, uint8 secure);

    int    (*Check304Resp)        (void * vmsg, uint64 mediasize, time_t mtime, uint32 inode);

    int    (*SetResContentType)   (void * vmsg, char * type, int typelen);
    int    (*SetResContentTypeID) (void * vmsg, uint32 mimeid);
    int    (*SetResContentLength) (void * vmsg, int64 len);

    int    (*AddResContent)       (void * vmsg, void * body, int64 bodylen);
    int    (*AddResStripContent)  (void * vmsg, void * body, int64 bodylen,
                                   char * escch, int chlen);
    int    (*AddResContentPtr)    (void * vmsg, void * body, int64 bodylen);
    int    (*AddResFile)          (void * vmsg, char * filename, int64 startpos, int64 len);
    int    (*AddResAppCBContent)  (void * vmsg, void * prewrite, void * prewobj, int64 offset, int64 length,
                                   void * movefunc, void * movepara, void * endwrite, void * endwobj);
    int    (*AddResTpl)           (void * vmsg, void * pbyte, int bytelen, void * tplvar);
    int    (*AddResTplFile)       (void * vmsg, char * tplfile, void * tplvar);

    int    (*AsynReply)       (void * vmsg, int bodyend, int probewrite);
    int    (*Reply)           (void * vmsg);
    int    (*ReplyFeeding)    (void * vmsg);
    int    (*ReplyFeedingEnd) (void * vmsg);
 
    int    (*RedirectReply)   (void * vmsg, int status, char * redurl);

    uint8  extdata[1];

} HTTPMsg;

int    http_msg_cmp_http_msg(void * a, void * b);
int    http_msg_cmp_msgid   (void * a, void * pat);
ulong  http_msg_hash_msgid  (void * key); 


/* http message instance release/initialize/recycle routines */
int    http_mgmt_msg_free (void * vmsg);
int    http_msg_free    (void * vmsg);
int    http_msg_init    (void * vmsg);
int    http_msg_recycle (void * vmsg);

int http_msg_closeit (void * vmsg);
#define http_msg_close(msg) http_msg_close_dbg((msg), __FILE__, __LINE__)
int    http_msg_close_dbg (void * vmsg, char * file, int line);

int    http_msg_init_method (void * vmsg);
int    http_msg_init_req (void * vmsg);
int    http_msg_init_res (void * vmsg);

char * http_msg_srcip   (void * vmsg);
int    http_msg_srcport (void * vmsg);
ulong  http_msg_id      (void * vmsg);

void * http_msg_cbobj   (void * vmsg);
void * http_msg_obj     (void * vmsg);
void * http_msg_mgmtobj (void * vmsg);

void * http_msg_newmsg (void * vmsg);

char * http_msg_get_mime (void * vmsg, char * extname, uint32 * mimeid);
void * http_msg_get_mimemgmt (void * vmsg);

int    http_msg_set_teardown_notify (void * vmsg, void * func, void * para);
int    http_msg_set_response_notify (void * vmsg, void * func, void * para, void * cbval,
                                     char * storefile, int64 offset,
                                     void * procnotify, void * notifypara, uint64 notifycbval);

int http_msg_set_res_store_file      (void * vmsg, char * storefile, int64 offset);
int http_msg_set_res_recvall_notify  (void * vmsg, void * func, void * para, void * cbval);
int http_msg_set_res_recvproc_notify (void * vmsg, void * procnotify, void * para, uint64 cbval);

int http_msg_set_req_sendproc_notify (void * vmsg, void * procnotify, void * para, uint64 cbval);


/* 1 - temporary cache file
   2 - application-given file for storing response body
   3 - proxy cache file with partial content
   4 - proxy cache file will all content */
int    http_msg_cache_type    (void * vmsg, int respornot);
char * http_msg_cache_file    (void * vmsg, int respornot);

int    http_msg_mgmt_add (void * vmgmt, void * vmsg);
void * http_msg_mgmt_get (void * vmgmt, ulong msgid);
void * http_msg_mgmt_del (void * vmgmt, ulong msgid);

int    http_msg_var_set (void * vmsg, char * name, char * value, int valuelen);
int    http_msg_var_get (void * vmsg, char * name, char * value, int valuelen);


#ifdef __cplusplus
}
#endif

#endif

