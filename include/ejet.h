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

#ifndef _EJET_H_
#define _EJET_H_

#ifdef __cplusplus
extern "C" {
#endif

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


typedef int    HTTPObjInit    (void * httpmgmt, void * vobj, void * hconf);
typedef int    HTTPObjClean   (void * vobj);

typedef void * HTTPCBInit     (void * httpmgmt, int argc, char ** argv);
typedef int    HTTPCBHandler  (void * cbobj, void * vmsg, void * tplfile);
typedef void   HTTPCBClean    (void * cbobj);

typedef int    PageTplCB      (void * cbobj, void * vmsg, void * tplvar, void * tplunit, frame_p cfrm);

typedef int    RecvAllNotify  (void * vmsg, void * para, void * cbval, int status);
typedef int    TearDownNotify (void * vmsg, void * para);


typedef struct http_uri_s {
 
    frame_t   * uri;
    uint8       type;      //0-relative 1-absolute  2-connect uri
    uint8       needfree  : 1;  //0-regular  1-ssl
    uint8       ssl_link  : 5;  //0-regular  1-ssl
    uint8       alloctype : 2;  //0-default kalloc/kfree 1-os-specific malloc/free 2-kmempool alloc/free 3-kmemblk alloc/free
 
    void      * mpool;

    char      * reluri;
    int         relurilen;
 
    char      * baseuri;
    int         baseurilen;
 
    char      * rooturi;
    int         rooturilen;
 
    char      * scheme;
    int         schemelen;
 
    char      * host;
    int         hostlen;
    int         port;
 
    char      * path;
    int         pathlen;
 
    char      * query;
    int         querylen;
 
    char      * dir;
    int         dirlen;
 
    char      * file;
    int         filelen;
 
    char      * file_base;
    int         file_baselen;
 
    char      * file_ext;
    int         file_extlen;
 
} HTTPUri, http_uri_t;
 
void * http_uri_alloc  (int alloctype, void * mpool);
void   http_uri_free   (void * vuri);
void   http_uri_init   (void * vuri);
int    http_uri_set    (void * vuri, char * p, int len, int decode);
int    http_uri_parse  (void * vuri);
char * http_uri_string (void * vuri);


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

    uint8              req_url_type;  //0-relative 1-absolute 2-connect uri
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


int    http_msg_close   (void * vmsg);
 
void * http_mgmt_alloc    (void * epump, char * jsonconf, int extsize, int msgextsize);
int    http_mgmt_init     (void * vmgmt);
int    http_mgmt_cleanup  (void * vmgmt);
 
int    http_mgmt_obj_init  (void * vmgmt, HTTPObjInit * objinit, void * hconf);
int    http_mgmt_obj_clean (void * vmgmt, HTTPObjClean * objclean);
void * http_mgmt_obj       (void * vmgmt);
 
void * http_ssl_listen_start (void * vmgmt, char * localip, int port, uint8 fwdpxy,
                              char * cert, char * prikey, char * cacert, char * libfile);
void * http_listen_start     (void * vmgmt, char * localip, int port, uint8 fwdpxy, char * libfile);
 
int    http_listen_num  (void * vmgmt);
void * http_listen_get  (void * vmgmt, int index);

void * http_listen_find (void * vmgmt, char * localip, int port);
int    http_listen_stop (void * vmgmt, char * localip, int port);


void * http_prefix_loc (void * vhl, char * hostn, int hostlen, char * matstr, int len,
                        char * root, void * cbfunc, void * cbobj, void * tplfile);

void * http_exact_loc (void * vhl, char * hostn, int hostlen, char * matstr, int len,
                       char * root, void * cbfunc, void * cbobj, void * tplfile);

void * http_regex_loc (void * vhl, char * hostn, int hostlen, char * matstr, int len, int ignorecase,
                       char * root, void * cbfunc, void * cbobj, void * tplfile);

int    http_loc_set_root    (void * vloc, char * root, int rootlen);
int    http_loc_set_index   (void * vloc, char ** indexlist, int num);
int    http_loc_set_proxy   (void * vloc, char * passurl, char * cachefile);
int    http_loc_set_fastcgi (void * vloc, char * passurl);


/* <?ejetpl TEXT $CURROOT PARA=abcd ?>                                                  */
/* <?ejetpl LINK $LINKNAME URL=/csc/disponlist.so SHOW=第一页 PARA=listfile?>           */
/* <?ejetpl IMG $IMGNAME URL=/csc/drawimg.so?randval=234 SHOW=实时走势 PARA="a=1"?>     */
/* <?ejetpl LIST $ACCESSLOG PARA=1?>                                                    */
/* <?ejetpl INCLUDE /home/hzke/dxcang/httpdoc/foot.html ?>                        */
 
typedef struct pagetplunit {
    uint8    type; //1-TEXT, 2-LINK, 3-IMG, 4-LIST, 5-INCLUDE, 0-Unknown
    char   * text;
    int      textlen;
    char   * url;
    int      urllen;
    char   * show;
    int      showlen;
    char   * para;
    int      paralen;
    size_t   bgnpos;
    size_t   endpos;
    char   * tplfile;
} PageTplUnit;

int    http_pagetpl_text_cb (void * vhl, char * hostn, int hostlen,
                             void * text, int textlen, void * func, void * cbobj);
int    http_pagetpl_list_cb (void * vhl, char * hostn, int hostlen,
                             void * text, int textlen, void * func, void * cbobj);


void   http_overhead       (void * vmgmt, uint64 * recv, uint64 * sent,
                             struct timeval * lasttick, int reset, struct timeval * curt);
 
int    http_msg_mgmt_add (void * vmgmt, void * vmsg);
void * http_msg_mgmt_get (void * vmgmt, ulong msgid);
void * http_msg_mgmt_del (void * vmgmt, ulong msgid);

int    http_set_reqhandler (void * vmgmt, HTTPCBHandler * reqhandler, void * cbobj);

int    http_set_reqcheck (void * vmgmt, HTTPCBHandler * reqcheck, void * checkobj);
int    http_set_rescheck (void * vmgmt, HTTPCBHandler * rescheck, void * checkobj);

void * http_get_json_conf  (void * vmgmt);
void * http_get_mimemgmt   (void * vmgmt);
void * http_get_frame_pool (void * vmgmt);
void * http_get_epump      (void * vmgmt);

char * http_get_mime (void * vmgmt, char * file, uint32 * mimeid);


/* sending HTTP Request to HTTPServer and receiving the response */
int    do_http_request (void * vmsg);
 
void * do_http_get_msg (void * vmgmt, char * url, int urllen,
                        void * resfunc, void * para, void * cbval,
                        void * rcvprocfunc, void * procpara, uint64 proccbval,
                        char * resfile, long resoff);
 
void * do_http_get     (void * vmgmt, char * url, int urllen,
                        void * resfunc, void * para, void * cbval,
                        void * rcvprocfunc, void * procpara, uint64 proccbval,
                        char * resfile, long resoff);
 
void * do_http_post_msg (void * vmgmt, char * url, int urllen, char * mime,
                         char * body, int bodylen,
                         char * fname, long offset, long length,
                         void * resfunc, void * para, void * cbval,
                         void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                         void * sndprocfunc, void * sndpara, uint64 sndcbval,
                         char * resfile, long resoff);
 
void * do_http_post (void * vmgmt, char * url, int urllen, char * mime,
                     char * body, int bodylen,
                     char * fname, long offset, long length,
                     void * resfunc, void * para, void * cbval,
                     void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                     void * sndprocfunc, void * sndpara, uint64 sndcbval,
                     char * resfile, long resoff);


typedef struct HTTPForm_ {
    char      * name;        //allocated, need free
    char      * ctype;       //allocated, need free
 
    uint8       formtype  : 6; //0-form data  1-file
    uint8       alloctype : 2; //0-default kalloc/kfree 1-os-specific malloc/free 2-kmempool alloc/free 3-kmemblk alloc/free

    void      * mpool;
 
    char      * filename;    //allocated, need free
    char      * basename;    //allocated, need free
    char      * extname;
 
    int64       valuepos;
    int64       valuelen;
 
    chunk_t   * body_chunk;
    uint8       filecache;
 
} HTTPForm, http_form_t;
 
void * http_form_node (void * vmsg, char * key);

int http_form_get    (void * vmsg, char * key, char ** ctype, uint8 * formtype, char ** fname, int64 * valuelen);
int http_form_value  (void * vmsg, char * key, char * value, int64 valuelen);
int http_form_valuep (void * vmsg, char * key, int64 pos, char ** pvalue, int64 * valuelen);
int http_form_tofile (void * vmsg, char * key, int filefd);
 

#ifdef __cplusplus
}
#endif

#endif


