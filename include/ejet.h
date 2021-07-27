/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
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
    uint8       ssl_link;  //0-regular  1-ssl
 
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
 
void * http_uri_alloc  ();
void   http_uri_free   (void * vuri);
void   http_uri_init   (void * vuri);
int    http_uri_set    (void * vuri, char * p, int len, int decode);
int    http_uri_parse  (void * vuri);
char * http_uri_string (void * vuri);


typedef struct http_msg {
    void             * res[2];
 
    /* global unique identifier for HTTPMsg */
    ulong              msgid;
    uint8              msgtype;  /* 0-sending request  1-receiving request */
 
    void             * hl;
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
    time_t             createtime;
    time_t             stamp;
 
    /* client request and server response ip address of wap proxy system */
    char               srcip[41];
    int                srcport;
    char               dstip[41];
    int                dstport;
 
    uint8              ssl_link;
 
    /* the Flag used for determining if Request sent to server or not */
    uint8              reqsent;
    uint8              redirecttimes;
 
    uint8              req_url_type;  //0-relative 1-absolute
    http_uri_t       * uri;
    http_uri_t       * absuri;
    http_uri_t       * docuri;
 
    /* the elements following form the request line. they are
     * assigned value by invoker that would like to send request.
     * these elements are origin data constructing request. */
    int                req_methind;
    char               req_meth[16];
    char               req_ver[16];
    int                req_ver_major;
    int                req_ver_minor;
 
    /* following 7 elements are parsed to pointer to the location of msg->uri */
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
 
    /* variables for http-request receiving management */
    int64              req_header_length;
    int64              req_body_length;
    int64              req_body_iolen;
 
    uint8              req_chunk_state;
    int64              req_chunk_iolen;
    int64              req_chunk_size;
 
    /* request body is too large, memory is not enough to hold them.
     * we store the body content into a temperory file */
    uint8              req_multipart;
    uint8              req_file_cache;
    char             * req_file_name;
    void             * req_file_handle;
 
    /* 0-no body 1-Content-Length body 2-Transfer-Encoding body 3-unknown body */
    uint8              req_body_flag;
 
    uint8              req_conn_keepalive;
 
    /* the headers are made up of many HeaderUnits. these unit are
     * generated by invoker that would like to send request.
     * they are the origin data constructing request */
    hashtab_t        * req_header_table;
    arr_t            * req_header_list;
    hashtab_t        * req_cookie_table;
 
    /* the following member are data buffer that above elements(reqline, headers)
     * have their pointers to the location of buffer. */
    frame_p            req_header_stream;
    frame_p            req_body_stream;
    frame_p            req_stream;
 
    void             * req_chunk;
    chunk_t          * req_body_chunk;
    int64              req_stream_sent;
    int64              req_stream_recv;
 
    /* by adopting zero-copy for higher performance, frame buffers of HTTPCon, which stores
       octets from sockets,  will be moved to following list, for further parsing or handling,
       when receiving octest from client connection and forwarding to origin server.
       the overhead of memory copy will be lessened significantly. */
    arr_t            * req_rcvs_list;
 
    /* if content type of POST request is multipart form, every part is stored in list */
    arr_t            * req_formlist;
    void             * req_form_json;
    void             * req_form_kvobj;
    void             * req_query_kvobj;
 
    /* TCP connection instance for the reading/writing of HTTP Request/Response */
    void             * pcon;
    ulong              conid;
    ulong              workerid;
 
    /* redirect the request to a new URL with status code 302/301 */
    uint8              redirected;
 
    /* indicate current HTTPMsg is proxied to another origin server */
    uint8              proxied : 4;  //0-no proxy 1-original request  2-proxing request
    uint8              cacheon : 4;
    struct http_msg  * proxymsg;
 
    /* indicate the msg is Fast-CGI to Fast-CGI Processor Manager server */
    uint8              fastcgi;  //0-no fastcgi 1-send to FastCGI server
    void             * fcgimsg;
    uint8              fcgi_resend;
 
    char             * fwdurl;
    int                fwdurllen;
 
    /* determine if the requested host is reached via proxy */
    char             * proxy;
    int                proxyport;
 
    //0-no partial,
    uint8              partial_flag;
    void             * partial_list;
 
    uint8              flag304;   //not modified content, just return 304
 
 
    /* the Flag indicated if application has issued the response to client
       or the request to server */
    int                issued;
 
    /* the first line of response contains following information. */
    char               res_ver[16];
    int                res_status;
 
    uint32             res_verloc;
    int                res_verlen;
    uint32             res_statusloc;
    int                res_statuslen;
    uint32             res_reasonloc;
    int                res_reasonlen;
    frame_p            res_line;
 
    /* the number of header/body octets received from server or high layer */
    int64              res_header_length;
    int64              res_body_length;
    int64              res_body_iolen;
 
    /* based on caching configure and cache policy in origin server response,
       response body is cached into res_file_name, caching information is stored
       in res_cache_name. */
    char             * res_file_name;
    void             * res_file_handle;
 
    uint8              res_file_cache;
    int64              cache_req_start;
    int64              cache_req_off;
    int64              cache_req_len;
 
    void             * res_cache_info;
 
    /* 0-no body 1-Content-Length body 2-Transfer-Encoding body 3-unknown body */
    uint8              res_body_flag;
 
    uint8              res_conn_keepalive;
 
    /* by parsing from raw octets, response headers are stored into HeaderUnits,
       which organized by following hashtab and list. */
    hashtab_t        * res_header_table;
    arr_t            * res_header_list;
 
    /* following frame buffers store headers or body data from origin server,
       or higher layer module. access to header/body is just referenced to frame buffers.
     * res_stream stores encoded headers to be delivered to client. */
    frame_p            res_header_stream;
    frame_p            res_body_stream;
    frame_p            res_stream;
 
    /* response bodies with various formats are handled and store in chunk facilities. */
    void             * res_chunk;
    chunk_t          * res_body_chunk;
    int64              res_stream_sent;
    int64              res_stream_recv;
 
    /* by adopting zero-copy for higher performance, frame buffers of HTTPCon, which stores
       octets from sockets,  will be moved to following list, for further parsing or handling,
       when receiving octest from origin server connection and forwarding to client.
       the overhead of memory copy will be lessened significantly. */
    arr_t            * res_rcvs_list;
 
 
    /* system management instance */
    void             * pcore;
    void             * httpmgmt;
 
    /* notify upper-layer application while TCP connection tear-down */
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
                                void * procnotify, void * procpara, uint64 proccbval);
 
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
 
    uint8       formtype;    //0-form data  1-file
 
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


