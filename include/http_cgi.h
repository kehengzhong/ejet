/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_CGI_H_
#define _HTTP_CGI_H_

#ifdef __cplusplus
extern "C" {
#endif


void * GetHTTPMgmt (void * vmsg);
void * GetEPump    (void * vmsg);
void * GetIODev    (void * vmsg);

frame_p GetFrame      (void * vmsg);
int     RecycleFrame  (void * vmsg, frame_p frame);

char * GetRootPath   (void * vmsg);

int GetPathP         (void * vmsg, char ** ppath, int * pathlen);
int GetReqPath       (void * vmsg, char * path, int pathlen);
int GetRealPath      (void * vmsg, char * path, int pathlen);
int GetRealFile      (void * vmsg, char * path, int pathlen);
int GetLocFile       (void * vmsg, char * p, int len, char * f, int flen, char * d, int dlen);
int GetPathOnly      (void * vmsg, char * path, int pathlen);
int GetFileOnly      (void * vmsg, char * path, int pathlen);
int GetFileExt       (void * vmsg, char * path, int pathlen);

int    GetMethodInd  (void * vmsg);
char * GetMethod     (void * vmsg);
int    GetBaseURL    (void * vmsg, char ** pbase, int * plen);
char * GetAbsURL     (void * vmsg);
char * GetRelative   (void * vmsg);
char * GetURL        (void * vmsg);
char * GetDocURL     (void * vmsg);

int GetSchemeP       (void * vmsg, char ** pscheme, int * schemelen);
int GetScheme        (void * vmsg, char * scheme, int schemelen);
int GetHostP         (void * vmsg, char ** phost, int * hostlen);
int GetHost          (void * vmsg, char * host, int hostlen);
int GetPort          (void * vmsg);

int GetQueryP        (void * vmsg, char ** pquery, int * pquerylen);
int GetQuery         (void * vmsg, char * query, int querylen);
int GetQueryValueP   (void * vmsg, char * key, char ** pval, int * vallen);
int GetQueryValue    (void * vmsg, char * key, char * val, int vallen);
int GetQueryUint     (void * vmsg, char * key, uint32 * val);
int GetQueryInt      (void * vmsg, char * key, int * val);
int GetQueryUlong    (void * vmsg, char * key, ulong * val);
int GetQueryInt64    (void * vmsg, char * key, int64 * val);
int GetQueryUint64   (void * vmsg, char * key, uint64 * val);
int GetQueryLong     (void * vmsg, char * key, long * val);
int GetQueryKeyExist (void * vmsg, char * key);

int GetReqContent    (void * vmsg, void * body, int bodylen);
int GetReqContentP   (void * vmsg, void ** pbody, int * bodylen);

int GetReqFormJsonValueP   (void * vmsg, char * key, char ** ppval, int * vallen);
int GetReqFormJsonValue    (void * vmsg, char * key, char * pval, int vallen);
int GetReqFormJsonKeyExist (void * vmsg, char * key);

int GetReqFormDecodeValueP (void * vmsg, char * key, char ** ppval, int * vallen);
int GetReqFormDecodeValue  (void * vmsg, char * key, char * pval, int vallen);

int GetReqFormValueP   (void * vmsg, char * key, char ** ppval, int * vallen);
int GetReqFormValue    (void * vmsg, char * key, char * pval, int vallen);
int GetReqFormUint     (void * vmsg, char * key, uint32 * val);
int GetReqFormInt      (void * vmsg, char * key, int * val);
int GetReqFormUlong    (void * vmsg, char * key, ulong * val);
int GetReqFormLong     (void * vmsg, char * key, long * val);
int GetReqFormUint64   (void * vmsg, char * key, uint64 * val);
int GetReqFormKeyExist (void * vmsg, char * key);

int GetReqHdrNum  (void * vmsg);
int GetReqHdrIndP (void * vmsg, int index, char ** pname, int * namelen, 
                   char ** pvalue, int * valuelen);
int GetReqHdrInd  (void * vmsg, int index, char * name, int namelen,
                   char * value, int valuelen);
int GetReqHdr     (void * vmsg, char * name, int namelen, char * value, int valuelen);
int GetReqHdrP    (void * vmsg, char * name, int namelen, char ** pval, int * vallen);

int    GetReqHdrInt    (void * vmsg, char * name, int namelen);
long   GetReqHdrLong   (void * vmsg, char * name, int namelen);
ulong  GetReqHdrUlong  (void * vmsg, char * name, int namelen);
int64  GetReqHdrInt64 (void * vmsg, char * name, int namelen);
uint64 GetReqHdrUint64 (void * vmsg, char * name, int namelen);

int GetReqContentTypeP    (void * vmsg, char ** ptype, int * typelen);
int GetReqContentType     (void * vmsg, char * type, int typelen);
int GetReqContentLength   (void * vmsg);

int GetReqEtag (void * vmsg, char * etag, int etaglen);
int GetCookieP (void * vmsg, char * name, int nlen, char ** pv, int * vlen);
int GetCookie  (void * vmsg, char * name, int nlen, char * val, int vlen);
       
int AddReqHdr       (void * vmsg, char * name, int namelen, char * value, int valuelen);
int AddReqHdrInt    (void * vmsg, char * name, int namelen, int value);
int AddReqHdrUint32 (void * vmsg, char * name, int namelen, uint32 value);
int AddReqHdrLong   (void * vmsg, char * name, int namelen, long value);
int AddReqHdrUlong  (void * vmsg, char * name, int namelen, ulong value);
int AddReqHdrInt64  (void * vmsg, char * name, int namelen, int64 value);
int AddReqHdrUint64 (void * vmsg, char * name, int namelen, uint64 value);
int AddReqHdrDate   (void * vmsg, char * name, int namelen, time_t dtime);
int DelReqHdr       (void * vmsg, char * name, int namelen);

int    SetResEtag (void * vmsg, char * etag, int etaglen);
int    SetCookie  (void * vmsg, char * name, char * value, time_t expire, 
                    char * path, char * domain, uint8 secure);

int    SetReqContentType   (void * vmsg, char * type, int typelen);
int    SetReqContentLength (void * vmsg, int64 len);
int    SetReqContent       (void * vmsg, void * body, int bodylen);
int    SetReqFileContent   (void * vmsg, char * filename);

int    AddReqContent       (void * vmsg, void * body, int64 bodylen);
int    AddReqContentPtr    (void * vmsg, void * body, int64 bodylen);
int    AddReqFile          (void * vmsg, char * filename, int64 startpos, int64 len);
int    AddReqAppCBContent  (void * vmsg, void * fetchfunc, void * fetchobj, int64 offset, int64 length,
                            void * movefunc, void * movepara, void * endfetch, void * endobj);


int    GetResHdrNum          (void * vmsg);
int    GetResHdrIndP         (void * vmsg, int index, char ** pname, int * namelen,
                              char ** pvalue, int * valuelen);
int    GetResHdrInd          (void * vmsg, int index, char * name, int namelen,
                               char * value, int valuelen);
int    GetResHdr             (void * vmsg, char * name, int namelen, char * value, int valuelen);
int    GetResHdrP            (void * vmsg, char * name, int namelen, char ** pval, int * vallen);

int    GetResHdrInt    (void * vmsg, char * name, int namelen);
long   GetResHdrLong   (void * vmsg, char * name, int namelen);
ulong  GetResHdrUlong  (void * vmsg, char * name, int namelen);
int64  GetResHdrInt64  (void * vmsg, char * name, int namelen);
uint64 GetResHdrUint64 (void * vmsg, char * name, int namelen);

int    GetResContentTypeP    (void * vmsg, char ** ptype, int * typelen);
int    GetResContentType     (void * vmsg, char * type, int typelen);
int    GetResContentTypeID   (void * vmsg, uint32 * mimeid, char ** pext);
int64  GetResContentLength   (void * vmsg);
    
int    GetResContent         (void * vmsg, void * body, int bodylen);
int    GetResContentP        (void * vmsg, int64 pos, void ** pbody, int64 * bodylen);

int    GetStatus    (void * vmsg, char * reason, int * reasonlen);

int SetStatus       (void * vmsg, int code, char * reason);

int AddResHdr       (void * vmsg, char * name, int namelen, char * value, int valuelen);
int AddResHdrInt    (void * vmsg, char * name, int namelen, int value);
int AddResHdrUint32 (void * vmsg, char * name, int namelen, uint32 value);
int AddResHdrLong   (void * vmsg, char * name, int namelen, long value);
int AddResHdrUlong  (void * vmsg, char * name, int namelen, ulong value);
int AddResHdrInt64 (void * vmsg, char * name, int namelen, int64 value);
int AddResHdrUint64 (void * vmsg, char * name, int namelen, uint64 value);
int AddResHdrDate   (void * vmsg, char * name, int namelen, time_t dtime);
int DelResHdr       (void * vmsg, char * name, int namelen);

int    Check304Resp (void * vmsg, uint64 mediasize, time_t mtime, uint32 inode);

int    SetResContentType   (void * vmsg, char * type, int typelen);
int    SetResContentTypeID (void * vmsg, uint32 mimeid);
int    SetResContentLength (void * vmsg, int64 len);

int    AddResContent       (void * vmsg, void * body, int64 bodylen);
int    AddResStripContent  (void * vmsg, void * body, int64 bodylen, char * escch, int chlen);
int    AddResContentPtr    (void * vmsg, void * body, int64 bodylen);
int    AddResFile          (void * vmsg, char * filename, int64 startpos, int64 len);
int    AddResAppCBContent  (void * vmsg, void * fetchfunc, void * fetchobj, int64 offset, int64 length,
                            void * movefunc, void * movepara, void * endfetch, void * endobj);

int AsynReply       (void * vmsg, int bodyend, int probewrite);
int Reply           (void * vmsg);
int ReplyFeeding    (void * vmsg);
int ReplyFeedingEnd (void * vmsg);
 
int RedirectReply   (void * vmsg, int status, char * url);

#ifdef __cplusplus
}
#endif

#endif


