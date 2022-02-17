/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"

#include "http_msg.h"
#include "http_mgmt.h"
#include "http_con.h"
#include "http_header.h"
#include "http_request.h"
#include "http_response.h"
#include "http_pump.h"
#include "http_status.h"
#include "http_cgi.h"
#include "http_listen.h"
#include "http_cli_io.h"

extern HTTPMgmt * gp_httpmgmt;


void * GetHTTPMgmt (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return NULL;

    return msg->httpmgmt;
}

void * GetEPump (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;

    if (!msg) return NULL;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return NULL;

    return mgmt->pcore;
}

void * GetIODev (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return NULL;
 
    return http_con_iodev(msg->pcon);
}
 
 
frame_p GetFrame (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    frame_p    frame = NULL;

    if (!msg) return NULL;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return NULL;

    frame = bpool_fetch(mgmt->frame_pool);
    frame_empty(frame);

    return frame;
}

int RecycleFrame (void * vmsg, frame_p frame)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;

    if (!msg) return -1;
    if (!frame) return -2;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -3;

    bpool_recycle(mgmt->frame_pool, frame);
    return 0;
}

int GetMethodInd (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return 0;

    return msg->req_methind;
}

char * GetMethod (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return "";

    return msg->req_meth;
}


int GetBaseURL (void * vmsg, char ** pbase, int * plen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;

    if (pbase) *pbase = NULL;
    if (plen) *plen = 0;

    if (!msg) return -1;

    if (pbase) *pbase = msg->absuri->baseuri;
    if (plen) *plen = msg->absuri->baseurilen;

    return 0;
}

char * GetAbsURL (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;

    if (!msg) return "";

    return frame_string(msg->absuri->uri);
}

char * GetRelative (void * vmsg) 
{ 
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return "";
 
    return msg->uri->reluri; 
} 

char * GetURL (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;

    if (!msg) return "";

    return frame_string(msg->uri->uri);
}
 
char * GetDocURL (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return "";
 
    return frame_string(msg->docuri->uri);
}


int GetSchemeP (void * vmsg, char ** pscheme, int * schemelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (pscheme) *pscheme = msg->req_scheme;
    if (schemelen) *schemelen = msg->req_schemelen;

    return msg->req_schemelen;
}

int GetScheme (void * vmsg, char * scheme, int schemelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!scheme || schemelen <= 0) return -2;

    return str_secpy(scheme, schemelen, msg->req_scheme, msg->req_schemelen);
}

int GetHostP (void * vmsg, char ** phost, int * hostlen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;
    if (!hostlen) return -2;

    if (!msg->req_host || msg->req_hostlen <= 0) {
        punit = http_header_get(msg, 0, "Host", 4);
        if (punit) {
            if (phost) *phost = HUValue(punit);
            if (hostlen) *hostlen = punit->valuelen;
            return punit->valuelen;
        } else {
            if (phost) *phost = NULL;
            if (hostlen) *hostlen = 0;
            return 0;
        }
    }

    if (phost) *phost = msg->req_host;
    if (hostlen) *hostlen = msg->req_hostlen;

    return msg->req_hostlen;
}

int GetHost (void * vmsg, char * host, int hostlen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;
    if (!host || hostlen <= 0) return -2;

    memset(host, 0, hostlen);

    if (!msg->req_host || msg->req_hostlen <= 0) {
        punit = http_header_get(msg, 0, "Host", 4);
        if (punit) {
            return str_secpy(host, hostlen, HUValue(punit), punit->valuelen);
        }
        return 0;
    }

    return str_secpy(host, hostlen, msg->req_host, msg->req_hostlen);
}

int GetPort(void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
        
    if (!msg) return -1;

    return msg->req_port;
}

int GetPathP (void * vmsg, char ** ppath, int * pathlen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1; 

    if (ppath) *ppath = msg->req_path;
    if (pathlen) *pathlen = msg->req_pathlen;

    return msg->req_pathlen;
}

int GetReqPath (void * vmsg, char * path, int pathlen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (!path || pathlen <= 0) return -2;

    return uri_decode(msg->req_path, msg->req_pathlen, path, pathlen);
    //return str_secpy(path, pathlen, msg->req_path, msg->req_pathlen);
}

char * GetRootPath (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPHost   * phost = NULL;
    HTTPLoc    * ploc = NULL;
 
    if (!msg) return ".";

    if (!msg->ploc) {
        if (msg->phost) {
            phost = (HTTPHost *)msg->phost;
            return phost->root;
        }
        return ".";
    }
 
    ploc = (HTTPLoc *)msg->ploc;

    return ploc->root;
}

int GetRealPath (void * vmsg, char * path, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char       * root = NULL;
    int          slen = 0;
    int          retlen = 0;
 
    if (!msg) return -1;
    if (!path || len <= 0) return -2;
 
    root = GetRootPath(msg);
    retlen = str_len(root);
 
    if (path && len > 0)
        str_secpy(path, len, root, retlen);

    if (path) {
        slen = strlen(path);
        uri_decode(msg->docuri->dir, msg->docuri->dirlen, path + slen, len - slen);
    }
    retlen += msg->docuri->dirlen;
 
    if (path) return strlen(path);
 
    return retlen;
}

int GetRealFile (void * vmsg, char * path, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPLoc    * ploc = NULL;
    char       * root = NULL;
    int          i, slen = 0;
    int          retlen = 0;
 
    if (!msg) return -1;
    if (!path || len <= 0) return -2;
 
    root = GetRootPath(msg);
    retlen = str_len(root);
 
    if (path && len > 0)
        str_secpy(path, len, root, retlen);

    if (msg->docuri->path && msg->docuri->pathlen > 0) {
        if (path) {
            slen = strlen(path);
            uri_decode(msg->docuri->path, msg->docuri->pathlen, path + slen, len - slen);
        }
        retlen += msg->docuri->pathlen;
 
    } else {
        if (path) {
            slen = strlen(path);
            str_secpy(path + slen, len - slen, "/", 1);
        }
        retlen += 1;
    }
 
    if (path && file_is_dir(path) && (ploc = msg->ploc)) {
        slen = strlen(path);
        for (i = 0; i < (int)ploc->indexnum; i++) {
            snprintf(path + slen, len - slen, "%s", ploc->index[i]);
            if (file_is_regular(path)) {
                return strlen(path);
            }
        }
        path[slen] = '\0';
    }

    if (path) return strlen(path);

    return retlen;
}

int GetLocFile (void * vmsg, char * upath, int upathlen, char * locfile, int loclen, char * docuri, int doclen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPLoc  * ploc = NULL;
    frame_t  * pathfrm = NULL;
    frame_t  * urifrm = NULL;
    int        i;
    uint8      slash = 0;
    int        pathlen = 0;
    int        ret = 0;

    if (locfile && loclen > 0) locfile[0] = '\0';
    if (docuri && doclen > 0) docuri[0] = '\0';

    if (!msg) return -1;

    ploc = (HTTPLoc *)msg->ploc;
    if (!ploc) return -2;

    pathfrm = frame_new(1024);
    urifrm = frame_new(1024);

    /* root path */
    frame_append(pathfrm, ploc->root);

    /* append uri path */
    if (upath && upathlen > 0) {
        frame_put_nlast(pathfrm, upath, upathlen);
    } else {
        frame_uri_decode(pathfrm, msg->docuri->path, msg->docuri->pathlen);
    }

    if (file_is_regular(frameS(pathfrm))) {
        if (locfile && loclen > 0) 
            str_secpy(locfile, loclen, frameP(pathfrm), frameL(pathfrm));

        if (docuri && doclen > 0) {
            /* construct a new DocURI */
            frame_empty(urifrm);
    
            /* add: scheme://domain[:port] */ 
            if (msg->docuri->type == 1 && msg->docuri->rooturilen > 0) {
                frame_put_nlast(urifrm, msg->uri->rooturi, msg->uri->rooturilen);
            }
    
            /* add relative uri */
            if (upath && upathlen > 0) {
                frame_put_nlast(urifrm, upath, upathlen);
            } else {
                frame_put_nlast(urifrm, msg->docuri->path, msg->docuri->pathlen);
            }
            
            /* add query string */
            if (msg->docuri->querylen > 0) {
                frame_put_last(urifrm, '?');
                frame_put_nlast(urifrm, msg->docuri->query, msg->docuri->querylen);
            }
    
            str_secpy(docuri, doclen, frameP(urifrm), frameL(urifrm));
        }

        ret = 1;

    } else if (file_is_dir(frameS(pathfrm))) {
        if (frame_read(pathfrm, frameL(pathfrm)-1) != '/') {
            frame_put_last(pathfrm, '/');
            slash = 1;
        } else {
            slash = 0;
        }
        pathlen = frameL(pathfrm);

        for (i = 0; i < (int)ploc->indexnum; i++) {
            frame_trunc(pathfrm, pathlen);
            frame_append(pathfrm, ploc->index[i]);

            if (!file_is_regular(frameS(pathfrm)))
                continue;

            if (locfile && loclen > 0) 
                str_secpy(locfile, loclen, frameP(pathfrm), frameL(pathfrm));

            if (docuri && doclen > 0) {
                /* construct a new DocURI */
                frame_empty(urifrm);
     
                /* add: scheme://domain[:port] */
                if (msg->docuri->type == 1 && msg->docuri->rooturilen > 0) {
                    frame_put_nlast(urifrm, msg->uri->rooturi, msg->uri->rooturilen);
                }
     
                /* add relative uri */
                if (upath && upathlen > 0) {
                    frame_put_nlast(urifrm, upath, upathlen);
                } else {
                    frame_put_nlast(urifrm, msg->docuri->path, msg->docuri->pathlen);
                }
     
                if (slash) frame_put_last(urifrm, '/');

                /* add the index file */
                frame_append(urifrm, ploc->index[i]);

                /* add query string */
                if (msg->docuri->querylen > 0) {
                    frame_put_last(urifrm, '?');
                    frame_put_nlast(urifrm, msg->docuri->query, msg->docuri->querylen);
                }
     
                str_secpy(docuri, doclen, frameP(urifrm), frameL(urifrm));
            }
            ret = 2;
            break;
        }
    }

    frame_delete(&urifrm);
    frame_delete(&pathfrm);

    return ret;
}


int GetPathOnly(void * vmsg, char * path, int pathlen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (!path || pathlen <= 0) return -2;

    return str_secpy(path, pathlen, msg->docuri->dir, msg->docuri->dirlen);
}

int GetFileOnly(void * vmsg, char * path, int pathlen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (!path || pathlen <= 0) return -2;
        
    return uri_decode(msg->docuri->file, msg->docuri->filelen, path, pathlen);
}

int GetFileExt(void * vmsg, char * path, int pathlen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (!path || pathlen <= 0) return -2;

    return str_secpy(path, pathlen, msg->docuri->file_ext, msg->docuri->file_extlen);
}


int GetQuery (void * vmsg, char * query, int querylen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!query || querylen <= 0) return -2;
    
    return uri_decode(msg->req_query, msg->req_querylen, query, querylen);
}

int GetQueryP (void * vmsg, char ** pquery, int * pquerylen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (pquery) *pquery = msg->req_query;
    if (pquerylen) *pquerylen = msg->req_querylen;

    return 0;
}

int GetQueryValueP (void * vmsg, char * key, char ** pval, int * vallen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!key) return -2;

    return kvpair_getP(msg->req_query_kvobj, key, strlen(key), 0, (void **)pval, vallen);
}

int GetQueryValue (void * vmsg, char * key, char * val, int vallen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1; 
    if (!key) return -2;

    return kvpair_get(msg->req_query_kvobj, key, strlen(key), 0, val, &vallen);
}

int GetQueryUint(void * vmsg, char * key, uint32 * val)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!key) return -2;

    return kvpair_get_uint32(msg->req_query_kvobj, key, strlen(key), 0, val);
}

int GetQueryInt(void * vmsg, char * key, int * val)
{    
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (val) *val = 0;

    if (!msg) return -1;
    if (!key) return -2;

    return kvpair_get_int(msg->req_query_kvobj, key, strlen(key), 0, val);
}        
     
int GetQueryUlong (void * vmsg, char * key, ulong * val)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (val) *val = 0;

    if (!msg) return -1;
    if (!key) return -2;

    return kvpair_get_ulong(msg->req_query_kvobj, key, strlen(key), 0, val);
}
 
int GetQueryLong (void * vmsg, char * key, long * val)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (val) *val = 0;

    if (!msg) return -1;
    if (!key) return -2;

    return kvpair_get_long(msg->req_query_kvobj, key, strlen(key), 0, val);
}

int GetQueryInt64(void * vmsg, char * key, int64 * val)
{   
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    
    if (val) *val = 0;

    if (!msg) return -1;
    if (!key) return -2;

    return kvpair_get_int64(msg->req_query_kvobj, key, strlen(key), 0, val);
}

int GetQueryUint64(void * vmsg, char * key, uint64 * val)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (val) *val = 0;

    if (!msg) return -1;
    if (!key) return -2;

    return kvpair_get_uint64(msg->req_query_kvobj, key, strlen(key), 0, val);
}

int GetQueryKeyExist (void * vmsg, char * key)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return 0;
    if (!key) return 0;

    return kvpair_getP(msg->req_query_kvobj, key, strlen(key), 0, NULL, NULL) > 0;
}


int GetReqContent (void * vmsg, void * body, int bodylen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    int       num = 0;

    if (!msg) return -1;
    if (!body || bodylen <= 0) return -2;

    num = min(bodylen, chunk_size(msg->req_body_chunk, 0));

    chunk_read(msg->req_body_chunk, body, 0, num, 0);

    return uri_decode(body, num, body, bodylen);
}

int GetReqContentP (void * vmsg, void ** pbody, int * bodylen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    int64     len = 0;

    if (!msg) return -1;

    chunk_ptr(msg->req_body_chunk, 0, NULL, pbody, &len);

    if (bodylen) *bodylen = len;

    return 0;
}

int GetReqFormValueP (void * vmsg, char * key, char ** ppval, int * vallen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!key) return -2;

    return kvpair_getP(msg->req_form_kvobj, key, strlen(key), 0, (void **)ppval, vallen);
}

int GetReqFormValue (void * vmsg, char * key, char * pval, int vallen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!key) return -2;
 
    if (kvpair_get(msg->req_form_kvobj, key, strlen(key), 0, pval, &vallen) > 0)
        return vallen;

    return 0;
}

int GetReqFormDecodeValue(void * vmsg, char * key, char * pval, int vallen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    char    * p = NULL;
    int       len = 0;
    int       ret = 0;

    if (!msg) return -1;

    ret = GetReqFormValueP(msg, key, &p, &len);
    if (ret >= 0 && p && len > 0) {
        ret = uri_decode(p, len, pval, vallen);
    }
    
    return ret;
}


int GetReqFormJsonValueP (void * vmsg, char * key, char ** ppval, int * vallen)
{ 
    HTTPMsg * msg = (HTTPMsg *)vmsg;
     
    if (!msg) return -1;
    if (!key) return -2;
     
    return json_mgetP(msg->req_form_json, key, strlen(key), (void **)ppval, vallen);
}                       
 
int GetReqFormJsonValue (void * vmsg, char * key, char * pval, int vallen)
{ 
    HTTPMsg * msg = (HTTPMsg *)vmsg;
     
    if (!msg) return -1;
    if (!key) return -2;
     
    return json_mget(msg->req_form_json, key, strlen(key), pval, &vallen);
}
 
int GetReqFormJsonKeyExist (void * vmsg, char * key)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
     
    if (!msg) return 0;
    if (!key || str_len(key) <= 0) return 0;

    return json_mgetP(msg->req_form_json, key, strlen(key), NULL, 0) > 0;
}

int GetReqFormUint (void * vmsg, char * key, uint32 * val)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (val) *val = 0;

    if (!msg) return -1;
    if (!key) return -2;
 
    return kvpair_get_uint32(msg->req_form_kvobj, key, strlen(key), 0, val);
}   

int GetReqFormInt (void * vmsg, char * key, int * val)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (val) *val = 0;

    if (!msg) return -1;
    if (!key) return -2;
 
    return kvpair_get_int(msg->req_form_kvobj, key, strlen(key), 0, val);
}
 
int GetReqFormUlong (void * vmsg, char * key, ulong * val)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (val) *val = 0;

    if (!msg) return -1;
    if (!key) return -2;
 
    return kvpair_get_ulong(msg->req_form_kvobj, key, strlen(key), 0, val);
}
 
int GetReqFormLong (void * vmsg, char * key, long * val)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (val) *val = 0;

    if (!msg) return -1;
    if (!key) return -2;
 
    return kvpair_get_long(msg->req_form_kvobj, key, strlen(key), 0, val);
}
 
int GetReqFormUint64(void * vmsg, char * key, uint64 * val)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (val) *val = 0;
 
    if (!msg) return -1;
    if (!key) return -2;
 
    return kvpair_get_uint64(msg->req_form_kvobj, key, strlen(key), 0, val);
}

int GetReqFormKeyExist (void * vmsg, char * key)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return 0;
    if (!key || str_len(key) <= 0) return 0;
 
    return kvpair_getP(msg->req_form_kvobj, key, strlen(key), 0, NULL, NULL) > 0;
}


int GetReqHdrNum (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return 0;

    return arr_num(msg->req_header_list);
}


int GetReqHdrIndP(void * vmsg, int index, char ** pname, int * namelen, 
                    char ** pvalue, int * valuelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    int       num = 0;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;

    if (pname) *pname = NULL;
    if (namelen) *namelen = 0;
    if (pvalue) *pvalue = NULL;
    if (valuelen) *valuelen = 0;

    num = arr_num(msg->req_header_list);
    if (index >= num) return -100;

    punit = arr_value(msg->req_header_list, index);

    if (pname) *pname = HUName(punit);
    if (namelen) *namelen = punit->namelen;

    if (pvalue) *pvalue = HUValue(punit);
    if (valuelen) *valuelen = punit->valuelen;

    return 0;
}

int GetReqHdrInd (void * vmsg, int index, char * name, int namelen,
                         char * value, int valuelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
    int          num = 0;

    if (!msg) return -1;

    if (name && namelen > 0) name[0] = '\0';
    if (value && valuelen > 0) value[0] = '\0';

    num = arr_num(msg->req_header_list);
    if (index >= num) return -100;

    punit = arr_value(msg->req_header_list, index);
    if (!punit) return -101;

    if (name && namelen > 0)
        str_secpy(name, namelen, HUName(punit), namelen);

    if (value && valuelen > 0)
        str_secpy(value, valuelen, HUValue(punit), valuelen);

    return 0;
}


int GetReqHdr (void * vmsg, char * name, int namelen, char * value, int valuelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;

    punit = http_header_get(msg, 0, name, namelen);
    if (!punit) return -100;

    if (value && valuelen > 0)
        return str_secpy(value, valuelen, HUValue(punit), punit->valuelen);

    return punit->valuelen;
}

int GetReqHdrInt (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_int(msg, 0, name, namelen);
}
 
long GetReqHdrLong (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_long(msg, 0, name, namelen);
}
 
ulong GetReqHdrUlong (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_ulong(msg, 0, name, namelen);
}
 
int64 GetReqHdrInt64 (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_int64(msg, 0, name, namelen);
}
 
uint64 GetReqHdrUint64 (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_uint64(msg, 0, name, namelen);
}
 

int GetReqHdrP (void * vmsg, char * name, int namelen, char ** pval, int * vallen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
    
    if (pval) *pval = NULL;
    if (vallen) *vallen = 0;
    
    if (!msg) return -1;

    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -2;

    punit = http_header_get(msg, 0, name, namelen);
    if (!punit) return -100;

    if (pval) *pval = HUValue(punit);
    if (vallen) *vallen = punit->valuelen;

    return punit->valuelen;
}


int GetReqContentTypeP (void * vmsg, char ** ptype, int * typelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;

    if (ptype) *ptype = NULL;
    if (typelen) *typelen = 0;

    punit = http_header_get(msg, 0, "Content-Type", 12);
    if (!punit)  return 0; 

    if (ptype) *ptype = HUValue(punit);
    if (typelen) *typelen = punit->valuelen;

    return punit->valuelen;
}

int GetReqContentType (void * vmsg, char * type, int typelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;

    punit = http_header_get(msg, 0, "Content-Type", 12);
    if (!punit) return 0;

    if (type && typelen > 0)
        return str_secpy(type, typelen, HUValue(punit), punit->valuelen);

    return punit->valuelen;
}

int GetReqEtag (void * vmsg, char * etag, int etaglen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    char    * p = NULL;
    char    * poct = NULL;
    char    * pend = NULL;
    int       len = 0;

    if (!msg) return -1;

    GetReqHdrP(msg, "If-None-Match", -1, &p, &len);
    if (len <= 0) return -5;

    pend = p + len;
    p = skipTo(p, pend-p, "\"", 1);
    if (p >= pend) {
        len = pend - p;
    } else {
        p = p+1;
        poct = skipTo(p, pend-p, "\"", 1);
        len = poct - p;
    }

    if (etag && etaglen > 0)
        return str_secpy(etag, etaglen, p, len);

    return len;
}

int GetCookieP (void * vmsg, char * name, int nlen, char ** pv, int * vlen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * unit = NULL;

    if (pv) *pv = NULL;
    if (vlen) *vlen = 0;

    if (!msg) return -1;
    if (!name) return -2;
    if (nlen < 0) nlen = str_len(name);
    if (nlen <= 0) return -3;

    unit = http_req_getcookie(msg, name, nlen);
    if (!unit) return -10;

    if (pv) *pv = HUValue(unit);
    if (vlen) *vlen = unit->valuelen;

    return unit->valuelen;
}

int GetCookie (void * vmsg, char * name, int nlen, char * val, int vlen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * unit = NULL;

    if (!msg) return -1;
    if (!name) return -2;
    if (nlen < 0) nlen = str_len(name);
    if (nlen <= 0) return -3;

    unit = http_req_getcookie(msg, name, nlen);
    if (!unit) return -10;

    if (val && vlen > 0)
        return str_secpy(val, vlen, HUValue(unit), unit->valuelen);

    return unit->valuelen;
}


int GetReqContentLength (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    return msg->req_body_length;
}


int AddReqHdr (void * vmsg, char * name, int namelen, char * value, int valuelen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;

    return http_header_append(msg, 0, name, namelen, value, valuelen);
}


int AddReqHdrInt (void * vmsg, char * name, int namelen, int value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;

    return http_header_append_int(msg, 0, name, namelen, value);
}

int AddReqHdrUint32 (void * vmsg, char * name, int namelen, uint32 value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;
 
    return http_header_append_uint32(msg, 0, name, namelen, value);
}

int AddReqHdrLong (void * vmsg, char * name, int namelen, long value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;
 
    return http_header_append_long(msg, 0, name, namelen, value);
}
 
int AddReqHdrUlong (void * vmsg, char * name, int namelen, ulong value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;
 
    return http_header_append_ulong(msg, 0, name, namelen, value);
}
 
int AddReqHdrInt64 (void * vmsg, char * name, int namelen, int64 value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;
 
    return http_header_append_int64(msg, 0, name, namelen, value);
}
 
int AddReqHdrUint64 (void * vmsg, char * name, int namelen, uint64 value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;
 
    return http_header_append_uint64(msg, 0, name, namelen, value);
}

int AddReqHdrDate (void * vmsg, char * name, int namelen, time_t dtime)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;

    return http_header_append_date(msg, 0, name, namelen, dtime);
}

int DelReqHdr (void * vmsg, char * name, int namelen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;

    return http_header_del(msg, 0, name, namelen);
}

int SetReqContentType (void * vmsg, char * type, int typelen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!type) return -2;
    if (typelen < 0) typelen = str_len(type);

    http_header_del(msg, 0, "Content-Type", 12);

    if (typelen <= 0) return 0;

    return http_header_append(msg, 0, "Content-Type", 12, type, typelen);
}

int SetReqContentLength (void * vmsg, int64 len)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;

    http_header_del(msg, 0, "Content-Length", 14);

    return http_header_append_int64(msg, 0, "Content-Length", 14, len);
}


int SetReqContent (void * vmsg, void * body, int bodylen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;

    SetReqContentLength(msg, bodylen);

    if (!body || bodylen <= 0) return 0;
    
    chunk_add_buffer(msg->req_body_chunk, body, bodylen);

    return bodylen;
}


int SetReqFileContent (void * vmsg, char * filename)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    char     * mime = NULL;

    if (!msg) return -1;
    if (!filename) return -2;

    if (!file_exist(filename)) return -100;

    frame_empty(msg->req_body_stream);
    chunk_zero(msg->req_body_chunk);

    chunk_add_file(msg->req_body_chunk, filename, 0, -1, 1);

    SetReqContentLength(msg, chunk_size(msg->req_body_chunk, 0));

    mime = http_get_mime(msg->httpmgmt, filename, NULL);
    SetReqContentType(msg, mime, str_len(mime));

    return 0;
}

int AddReqContent (void * vmsg, void * body, int64 bodylen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    if (!body) return -2;
    if (bodylen < 0) bodylen = str_len(body);
    if (bodylen <= 0) return -3;
 
    chunk_add_buffer(msg->req_body_chunk, body, bodylen);
    return 0;
}
 
int AddReqContentPtr (void * vmsg, void * body, int64 bodylen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    if (!body) return -2;
    if (bodylen < 0) bodylen = str_len(body);
    if (bodylen <= 0) return -3;
 
    chunk_add_bufptr(msg->req_body_chunk, body, bodylen, NULL, NULL);
    return 0;
}
 
int AddReqFile (void * vmsg, char * filename, int64 startpos, int64 len)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!filename) return -2;
 
    chunk_add_file(msg->req_body_chunk, filename, startpos, len, 1);
 
    return 0;
}
 
int AddReqAppCBContent (void * vmsg, void * fetchfunc, void * fetchobj, int64 offset, int64 length,
                        void * movefunc, void * movepara, void * endfetch, void * endobj)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    chunk_add_cbdata(msg->req_body_chunk, fetchfunc, fetchobj, offset, length,
                     movefunc, movepara, endfetch, endobj);
 
    return 0;
}
 

int GetResHdrNum (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return 0;

    return arr_num(msg->res_header_list);
}

int GetResHdrIndP(void * vmsg, int index, char ** pname, int * namelen,
                    char ** pvalue, int * valuelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    int          num = 0;
    HeaderUnit * punit = NULL;
    
    if (!msg) return -1;

    if (pname) *pname = NULL;
    if (namelen) *namelen = 0;
    if (pvalue) *pvalue = NULL;
    if (valuelen) *valuelen = 0;

    num = arr_num(msg->res_header_list);
    if (index >= num) return -100;

    punit = arr_value(msg->res_header_list, index);

    if (pname) *pname = HUName(punit);
    if (namelen) *namelen = punit->namelen;

    if (pvalue) *pvalue = HUValue(punit);
    if (valuelen) *valuelen = punit->valuelen;

    return 0;
}

int GetResHdrInd (void * vmsg, int index, char * name, int namelen,
                         char * value, int valuelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
    int          num = 0;

    if (!msg) return -1;

    num = arr_num(msg->res_header_list);
    if (index >= num) return -100;

    punit = arr_value(msg->res_header_list, index);
    if (!punit) return -200;

    if (name && namelen > 0) {
        str_secpy(name, namelen, HUName(punit), punit->namelen);
    }

    if (value && valuelen > 0) {
        str_secpy(value, valuelen, HUValue(punit), punit->namelen);
    }

    return 0;
}

int GetResHdr (void * vmsg, char * name, int namelen, char * value, int valuelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;

    punit = http_header_get(msg, 1, name, namelen);
    if (!punit) return -100;

    if (value && valuelen > 0) {
        str_secpy(value, valuelen, HUValue(punit), punit->valuelen);
    }

    return punit->valuelen;
}


int GetResHdrP (void * vmsg, char * name, int namelen, char ** pval, int * vallen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;

    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -2;

    if (pval) *pval = NULL;
    if (vallen) *vallen = 0;

    punit = http_header_get(msg, 1, name, namelen);
    if (!punit) return -100;

    if (pval) *pval = HUValue(punit);
    if (vallen) *vallen = punit->valuelen;

    return punit->valuelen;
}

int GetResHdrInt (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_int(msg, 1, name, namelen);
}
 
long GetResHdrLong (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_long(msg, 1, name, namelen);
}
 
ulong GetResHdrUlong (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_ulong(msg, 1, name, namelen);
}
 
int64 GetResHdrInt64 (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_int64(msg, 1, name, namelen);
}
 
uint64 GetResHdrUint64 (void * vmsg, char * name, int namelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -5;
 
    return http_header_get_uint64(msg, 1, name, namelen);
}
 
 
int GetResContentTypeP (void * vmsg, char ** ptype, int * typelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;

    if (ptype) *ptype = NULL;
    if (typelen) *typelen = 0;

    punit = http_header_get(msg, 1, "Content-Type", 12);
    if (!punit)  return 0;

    if (ptype) *ptype = HUValue(punit);
    if (typelen) *typelen = punit->valuelen;

    return punit->valuelen;
}

int GetResContentType (void * vmsg, char * type, int typelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;

    punit = http_header_get(msg, 1, "Content-Type", 12);
    if (!punit) return 0;

    if (type && typelen > 0) {
        str_secpy(type, typelen, HUValue(punit), punit->valuelen);
    }

    return punit->valuelen;
}

int GetResContentTypeID (void * vmsg, uint32 * mimeid, char ** pext)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
    HTTPMgmt   * mgmt = NULL;
    char         mime[256];
 
    if (mimeid) *mimeid = 0;
    if (pext) *pext = ".bin";

    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    punit = http_header_get(msg, 1, "Content-Type", 12);
    if (punit && punit->valuelen > 0) {
        str_secpy(mime, sizeof(mime)-1, HUValue(punit), punit->valuelen);
        return mime_type_get_by_mime(mgmt->mimemgmt, mime, pext, mimeid, NULL);
    }

    return -200;
}

int64 GetResContentLength (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return 0;

    return msg->res_body_length;
}


int GetResContent (void * vmsg, void * body, int bodylen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!body || bodylen <= 0) return -2;

    return chunk_read(msg->res_body_chunk, body, 0, bodylen, 0);
}


int GetResContentP (void * vmsg, int64 pos, void ** pbody, int64 * bodylen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (pbody) *pbody = NULL;
    if (bodylen) *bodylen = 0;

    return chunk_read_ptr(msg->res_body_chunk, pos, -1, pbody, bodylen, 0);
}

int GetStatus (void * vmsg, char * reason, int * reasonlen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    char     * p = NULL;
    int        len = 0;

    if (!msg) return -1;

    mgmt = (HTTPMgmt *)msg->httpmgmt;

    http_get_status2 (mgmt, msg->res_status, &p);

    len = str_len(p);
    if (reason && reasonlen && *reasonlen > len) {
        strcpy(reason, p);
    }
    if (reasonlen) *reasonlen = len;

    return msg->res_status;
}

int AddResHdr (void * vmsg, char * name, int namelen, char * value, int valuelen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -2;

    return http_header_append(msg, 1, name, namelen, value, valuelen);
}

int AddResHdrInt (void * vmsg, char * name, int namelen, int value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -2;

    return http_header_append_int(msg, 1, name, namelen, value);
}

int AddResHdrUint32 (void * vmsg, char * name, int namelen, uint32 value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -2;
 
    return http_header_append_uint32(msg, 1, name, namelen, value);
} 

int AddResHdrLong (void * vmsg, char * name, int namelen, long value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!name) return -2;

    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;

    return http_header_append_long(msg, 1, name, namelen, value);
}

int AddResHdrUlong (void * vmsg, char * name, int namelen, ulong value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!name) return -2;

    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;

    return http_header_append_ulong(msg, 1, name, namelen, value);
}

int AddResHdrInt64 (void * vmsg, char * name, int namelen, int64 value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!name) return -2;

    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;

    return http_header_append_int64(msg, 1, name, namelen, value);
}

int AddResHdrUint64 (void * vmsg, char * name, int namelen, uint64 value)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!name) return -2;
 
    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -3;
 
    return http_header_append_uint64(msg, 1, name, namelen, value);
}

int AddResHdrDate (void * vmsg, char * name, int namelen, time_t dtime)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -2;

    return http_header_append_date(msg, 1, name, namelen, dtime);
}

int DelResHdr (void * vmsg, char * name, int namelen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (namelen < 0) namelen = str_len(name);
    if (namelen <= 0) return -2;

    return http_header_del(msg, 1, name, namelen);
}

int SetResEtag (void * vmsg, char * etag, int etaglen)
{
    char buf[128];

    if (!vmsg) return -1;
    if (!etag) return -2;
    if (etaglen < 0) etaglen = str_len(etag);

    if (etaglen > sizeof(buf) - 1) return -100;

    buf[0] = '"';
    memcpy(buf+1, etag, etaglen);
    buf[1+etaglen] = '"';
    buf[2+etaglen] = '\0';

    return AddResHdr(vmsg, "ETag", 4, buf, etaglen+2);
}

int SetCookie (void * vmsg, char * name, char * value, time_t expire, 
               char * path, char * domain, uint8 secure)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    frame_p    cookie = NULL;
    char       timestr[64];
    time_t     curt;

    if (!msg) return -1;
    if (!name || str_len(name) <= 0) return -2;
    if (!value || str_len(value) <= 0) return -3;

    cookie = GetFrame(msg);
    frame_empty(cookie);

    frame_appendf(cookie, "%s=%s", name, value);
    time(&curt); 
    if (expire > curt) {
        str_time2gmt(&expire, timestr, sizeof(timestr), 1);
        frame_appendf(cookie, "; expires=%s", timestr);
    }
    if (path && str_len(path) > 0) {
        frame_appendf(cookie, "; path=%s", path);
    }
    if (domain && str_len(domain) > 0) {
        frame_appendf(cookie, "; domain=%s", domain);
    }
    if (secure) frame_appendf(cookie, "; SECURE");

    http_header_append(msg, 1, "Set-Cookie", -1, frameP(cookie), frameL(cookie));
    RecycleFrame(msg, cookie);
    return 0;
}


int SetResContentType (void * vmsg, char * type, int typelen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!type) return -2;

    if (typelen < 0) typelen = str_len(type);

    http_header_del(msg, 1, "Content-Type", 12);

    if (typelen == 0) return 0;

    return http_header_append(msg, 1, "Content-Type", 12, type, typelen);
}

int SetResContentTypeID (void * vmsg, uint32 mimeid)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    char     * mime = NULL;
 
    if (!msg) return -1;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;

    mime_type_get_by_mimeid(mgmt->mimemgmt, mimeid, &mime, NULL, NULL);
    if (!mime) return -100;

    http_header_del(msg, 1, "Content-Type", 12);

    return http_header_append(msg, 1, "Content-Type", 12, mime, str_len(mime));
}

int SetResContentLength (void * vmsg, int64 len)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    msg->res_body_flag = BC_CONTENT_LENGTH;
    msg->res_body_length = len;

    http_header_del(msg, 1, "Content-Length", 14);

    return http_header_append_int64(msg, 1, "Content-Length", 14, len);
}


int AddResContent (void * vmsg, void * body, int64 bodylen) 
{        
    HTTPMsg  * msg = (HTTPMsg *)vmsg; 

    if (!msg) return -1;

    if (!body) return -2;
    if (bodylen < 0) bodylen = str_len(body);
    if (bodylen <= 0) return -3;
                 
    chunk_add_buffer(msg->res_body_chunk, body, bodylen);
    return 0;
}

int AddResStripContent (void * vmsg, void * body, int64 bodylen, char * escch, int chlen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    if (!body) return -2;
    if (bodylen < 0) bodylen = str_len(body);
    if (bodylen <= 0) return -3;
 
    chunk_add_strip_buffer(msg->res_body_chunk, body, bodylen, escch, chlen);
    return 0;
}

 
int AddResContentPtr (void * vmsg, void * body, int64 bodylen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    if (!body) return -2;
    if (bodylen < 0) bodylen = str_len(body);
    if (bodylen <= 0) return -3;
 
    chunk_add_bufptr(msg->res_body_chunk, body, bodylen, NULL, NULL);
    return 0;
}

static void AdjustPartial (http_partial_t * part, int64 fsize)
{
    if (!part || fsize <= 0) return;

    part->fsize = fsize;

    switch (part->partflag) {

    case 1: //byte=348-1589
        if (part->start >= fsize)
            part->start = fsize;

        if (part->end >= fsize)
            part->end = fsize - 1;

        part->length = part->end - part->start + 1;
        break;

    case 2: //byte=348-
        if (part->start >= fsize)
            part->start = fsize;

        part->length = fsize - part->start;

        part->end = part->start + part->length - 1;
        break;

    case 3: //byte=-500
        if (part->length > fsize)
            part->length = fsize;

        part->start = fsize - part->length;

        part->end = fsize - 1;
        break;
    }
}

int AddResFile (void * vmsg, char * filename, int64 startpos, int64 len)
{
    HTTPMsg        * msg = (HTTPMsg *)vmsg;
    char           * mime = NULL;
    int              ret = 0;
    http_partial_t * part = NULL;
    int              i, num;
    struct stat      st;
    char             boundary[128];
    char             buf[512];
 
    if (!msg) return -1;
    if (!filename) return -2;
 
    if (file_stat(filename, &st) < 0) return -3;

    ret = strlen(filename);
    if (ret > 7 && str_casecmp(filename + ret - 7, ".ejetpl") == 0) {
        return msg->AddResTplFile(msg, filename, NULL);
    }

    if ((num = vstar_num(msg->partial_list)) > 0) {

        if (num == 1) {
            part = vstar_get(msg->partial_list, 0);
            if (!part) goto addfile;

            AdjustPartial(part, st.st_size);

            ret = chunk_add_file(msg->res_body_chunk, filename, part->start, part->length, 1);

#if defined(_WIN32) || defined(_WIN64)
            sprintf(buf, "bytes %I64d-%I64d/%I64d", part->start, part->end, part->fsize);
#else
            sprintf(buf, "bytes %lld-%lld/%lld", part->start, part->end, part->fsize);
#endif
            http_header_append(msg, 1, "Content-Range", -1, buf, strlen(buf));

            if (http_header_get(msg, 1, "Content-Type", 12) == NULL) {
                mime = http_get_mime(msg->httpmgmt, filename, NULL);
                SetResContentType(msg, mime, str_len(mime));
            }

            return ret;

        } else {
            GetRandStr(boundary, 16, 1); boundary[16] = '\0';

            mime = http_get_mime(msg->httpmgmt, filename, NULL);

            for (i = 0; i < num; i++) {
                part = vstar_get(msg->partial_list, i);
                if (!part) continue;

                AdjustPartial(part, st.st_size);

#if defined(_WIN32) || defined(_WIN64)
                sprintf(buf, "--%s\r\nCotent-Type: %s\r\n"
                             "Content-Range: bytes %I64d-%I64d/%I64d\r\n\r\n",
                        boundary, mime, part->start, part->end, part->fsize);
#else
                sprintf(buf, "--%s\r\nCotent-Type: %s\r\n"
                             "Content-Range: bytes %lld-%lld/%lld\r\n\r\n",
                        boundary, mime, part->start, part->end, part->fsize);
#endif
                chunk_add_buffer(msg->res_body_chunk, buf, strlen(buf));

                chunk_add_file(msg->res_body_chunk, filename, part->start, part->length, 1);
            }

            sprintf(buf, "--%s--\r\n", boundary);
            chunk_add_buffer(msg->res_body_chunk, buf, strlen(buf));

            sprintf(buf, "multipart/byteranges; boundary=\"%s\"", boundary);
            http_header_append(msg, 1, "Content-Type", -1, buf, strlen(buf));
            
            return ret;
        }
    }

addfile:
    if (startpos >= st.st_size) return -100;
    if (len < 0 || len > st.st_size - startpos)
        len = st.st_size - startpos;

    ret = chunk_add_file(msg->res_body_chunk, filename, startpos, len, 1);

    if (len < st.st_size) {
        SetStatus(msg, 206, "Partial Content");

#if defined(_WIN32) || defined(_WIN64)
        sprintf(buf, "bytes %I64d-%I64d/%ld", startpos, startpos + len - 1, st.st_size);
#else
        sprintf(buf, "bytes %lld-%lld/%ld", startpos, startpos + len - 1, st.st_size);
#endif
        http_header_append(msg, 1, "Content-Range", -1, buf, strlen(buf));
    }

    if (http_header_get(msg, 1, "Content-Type", 12) == NULL) {
        mime = http_get_mime(msg->httpmgmt, filename, NULL);
        SetResContentType(msg, mime, str_len(mime));
    }

    return ret;
}

int AddResAppCBContent (void * vmsg, void * fetchfunc, void * fetchobj, int64 offset, int64 length,
                        void * movefunc, void * movepara, void * endfetch, void * endobj)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    chunk_add_cbdata(msg->res_body_chunk, fetchfunc, fetchobj, offset, length,
                     movefunc, movepara, endfetch, endobj);

    return 0;
}

int SetStatus (void * vmsg, int code, char * reason)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;

    if (!msg) return -1;

    mgmt = (HTTPMgmt *)msg->httpmgmt;

    /* set the status line */
    return http_res_statusline_set(msg, mgmt->httpver1, str_len(mgmt->httpver1), code, reason);
}

int Check304Resp (void * vmsg, uint64 mediasize, time_t mtime, uint32 inode)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    int        ret = 0, etaglen = 0;
    char       reqetag[64];
    char       etag[64];
    char     * pbgn = NULL;
    time_t     reqmtime = 0;

    if (!msg) return -1;

    GetResContentTypeP(msg, &pbgn, &ret);
    if (pbgn && ret == 21 && strncasecmp(pbgn, "application/x-mpegURL", 21) == 0) {
        msg->flag304 = 0;
        return 0;
    }

    /* get the value of http-header: If-None-Match */
    memset(reqetag, 0, sizeof(reqetag));
    etaglen = GetReqEtag(msg, reqetag, sizeof(reqetag)-1);

    GetReqHdrP(msg, "If-Modified-Since", -1, &pbgn, &ret);
    if (pbgn && ret > 0) str_gmt2time(pbgn, ret, &reqmtime);

    if (etaglen > 0 && reqmtime > 0 && mtime == reqmtime) {
        msg->flag304 = 1;
        SetResEtag(msg, reqetag, -1);

    } else if (mtime > 0 && mediasize > 0) {
        memset(etag, 0, sizeof(etag));
#if defined(_WIN32) || defined(_WIN64)
        sprintf(etag, "%I64x-%I64x", mediasize, mtime);
#else
        sprintf(etag, "%x-%llx-%lx", inode, mediasize, mtime);
#endif
        ret = str_len(etag);
 
        if (ret == str_len(reqetag) && memcmp(etag, reqetag, ret) == 0)
            msg->flag304 = 1;
        else
            msg->flag304 = 0;

        SetResEtag(msg, etag, -1);
    }

    if (!msg->flag304 && mtime > 0)
        http_header_append_date(msg, 1, "Last-Modified", -1, mtime);

    return 0;
}


int AsynReply (void * vmsg, int bodyend, int probewrite)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    int        ret = 0;
    time_t     gmtval = 0;
    char       rangestr[64];
 
    int64      fsize = 0;
    time_t     mtime = 0;
    long       inode = 0;
    char     * fname = NULL;
    char     * mime = NULL;
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)gp_httpmgmt;
    if (!mgmt) mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    if (http_msg_mgmt_get(mgmt, msg->msgid) != msg)
        return -100;
 
    if (msg->issued == 0) {
        msg->issued = 1;
 
        gmtval = time(NULL);
 
        memset(rangestr, 0, sizeof(rangestr));
 
        GetReqHdr(msg, "Super-Magic", -1, rangestr, sizeof(rangestr)-1);
        ret = atoi(rangestr);
        if (ret == 1) {
            AddResHdr(msg, "Random", -1, mgmt->uploadso, str_len(mgmt->uploadso));
            AddResHdr(msg, "RandomVar", -1, mgmt->uploadvar, str_len(mgmt->uploadvar));
        }
 
        /* append some necessary headers to fail-response */
        http_header_append(msg, 1, "Server", 6, mgmt->useragent, str_len(mgmt->useragent));
        if (http_header_get(msg, 1, "Date", 4) == NULL)
            http_header_append_date(msg, 1, "Date", 4, gmtval);
        //if (http_header_get(msg, 1, "Expires", 7) == NULL)
        //    http_header_append_date(msg, 1, "Expires", 7, gmtval + 24*3600);
        //if (http_header_get(msg, 1, "Cache-Control", 13) == NULL)
        //    http_header_append(msg, 1, "Cache-Control", 13, "no-cache", 8);
        //    http_header_append(msg, 1, "Cache-Control", 13, "max-age=86400", 13);
 
        if (msg->flag304) {
            http_res_statusline_set(msg, mgmt->httpver1, str_len(mgmt->httpver1), 304, "Not Modified");
            goto encoding;
        }
 
        if (chunk_is_file(msg->res_body_chunk, &fsize, &mtime, &inode, &fname)) {
            Check304Resp(msg, fsize, mtime, inode);
 
            if (msg->flag304) {
                http_res_statusline_set(msg, mgmt->httpver1, str_len(mgmt->httpver1), 304, "Not Modified");
                goto encoding;
            }
 
            if (http_header_get(msg, 1, "Content-Type", 12) == NULL && fname && str_len(fname) > 0) {
                mime = http_get_mime(msg->httpmgmt, fname, NULL);
                SetResContentType (msg, mime, str_len(mime));
            }
        }
 
        if (http_header_get(msg, 1, "Accept-Ranges", 13) == NULL)
            http_header_append(msg, 1, "Accept-Ranges", 13, "bytes", 5);
 
        if (msg->partial_flag > 0 && msg->res_status != 206)
            SetStatus(msg, 206, "Partial Content");
 
        if (msg->res_status < 100)
            SetStatus(msg, 200, NULL);
 
        if (msg->res_body_flag == BC_TE) {
            if (http_header_get(msg, 1, "Transfer-Encoding", 17) == NULL)
                http_header_append(msg, 1, "Transfer-Encoding", 17, "chunked", 7);
 
        } else {
            if (bodyend) {
                msg->res_body_length = chunk_size(msg->res_body_chunk, 0);
                SetResContentLength(msg, msg->res_body_length);
            }
        }
 
encoding:
        ret = http_res_encoding(msg);
        if (ret < 0) {
            msg->issued = 0;
            return ret;
        }
 
        msg->state = HTTP_MSG_REQUEST_HANDLED;
    }
 
    if (bodyend)
        chunk_set_end(msg->res_body_chunk);
 
    if (probewrite) {
        /* probing if the fd is wirte-ready. sending handling in http_cli_send
           is called when the fd is write-ready */
        http_cli_send_probe(msg->pcon);
 
    } else {
        /* directly send response to client without probing fd's wirtable */
        http_cli_send(msg->pcon);
    }
 
    return 0;
}
 
int Reply (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    return AsynReply(msg, 1, 0);
}
 
int ReplyFeeding (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    return AsynReply(msg, 0, 1);
}
 
int ReplyFeedingEnd (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    return AsynReply(msg, 1, 1);
}
 
int RedirectReply (void * vmsg, int status, char * url)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    int        ret = 0;
    time_t     gmtval = 0;
 
    if (!msg) return -1;
    if (!url) return -2;
 
    mgmt = (HTTPMgmt *)gp_httpmgmt;
    if (!mgmt) mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    if (http_msg_mgmt_get(mgmt, msg->msgid) != msg)
        return -100;
 
    gmtval = time(NULL);
 
    http_header_append(msg, 1, "Location", 8, url, str_len(url));
 
    if (status < 300 || status >= 400) status = 302;
 
    SetStatus(msg, status, NULL);
 
    /* append some necessary headers to fail-response */
 
    http_header_append(msg, 1, "Server", 6, mgmt->useragent, str_len(mgmt->useragent));
 
    if (http_header_get(msg, 1, "Accept-Ranges", 13) == NULL)
        http_header_append(msg, 1, "Accept-Ranges", 13, "bytes", 5);
 
    if (http_header_get(msg, 1, "Date", 4) == NULL)
        http_header_append_date(msg, 1, "Date", 4, gmtval);
 
    //if (http_header_get(msg, 1, "Expires", 7) == NULL)
    //    http_header_append_date(msg, 1, "Expires", 7, gmtval + 24*3600);
 
    if (http_header_get(msg, 1, "Cache-Control", 13) == NULL)
        http_header_append(msg, 1, "Cache-Control", 13, "no-cache", 8);
        //http_header_append(msg, 1, "Cache-Control", 13, "max-age=86400", 13);
 
    ret = http_res_encoding(msg);
    if (ret < 0) return ret;
 
    msg->issued = 1;
    msg->state = HTTP_MSG_REQUEST_HANDLED;
 
    chunk_set_end(msg->res_body_chunk);
 
    /* directly send response to client without probing if the fd is wirte-ready */
    return http_cli_send(msg->pcon);
    //return http_cli_send_probe(msg->pcon);
}

