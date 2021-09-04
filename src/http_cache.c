/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_header.h"
#include "http_listen.h"
#include "http_variable.h"
#include "http_cache.h"

extern HTTPMgmt * gp_httpmgmt;

void * cache_info_alloc ()
{
    CacheInfo * cacinfo = NULL;

    cacinfo = kzalloc(sizeof(*cacinfo));
    if (!cacinfo) return NULL;

    InitializeCriticalSection(&cacinfo->cacheCS);

    cacinfo->frag = frag_pack_alloc();

    return cacinfo;
}

void cache_info_free (void * vcacinfo)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;

    if (!cacinfo) return;

    if (frag_pack_complete(cacinfo->frag)) {
        if (strcmp(cacinfo->cache_tmp, cacinfo->cache_file) != 0)
            rename(cacinfo->cache_tmp, cacinfo->cache_file);
    }

    if (cacinfo->cache_file) {
        kfree(cacinfo->cache_file);
        cacinfo->cache_file = NULL;
    }

    if (cacinfo->cache_tmp) {
        kfree(cacinfo->cache_tmp);
        cacinfo->cache_tmp = NULL;
    }
 
    if (cacinfo->info_file) {
        kfree(cacinfo->info_file);
        cacinfo->info_file = NULL;
    }

    if (cacinfo->hinfo) {
        native_file_close(cacinfo->hinfo);
        cacinfo->hinfo = NULL;
    }

    if (cacinfo->frag) {
        frag_pack_free(cacinfo->frag);
        cacinfo->frag = NULL;
    }

    DeleteCriticalSection(&cacinfo->cacheCS);

    kfree(cacinfo);
}

int cache_info_zero (void * vcacinfo)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;
 
    if (!cacinfo) return -1;
 
    if (cacinfo->cache_file) {
        kfree(cacinfo->cache_file);
        cacinfo->cache_file = NULL;
    }
 
    if (cacinfo->cache_tmp) {
        kfree(cacinfo->cache_tmp);
        cacinfo->cache_tmp = NULL;
    }
 
    if (cacinfo->info_file) {
        kfree(cacinfo->info_file);
        cacinfo->info_file = NULL;
    }
 
    if (cacinfo->hinfo) {
        native_file_close(cacinfo->hinfo);
        cacinfo->hinfo = NULL;
    }
 
    cacinfo->body_flag = 0;
    cacinfo->header_length = 0;
    cacinfo->body_length = 0;
    cacinfo->body_rcvlen = 0;

    cacinfo->directive = 0;
    cacinfo->revalidate = 0;
    cacinfo->pubattr = 0;

    cacinfo->ctime = 0;
    cacinfo->expire = 0;
    cacinfo->maxage = 0;
    cacinfo->mtime = 0;
    memset(cacinfo->etag, 0, sizeof(cacinfo->etag));

    if (cacinfo->frag) {
        frag_pack_zero(cacinfo->frag);
    }

    return 0;
}

int64 cache_info_body_length (void * vcacinfo)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;
 
    if (!cacinfo) return -1;
 
    return cacinfo->body_length;
}

static char * cache_info_file (char * cafile, int cafnlen)
{
    int         pathlen = 0;
    char      * fname = NULL;
    int         fnlen = 0;
    char      * p = NULL;
    int         len = 0;

    if (!cafile) return NULL;
    if (cafnlen < 0) cafnlen = strlen(cafile);
    if (cafnlen <= 0) return NULL;
 
    p = rskipTo(cafile + cafnlen - 1, cafnlen, "/\\", 2);
    if (p < cafile) {
        fname = cafile;
        fnlen = cafnlen;
        pathlen = 0;
    } else {
        fname = p + 1;
        fnlen = cafile + cafnlen - fname;
        pathlen = fname - cafile;
    }
 
    /* path/.cacheinfo/fname.ext.cacinf, or ./.cacheinfo/fname.ext */
    len = cafnlen + 2 + 11 + 7 + 1;
    p = kalloc(len);
 
    if (pathlen <= 0) {
#if defined(_WIN32) || defined(_WIN64)
        strcpy(p, ".\\");
#else
        strcpy(p, "./");
#endif
    } else {
        str_secpy(p, len-1, cafile, pathlen);
    }
 
#if defined(_WIN32) || defined(_WIN64)
    str_secpy(p + strlen(p), len - 1 - strlen(p), ".cacheinfo\\", 11);
#else
    str_secpy(p + strlen(p), len - 1 - strlen(p), ".cacheinfo/", 11);
#endif
    str_secpy(p + strlen(p), len - 1 - strlen(p), fname, fnlen);

    str_secpy(p + strlen(p), len - 1 - strlen(p), ".cacinf", 7);

    return p;
}

int cache_info_read (void * vcacinfo)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;
    uint8       buf[96];
    int         val32 = 0;
    int64       val64 = 0;
    int         iter = 0;

    if (!cacinfo) return -1;
    if (!cacinfo->hinfo) return -2;

    native_file_seek(cacinfo->hinfo, 0);
    native_file_read(cacinfo->hinfo, buf, 96);

    if (strncasecmp((char *)buf + iter, "EJT", 3) != 0) {
        return -100; 
    }

    iter += 3;

    memcpy(&val32, buf+iter, 4);  iter += 4;
    cacinfo->mimeid = ntohl(val32);

    cacinfo->body_flag = buf[iter];  iter++;

    memcpy(&val32, buf+iter, 4);  iter += 4;
    cacinfo->header_length = ntohl(val32);

    memcpy(&val64, buf+iter, 8);  iter += 8;
    cacinfo->body_length = ntohll(val64);

    memcpy(&val64, buf+iter, 8);  iter += 8;
    cacinfo->body_rcvlen = ntohll(val64);

    cacinfo->directive = buf[iter];  iter++;
    cacinfo->revalidate = buf[iter];  iter++;
    cacinfo->pubattr = buf[iter];  iter++;

    memcpy(&val64, buf+iter, 8);  iter += 8;
    cacinfo->ctime = ntohll(val64);

    memcpy(&val64, buf+iter, 8);  iter += 8;
    cacinfo->expire = ntohll(val64);

    memcpy(&val32, buf+iter, 4);  iter += 4;
    cacinfo->maxage = ntohl(val32);

    memcpy(&val64, buf+iter, 8);  iter += 8;
    cacinfo->mtime = ntohll(val64);

    memcpy(cacinfo->etag, buf+iter, 32);  iter += 32;

    frag_pack_read(cacinfo->frag, cacinfo->hinfo, 96);

    if (cacinfo->body_length > 0 && frag_pack_length(cacinfo->frag) <= 0)
        frag_pack_set_length(cacinfo->frag, cacinfo->body_length);

    return 0;
}

int cache_info_write_meta (void * vcacinfo)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;
    uint8       buf[96];
    int         val32 = 0;
    int64       val64 = 0;
    int         iter = 0;
 
    if (!cacinfo) return -1;
    if (!cacinfo->hinfo) return -2;
 
    memset(buf, 0, sizeof(buf));

    memcpy(buf+iter, "EJT", 3);           iter += 3;

    val32 = htonl(cacinfo->mimeid);
    memcpy(buf+iter, &val32, 4);          iter += 4;

    buf[iter] = cacinfo->body_flag;       iter++;

    val32 = htonl(cacinfo->header_length);
    memcpy(buf+iter, &val32, 4);          iter += 4;

    val64 = htonll(cacinfo->body_length);
    memcpy(buf+iter, &val64, 8);          iter += 8;

    val64 = htonll(cacinfo->body_rcvlen);
    memcpy(buf+iter, &val64, 8);          iter += 8;

    buf[iter] = cacinfo->directive;       iter++;
    buf[iter] = cacinfo->revalidate;      iter++;
    buf[iter] = cacinfo->pubattr;         iter++;

    val64 = cacinfo->ctime; val64 = htonll(val64);
    memcpy(buf+iter, &val64, 8);          iter += 8;

    val64 = cacinfo->expire; val64 = htonll(val64);
    memcpy(buf+iter, &val64, 8);          iter += 8;

    val32 = cacinfo->maxage; val32 = htonl(val32);
    memcpy(buf+iter, &val32, 4);          iter += 4;

    val64 = cacinfo->mtime; val64 = htonll(val64);
    memcpy(buf+iter, &val64, 8);          iter += 8;

    str_secpy(buf+iter, 32, cacinfo->etag, str_len(cacinfo->etag));
    iter += 32;

    native_file_seek(cacinfo->hinfo, 0);
    native_file_write(cacinfo->hinfo, buf, 96);

    return 0;
}

int cache_info_write_frag (void * vcacinfo)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;
 
    if (!cacinfo) return -1;
    if (!cacinfo->hinfo) return -2;
 
    return frag_pack_write(cacinfo->frag, cacinfo->hinfo, 96);
}

int cache_info_write (void * vcacinfo)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;
    int         len = 0;
 
    if (!cacinfo) return -1;
    if (!cacinfo->hinfo) return -2;
 
    cache_info_write_meta(cacinfo);
    len = cache_info_write_frag(cacinfo);

    if (len >= 12) {
        native_file_resize(cacinfo->hinfo, 96 + len);
    }

    return 0;
}

int cache_info_add_frag (void * vcacinfo, int64 pos, int64 len, int complete)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;
    int         fragnum = 0;
    int64       rcvlen = 0;
    int         ret = 0;
 
    if (!cacinfo) return -1;
    if (!cacinfo->frag) return -2;
 
    EnterCriticalSection(&cacinfo->cacheCS);

    frag_pack_add(cacinfo->frag, pos, len);

    cacinfo->body_rcvlen += len;

    if (complete) {
        rcvlen = frag_pack_rcvlen(cacinfo->frag, &fragnum);
        if (fragnum == 1 && rcvlen == frag_pack_curlen(cacinfo->frag)) {
            frag_pack_set_length(cacinfo->frag, rcvlen);
            cacinfo->body_length = rcvlen;
        }
    }

    ret = cache_info_write(cacinfo);

    LeaveCriticalSection(&cacinfo->cacheCS);

    return ret;
}

int cache_info_verify (void * vcacinfo)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;
 
    if (!cacinfo) return -1;

    if (cacinfo->directive > 0) //0-max-age  1-no cache  2-no store
        return 0;

    if (cacinfo->revalidate > 0)  //0-none  1-must-revalidate
        return 0;

    if (cacinfo->expire > 0 && cacinfo->expire > time(NULL))
        return 0;

    if (cacinfo->maxage > 0 && cacinfo->mtime + cacinfo->maxage > time(NULL))
        return 0;

    return 1;
}


int cache_info_cmp_key (void * a, void * b)
{
    CacheInfo * cacinfo = (CacheInfo *)a;
    char      * fname = (char *)b;

    if (!a) return -1;
    if (!b) return 1;

    return strcmp(cacinfo->cache_file, fname);
}

int http_cache_info_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    InitializeCriticalSection(&mgmt->cacinfoCS);

    mgmt->cacinfo_table = ht_new(200, cache_info_cmp_key);

    tolog(1, "eJet - Proxy Cache resource allocated successfully.\n");
    return 0;
}

int http_cache_info_clean (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    DeleteCriticalSection(&mgmt->cacinfoCS);

    if (mgmt->cacinfo_table) {
        ht_free_all(mgmt->cacinfo_table, cache_info_free);
        mgmt->cacinfo_table = NULL;
    }

    tolog(1, "eJet - Proxy Cache resources cleaned.\n");
    return 0;
}

void * cache_info_open (void * vmgmt, char * cafile)
{
    HTTPMgmt    * mgmt = (HTTPMgmt *)vmgmt;
    CacheInfo   * cacinfo = NULL;
    int           cafnlen = 0;
    struct stat   st;
    char        * fname = NULL;
    void        * hinfo = NULL;

    if (!mgmt) return NULL;

    if (!cafile || (cafnlen = strlen(cafile)) <= 0)
        return NULL;

    EnterCriticalSection(&mgmt->cacinfoCS);

    cacinfo = ht_get(mgmt->cacinfo_table, cafile);

    if (cacinfo) {
        cacinfo->count++;
        LeaveCriticalSection(&mgmt->cacinfoCS);
        return cacinfo;
    }

    /* according to actual filename.ext, generate cacheinfo file: ./.cacheinfo/filename.ext.cacinf  */
 
    fname = cache_info_file(cafile, cafnlen);
    if (!fname) goto nullret;
 
    if (file_stat(fname, &st) < 0) {//Cache Info file not exist
        kfree(fname);
        goto nullret;
    }
 
    hinfo = native_file_open(fname, NF_READ | NF_WRITE);
    if (!hinfo) {
        kfree(fname);
        goto nullret;
    }
 
    cacinfo = cache_info_alloc();
    if (!cacinfo) {
        kfree(fname);
        native_file_close(hinfo);
        goto nullret;
    }
    cacinfo->httpmgmt = mgmt;

    cacinfo->info_file = fname;
    cacinfo->hinfo = hinfo;
 
    if (cache_info_read(cacinfo) < 0) {
        cache_info_free(cacinfo);
        goto nullret;
    }
 
    cacinfo->cache_file = str_dup(cafile, cafnlen);
    cacinfo->cache_tmp = kzalloc(cafnlen + 4 + 1);
    sprintf(cacinfo->cache_tmp, "%s.tmp", cafile);
 
    if (frag_pack_curlen(cacinfo->frag) > 0 &&
        frag_pack_complete(cacinfo->frag) == 0 &&
        (file_stat(cacinfo->cache_tmp, &st) < 0 || st.st_size <= 0))
    {
        frag_pack_zero(cacinfo->frag);
        cacinfo->body_rcvlen = 0;
    }
 
    cacinfo->count = 1;
 
    ht_set(mgmt->cacinfo_table, cafile, cacinfo);

    LeaveCriticalSection(&mgmt->cacinfoCS);
    return cacinfo;

nullret:
    LeaveCriticalSection(&mgmt->cacinfoCS);
    return NULL;
}

void cache_info_close (void * vcacinfo)
{
    CacheInfo * cacinfo = (CacheInfo *)vcacinfo;
    HTTPMgmt  * mgmt = NULL;

    if (!cacinfo) return;

    mgmt = gp_httpmgmt;
    if (!mgmt) mgmt = cacinfo->httpmgmt;
    if (!mgmt) return;

    EnterCriticalSection(&mgmt->cacinfoCS);

    cacinfo = ht_get(mgmt->cacinfo_table, cacinfo->cache_file);
    if (!cacinfo) {
        LeaveCriticalSection(&mgmt->cacinfoCS);
        return;
    }

    if (--cacinfo->count <= 0) {
        ht_delete(mgmt->cacinfo_table, cacinfo->cache_file);

        cache_info_free(cacinfo);
        LeaveCriticalSection(&mgmt->cacinfoCS);
        return;
    }

    LeaveCriticalSection(&mgmt->cacinfoCS);
}


void * cache_info_create (void * vmgmt, char * cafile, int64 fsize)
{
    HTTPMgmt    * mgmt = (HTTPMgmt *)vmgmt;
    CacheInfo   * cacinfo = NULL;
    int           cafnlen = 0;
    char        * fname = NULL;
    void        * hinfo = NULL;

    if (!mgmt) return NULL;

    if (!cafile || (cafnlen = strlen(cafile)) <= 0)
        return NULL;

    EnterCriticalSection(&mgmt->cacinfoCS);
    cacinfo = ht_get(mgmt->cacinfo_table, cafile);

    if (cacinfo) {
        cacinfo->count++;

        if (fsize > 0) {
            cacinfo->body_length = fsize;
            frag_pack_set_length(cacinfo->frag, fsize);
        }
 
        LeaveCriticalSection(&mgmt->cacinfoCS);
        return cacinfo;
    }

    fname = cache_info_file(cafile, cafnlen);
    if (!fname) goto nullret;
 
    file_dir_create(fname, 1);
 
    hinfo = native_file_open(fname, NF_READ | NF_WRITE);
    if (!hinfo) {
        kfree(fname);
        goto nullret;
    }
 
    cacinfo = cache_info_alloc();
    if (!cacinfo) {
        kfree(fname);
        native_file_close(hinfo);
        goto nullret;
    }
    cacinfo->httpmgmt = mgmt;

    cacinfo->info_file = fname;
    cacinfo->hinfo = hinfo;

    cacinfo->cache_file = str_dup(cafile, cafnlen);
    cacinfo->cache_tmp = kzalloc(cafnlen + 4 + 1);
    sprintf(cacinfo->cache_tmp, "%s.tmp", cafile);
 
    if (fsize > 0) {
        cacinfo->body_length = fsize;
        frag_pack_set_length(cacinfo->frag, fsize);
    }
 
    cacinfo->count = 1;

    ht_set(mgmt->cacinfo_table, cafile, cacinfo);

    LeaveCriticalSection(&mgmt->cacinfoCS);
    return cacinfo;
 
nullret:
    LeaveCriticalSection(&mgmt->cacinfoCS);
    return NULL;
}


int http_request_cache_init (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    char         path[512];
    ulong        hash;
    char       * ctype = NULL;
    char       * extname = NULL;
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    if (msg->req_file_handle) return 0;
 
#if defined(_WIN32) || defined(_WIN64)
    snprintf(path, sizeof(path) - 1, "%s\\ucache", msg->GetRootPath(msg));
#else
    snprintf(path, sizeof(path) - 1, "%s/ucache", msg->GetRootPath(msg));
#endif

    hash = generic_hash(msg->docuri->path, msg->docuri->pathlen, 0);
    hash = hash % 307;
 
#if defined(_WIN32) || defined(_WIN64)
    sprintf(path+strlen(path), "\\%lu\\", hash);
#else
    sprintf(path+strlen(path), "/%lu/", hash);
#endif
    file_dir_create(path, 0);
 
    msg->GetReqContentTypeP(msg, &ctype, NULL);
    mime_type_get_by_mime(mgmt->mimemgmt, ctype, &extname, NULL, NULL);
 
    sprintf(path+strlen(path), "%s-%ld%s",
            msg->srcip, msg->msgid, extname);
 
    msg->req_file_name = str_dup(path, strlen(path));
 
    msg->req_file_handle = native_file_open(path, NF_WRITEPLUS);
 
    msg->req_file_cache = 1;
 
    if (native_file_size(msg->res_file_handle) > 0) {
        native_file_resize(msg->res_file_handle, 0);
    }
 
    return 1;
}

int http_response_cache_init (void * vmsg)
{
    HTTPMsg        * msg = (HTTPMsg *)vmsg;
    HTTPMgmt       * mgmt = NULL;
    HTTPLoc        * ploc = NULL;
    char           * cachefn = NULL;
    int              fnlen = 0;
    char             buf[2048];
    int              ret = 0;
    http_partial_t * part = NULL;
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    if (msg->res_file_handle)
        return 0;
 
    if (msg->res_store_file) {
        msg->res_file_handle = native_file_open(msg->res_store_file, NF_WRITEPLUS);
        msg->res_file_cache = 2;
 
        if (msg->res_file_handle && msg->res_store_offset > 0) {
            native_file_seek(msg->res_file_handle, msg->res_store_offset);
 
        } else if (native_file_size(msg->res_file_handle) > 0) {
            native_file_resize(msg->res_file_handle, 0);
        }
 
        goto end;
    }
 
    ploc = (HTTPLoc *)msg->ploc;
    if (ploc) {
        if (ploc->cache == 0 || str_len(ploc->cachefile) <= 0)
            return 0;
 
        cachefn = ploc->cachefile;
        fnlen = strlen(cachefn);
 
    } else {
        if (mgmt->srv_resp_cache == 0 || strlen(mgmt->srv_resp_cache_file) <= 0)
            return 0;
 
        cachefn = mgmt->srv_resp_cache_file;
        fnlen = strlen(cachefn);
    }
 
    ret = http_var_copy(msg, cachefn, fnlen, buf, sizeof(buf)-1, NULL, 0, "cache file", 4);
    if (ret <= 0) return 0;
 
    for (ret = 0; ret < (int)strlen(buf); ret++) {
        if (buf[ret] == ':') { //ignore the colon in drive of path D:\prj\src\disk.txt
            if (ret > 1) buf[ret] = '_';
        } else if (buf[ret] == '?') buf[ret] = '_';
#if defined(_WIN32) || defined(_WIN64)
        else if (buf[ret] == '/') buf[ret] = '\\';
#endif
    }

    msg->res_file_name = str_dup(buf, strlen(buf));
    file_dir_create(msg->res_file_name, 1);
 
    msg->res_file_handle = native_file_open(msg->res_file_name, NF_WRITEPLUS);
 
    msg->res_file_cache = 1;
 
    /* if client request contains Range header, then we should seek to given pos */
    if (msg->partial_flag > 0) {
        part = vstar_get(msg->partial_list, 0);
        if (part && part->start > 0)
            native_file_seek(msg->res_file_handle, part->start);
    }
 
    /*if (native_file_size(msg->res_file_handle) > 0) {
        native_file_resize(msg->res_file_handle, 0);
    }*/
 
end:
    return msg->res_file_cache;
}


int http_request_in_cache (void * vmsg)
{
    HTTPMsg        * msg = (HTTPMsg *)vmsg;
    http_partial_t * part = NULL;
    CacheInfo      * cacinfo = NULL;
    int64            gappos = 0;
    int64            gaplen = 0;
    int64            reqpos = 0;
    int64            reqlen = 0;
    int64            start = 0;
    int64            length = 0;
    int              i, num, ret;
    int              incache = 1;
    uint8            execed = 0;
 
    if (!msg) return -1;

    cacinfo = msg->res_cache_info;
    if (!cacinfo) return 0;
 
    /* check the client request data is in local cache completely.
       if client request contains Range header, then we should seek to given pos */
    incache = 1;
    if (msg->partial_flag > 0) {
        num = vstar_num(msg->partial_list);
        for (i = 0; i < num; i++) {
            part = vstar_get(msg->partial_list, i);
            if (!part) continue;

            if (part->partflag == 1) {
                start = part->start;
                length = part->length;
            } else if (part->partflag == 2) {
                start = part->start;
                if (cacinfo->body_length > 0)
                    length = cacinfo->body_length - start;
                else
                    length = -1;
            } else if (part->partflag == 3) {
                length = part->length;
                if (cacinfo->body_length > 0)
                    start = cacinfo->body_length - length;
                else
                    start = cacinfo->body_rcvlen - length;
            } else {
                start = part->start;
                length = part->length;
            }

            ret = frag_pack_contain(cacinfo->frag, start, length,
                                    &reqpos, &reqlen, &gappos, &gaplen);
            if (ret < 3) { //ret 0:not in cache 1:right-side partial 2:left-side partial 3:in cache
                incache = 0;
            }
            execed = 1;

            msg->cache_req_off = gappos;
            msg->cache_req_len = gaplen;
            msg->cache_req_start = start;

            break;
        }
    } 

    if (!execed) {
        ret = frag_pack_contain(cacinfo->frag, 0, -1, &reqpos, &reqlen, &gappos, &gaplen);
        if (ret < 3) { //ret 0:not in cache 1:right-side partial 2:left-side partial 3:in cache
            incache = 0;
        }
        msg->cache_req_off = gappos;
        msg->cache_req_len = gaplen;
        msg->cache_req_start = 0;
    }
 
    return incache;
}

int http_proxy_cache_open (void * vmsg)
{
    HTTPMsg        * msg = (HTTPMsg *)vmsg;
    HTTPMgmt       * mgmt = NULL;
    HTTPLoc        * ploc = NULL;
    char           * cachefn = NULL;
    int              fnlen = 0;
    char             buf[1024];
    int              ret = 0;
    CacheInfo      * cacinfo = NULL;
    int              incache = 0;
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    ploc = (HTTPLoc *)msg->ploc;
    if (ploc) {
        if (ploc->cache == 0 || str_len(ploc->cachefile) <= 0) {
            msg->cacheon = 0;
            return 0;
        }
 
        cachefn = ploc->cachefile;
        fnlen = strlen(cachefn);
 
    } else {
        if (mgmt->srv_resp_cache == 0 || strlen(mgmt->srv_resp_cache_file) <= 0) {
            msg->cacheon = 0;
            return 0;
        }
 
        cachefn = mgmt->srv_resp_cache_file;
        fnlen = strlen(cachefn);
    }
    msg->cacheon = 1;
 
    ret = http_var_copy(msg, cachefn, fnlen, buf, sizeof(buf)-1, NULL, 0, "cache file", 4);
    if (ret <= 0) {
        msg->cacheon = 0;
        return 0;
    }
 
    for (ret = 0; ret < (int)strlen(buf); ret++) {
        if (buf[ret] == ':') { //ignore the colon in drive of path D:\prj\src\disk.txt
            if (ret > 1) buf[ret] = '_';
        } else if (buf[ret] == '?') buf[ret] = '_';
#if defined(_WIN32) || defined(_WIN64)
        else if (buf[ret] == '/') buf[ret] = '\\';
#endif
    }

    msg->res_file_name = str_dup(buf, strlen(buf));
    if (file_is_regular(msg->res_file_name)) {
        msg->res_file_cache = 3;
        incache = 2;
    }

    cacinfo = msg->res_cache_info = cache_info_open(mgmt, buf);
    if (!cacinfo) {
        msg->res_file_cache = 0;
        return msg->res_file_cache;
    }

    if (incache <= 0) {
        /* check the client request data is in local cache completely.
           if client request contains Range header, then we should seek to given pos */
        incache = http_request_in_cache(msg);
    
        /* if request file is in local cache, and local cache file has stored all file data.
           or request Ranges data are found in local cache, just return 3 to indicate
           the response is from local cache file */
        if (incache || frag_pack_complete(cacinfo->frag)) {
            msg->res_file_cache = 4;
        }
    }

    return msg->res_file_cache;
}

static char * str2int64 (char * pbgn, int len, int64 * pval)
{
    int64 val = 0;
    int   i;
 
    for (i = 0; i < len && isdigit(pbgn[i]); i++) {
        val *= 10; val += pbgn[i] - '0';
    }
 
    if (pval) *pval = val;
 
    return pbgn + i;
}

int http_proxy_cache_parse (void * vmsg, void * vclimsg, int * resend)
{
    HTTPMsg        * msg = (HTTPMsg *)vmsg;
    HTTPMsg        * climsg = (HTTPMsg *)vclimsg;
    CacheInfo      * cacinfo = NULL;
    HeaderUnit     * punit = NULL;
    char           * pbgn = NULL;
    char           * pend = NULL;
    char           * poct = NULL;
    int              len = 0;

    uint8            directive = 0;     //0-max-age  1-no cache  2-no store
    uint8            revalidate = 0;    //0-none  1-must-revalidate
    uint8            pubattr = 0;       //0-unknonw  1-public  2-private(only browser cache)
    time_t           expire = 0;
    int              maxage = 0;
    time_t           mtime = 0;
    char             etag[36] = {0};

    uint8            hasrange = 0;
    int64            start = 0;
    int64            end = 0;
    int64            size = 0;
 
    char           * plist[8];
    int              plen[8];
    int              i, num;
 
    if (resend) *resend = 0;

    if (!msg) return -1;
    if (!climsg) return -1;

    if (!msg->cacheon) return -100;
 
    if (climsg->issued) return 0;

    if (msg->res_status >= 300 || msg->res_status < 200) {
        msg->cacheon = 0;
        climsg->cacheon = 0;
        return -200;
    }

    punit = http_header_get(msg, 1, "Expires", -1);
    if (punit && punit->valuelen > 0) {
        str_gmt2time(HUValue(punit), punit->valuelen, &expire);
    }
 
    punit = http_header_get(msg, 1, "Last-Modified", -1);
    if (punit && punit->valuelen > 0) {
        str_gmt2time(HUValue(punit), punit->valuelen, &mtime);
    }
 
    memset(etag, 0, sizeof(etag));
    punit = http_header_get(msg, 1, "ETag", -1);
    if (punit && punit->valuelen > 0) {
        pbgn = HUValue(punit);
        pend = pbgn + punit->valuelen;
        poct = skipTo(pbgn, pend-pbgn, "\"", 1);
 
        if (poct >= pend) {
            len = pend - pbgn;
        } else {
            pbgn = poct + 1;
            poct = skipTo(pbgn, pend-pbgn, "\"", 1);
            len = poct - pbgn;
        }
 
        str_secpy(etag, sizeof(etag)-1, pbgn, len);
    }
 
    punit = http_header_get(msg, 1, "Cache-Control", -1);
    if (punit && punit->valuelen > 0) {
        num = string_tokenize(HUValue(punit), punit->valuelen, ",", 1, (void **)plist, plen, 8);
        for (i = 0; i < num; i++) {
            pbgn = plist[i];
            pend = pbgn + plen[i];
            pbgn = skipOver(pbgn, pend-pbgn, ", \t", 3);
            poct = rskipOver(pend-1, pend-pbgn, ", \t", 3);
            if (poct < pbgn) continue;
            pend = poct + 1;
            len = pend - pbgn;
 
            if (len >= 8 && strncasecmp(pbgn, "no-cache", 8) == 0) {
                directive = 1; //no cache
 
            } else if (len >= 8 && strncasecmp(pbgn, "no-store", 8) == 0) {
                directive = 2; //no store
 
            } else if (len >= 7 && strncasecmp(pbgn, "max-age", 7) == 0) {
                directive = 0; //max-age
                pbgn = skipTo(pbgn + 7, pend-pbgn-7, "=", 1);
                if (pbgn > pend) {
                    maxage = 0;
                } else {
                    pbgn = skipOver(pbgn, pend-pbgn, "= \t", 3);
                    if (isdigit(*pbgn))
                        maxage = str_to_int(pbgn, pend-pbgn, 10, NULL);
                    else
                        maxage = 0;
                }
 
            } else if (len >= 15 && strncasecmp(pbgn, "must-revalidate", 15) == 0) {
                revalidate = 1; //must-revalidate
 
            } else if (len >= 6 && strncasecmp(pbgn, "public", 6) == 0) {
                pubattr = 1; //public
 
            } else if (len >= 7 && strncasecmp(pbgn, "private", 7) == 0) {
                pubattr = 2; //private
            }
        }
    }
 
    if (directive > 0                   ||   /* no-cache or no-store */
        (directive == 0 && maxage == 0) ||   /* max-age set but value is 0 */
        revalidate)                          /* set must-revalidate directive */
    {
        climsg->cacheon = 0;
        msg->cacheon = 0;

        if (climsg->res_cache_info) {
            cache_info_close(climsg->res_cache_info);
            climsg->res_cache_info = NULL;
        }

        /* now check if the proxy response body is original requested Range */
        if (climsg->cache_req_start != climsg->cache_req_off) {
            if (resend) *resend = 1;
        }
    }

    if (!msg->cacheon) return 0;

    punit = http_header_get(msg, 1, "Content-Range", -1);
    if (punit && punit->valuelen >= 5) {  //Content-Range: bytes 1000-5000/29387
        pbgn = HUValue(punit);
        pend = pbgn + punit->valuelen;
        if (strncasecmp(pbgn, "bytes", 5) == 0) {
            pbgn = skipOver(pbgn+5, pend-pbgn-5, " \t\r\n\f\v", 6);
            num = string_tokenize(pbgn, pend-pbgn, "-/ \t", 4, (void **)plist, plen, 8);
            if (num > 0) str2int64(plist[0], plen[0], &start);
            if (num > 1) str2int64(plist[1], plen[1], &end);
            if (num > 2) str2int64(plist[2], plen[2], &size);
            hasrange = 1;
        }
    }

    if ((cacinfo = climsg->res_cache_info) == NULL) {
        cacinfo = cache_info_create (msg->httpmgmt,
                                     climsg->res_file_name,
                                     msg->res_body_length);
        if (!cacinfo) {
            msg->cacheon = climsg->cacheon = 0;
            return -200;
        }

        climsg->res_cache_info = cacinfo;
    }

    EnterCriticalSection(&cacinfo->cacheCS); 

    cacinfo->directive = directive;
    cacinfo->revalidate = revalidate;
    cacinfo->pubattr = pubattr;
    if (cacinfo->ctime == 0)
        cacinfo->ctime = time(NULL); 
    cacinfo->expire = expire;
    cacinfo->maxage = maxage;
    cacinfo->mtime = mtime;
    if (cacinfo->mtime == 0)
        cacinfo->mtime = time(NULL); 
    str_secpy(cacinfo->etag, sizeof(cacinfo->etag), etag, strlen(etag));

    msg->GetResContentTypeID(msg, &cacinfo->mimeid, NULL);

    cacinfo->body_flag = msg->res_body_flag;
    cacinfo->header_length = msg->res_header_length;

    if (msg->res_body_length > 0 && 
        climsg->cache_req_off == 0 && 
        climsg->cache_req_len < 0)
        cacinfo->body_length = msg->res_body_length;

    climsg->res_file_handle = native_file_open(cacinfo->cache_tmp, NF_READ | NF_WRITE);

    if (hasrange) {
        num = native_file_seek(climsg->res_file_handle, start);
        if (size > 0) {
            if (cacinfo->body_length != size)
                cacinfo->body_length = size;
            if (frag_pack_length(cacinfo->frag) != size)
                frag_pack_set_length(cacinfo->frag, size);
        }

    } else {
        num = native_file_seek(climsg->res_file_handle, climsg->cache_req_start);
    }

    cache_info_write_meta(cacinfo);

    LeaveCriticalSection(&cacinfo->cacheCS); 

    return 1;
}

int http_proxy_cache_complete (void * vmsg)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    CacheInfo   * cacinfo = NULL;

    if (!msg) return -1;
 
    if (!msg->cacheon) return -100;
 
    cacinfo = (CacheInfo *)msg->res_cache_info;
    if (!cacinfo) return -101;

    if (frag_pack_complete(cacinfo->frag)) {
        /* cache file has gotton all bytes, now copy or rename to origin file */
        if (strcmp(cacinfo->cache_file, msg->res_file_name) != 0)
            rename(cacinfo->cache_file, msg->res_file_name);
    }

    return 0;
}

int http_cache_response_header (void * vmsg, void * vcacinfo)
{
    HTTPMsg        * climsg = (HTTPMsg *)vmsg;
    CacheInfo      * cacinfo = (CacheInfo *)vcacinfo;
    http_partial_t * part = NULL;
    int64            start = 0;
    int64            end = 0;
    int64            length = 0;
    char             buf[128];
 
    if (!climsg) return -1;
 
    if (!cacinfo) cacinfo = (CacheInfo *)climsg->res_cache_info;
    if (!cacinfo) return -3;
 
    http_header_del(climsg, 1, "ETag", 4);
    http_header_del(climsg, 1, "Content-Length", 14);
    http_header_del(climsg, 1, "Content-Range", 13);
    http_header_del(climsg, 1, "Transfer-Encoding", 17);
 
    if (cacinfo->body_length > 0) {
        climsg->res_body_flag = BC_CONTENT_LENGTH;
 
        if (climsg->partial_flag > 0) {
            part = vstar_get(climsg->partial_list, 0);
            switch (part->partflag) {
            case 1:
                start = part->start >= cacinfo->body_length ? cacinfo->body_length : part->start;
                end = part->end >= cacinfo->body_length ? cacinfo->body_length - 1 : part->end;
                length = end - start + 1;
                break;
            case 2:
                start = part->start >= cacinfo->body_length ? cacinfo->body_length : part->start;
                length = cacinfo->body_length - start;
                end = start + length - 1;
                break;
            case 3:
                length = part->length > cacinfo->body_length ? cacinfo->body_length : part->length;
                start = cacinfo->body_length - length;
                end = cacinfo->body_length - 1;
            }
 
            climsg->res_body_length = length;
            http_header_append_int64(climsg, 1, "Content-Length", 14, length);
 
#if defined(_WIN32) || defined(_WIN64)
            sprintf(buf, "bytes %I64d-%I64d/%I64d", start, end, cacinfo->body_length);
#else
            sprintf(buf, "bytes %lld-%lld/%lld", start, end, cacinfo->body_length);
#endif
            http_header_append(climsg, 1, "Content-Range", 13, buf, strlen(buf));
 
            if (length < cacinfo->body_length) {
                if (climsg->res_status >= 200 && climsg->res_status < 300)
                    climsg->SetStatus(climsg, 206, NULL);

            } else {
                if (climsg->res_status > 200 && climsg->res_status < 300)
                    climsg->SetStatus(climsg, 200, NULL);
            }

        } else {
            http_header_append_int64(climsg, 1, "Content-Length", 14, cacinfo->body_length);
            climsg->res_body_length = cacinfo->body_length;

            if (climsg->res_status > 200 && climsg->res_status < 300)
                climsg->SetStatus(climsg, 200, NULL);
        }
 
    } else {
        climsg->res_body_flag = BC_TE;
        http_header_append(climsg, 1, "Transfer-Encoding", 17, "chunked", 7);
    }
 
    if (cacinfo->expire > 0 && http_header_get(climsg, 1, "Expires", 7) == NULL) {
        str_time2gmt(&cacinfo->expire, buf, sizeof(buf)-1, 0);
        http_header_append(climsg, 1, "Expires", 7, buf, strlen(buf));
    }
 
    if (cacinfo->maxage > 0 && http_header_get(climsg, 1, "Cache-Control", 13) == NULL) {
        sprintf(buf, "max-age=%d", cacinfo->maxage);
        if (cacinfo->pubattr == 1) {
            sprintf(buf + strlen(buf), ", public");
        } else if (cacinfo->pubattr == 2) {
            sprintf(buf + strlen(buf), ", private");
        }
        http_header_append(climsg, 1, "Cache-Control", 13, buf, strlen(buf));
    }
 
    return 0;
}
