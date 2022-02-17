/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "btype.h"
#include "frame.h"
#include "memory.h"
#include "strutil.h"
#include "http_uri.h"

void * http_uri_alloc()
{
    HTTPUri * uri = NULL;

    uri = kzalloc(sizeof(*uri));
    if (uri) {
        uri->uri = frame_new(64);
    }

    return uri;
}

void http_uri_free (void * vuri)
{
    HTTPUri * uri = (HTTPUri *)vuri;

    if (!uri) return;

    frame_delete(&uri->uri);

    kfree(uri);
}

void http_uri_init (void * vuri)
{
    HTTPUri * uri = (HTTPUri *)vuri;

    if (!uri) return;

    frame_empty(uri->uri);

    uri->type = 0;
    uri->ssl_link = 0;

    uri->reluri = NULL;
    uri->relurilen = 0;

    uri->baseuri = NULL;
    uri->baseurilen = 0;

    uri->scheme = NULL;
    uri->schemelen = 0;

    uri->host = NULL;
    uri->hostlen = 0;
    uri->port = 0;

    uri->path = NULL;
    uri->pathlen = 0;

    uri->query = NULL;
    uri->querylen = 0;

    uri->dir = NULL;
    uri->dirlen = 0;

    uri->file = NULL;
    uri->filelen = 0;

    uri->file_base = NULL;
    uri->file_baselen = 0;

    uri->file_ext = NULL;
    uri->file_extlen = 0;
}
 
int http_uri_set (void * vuri, char * addr, int addrlen, int decode)
{
    HTTPUri * uri = (HTTPUri *)vuri;

    if (!uri) return -1;

    if (!addr) return -2;
    if (addrlen < 0) addrlen = str_len(addr);
    if (addrlen <= 0) return -3;

    http_uri_init(uri);

    if (decode)
        frame_uri_decode(uri->uri, addr, addrlen);
    else
        frame_put_nlast(uri->uri, addr, addrlen);

    return http_uri_parse(uri);
}

int http_uri_parse (void * vuri)
{
    HTTPUri * uri = (HTTPUri *)vuri;
    char    * pbgn = NULL;
    char    * pend = NULL;
    char    * p = NULL;
    char    * ptmp = NULL;
    long      lport = 0;
 
    if (!uri) return -1;

    pbgn = frameS(uri->uri);
    pend = pbgn + frameL(uri->uri);

    p = pbgn = skipOver(pbgn, pend-pbgn, " \t\r\n", 4);
    if (!pbgn || pbgn >= pend) return -100;
 
    uri->baseuri = pbgn;
    uri->rooturi = pbgn;

    p = rskipTo(pend-1, pend-pbgn, "/", 1);
    if (p && p >= pbgn) {
        uri->baseurilen = p - pbgn + 1;
    } else {
        uri->baseurilen = pend - pbgn;
    }

    p = skipTo(pbgn, pend-pbgn, "/", 1);
    if (p >= pend) {
        /* no path flag, eg. CONNECT k.test.dlinktb.com:443 */
        uri->host = pbgn;
        uri->rooturilen = 0;

        ptmp = skipTo(pbgn, pend-pbgn, ":", 1);
        if (ptmp < pend && *ptmp == ':') {
            /* ke.test.dlinktb.com:443?key=1373 */
            uri->hostlen = ptmp - pbgn;
 
            lport = strtol(ptmp+1, (char **)&pbgn, 10);
            uri->port = lport;

            ptmp = skipTo(pbgn, pend-pbgn, "?", 1);
            if (ptmp < pend && *ptmp == '?') {
                uri->query = ptmp + 1;
                uri->querylen = pend - ptmp - 1;
            }

        } else {
            ptmp = skipTo(pbgn, pend-pbgn, "?", 1);
            if (ptmp < pend && *ptmp == '?') {
                /* ke.test.dlinktb.com?key=1373 */
                uri->hostlen = ptmp - pbgn;

                uri->query = ptmp + 1;
                uri->querylen = pend - ptmp - 1;
            } else {
                uri->hostlen = pend - pbgn;
            }
        }

        goto connecturi;
 
    } else if (p > pbgn && *(p-1) == ':' && *p == '/' && *(p+1) == '/') {
        uri->scheme = pbgn;
        uri->schemelen = p - 1 - pbgn;
 
        if (uri->schemelen == 5 && strncasecmp(uri->scheme, "https", 5) == 0)
            uri->ssl_link = 1;
        else
            uri->ssl_link = 0;
 
        pbgn = p + 2;
 
        p = skipTo(pbgn, pend-pbgn, ":/", 2);
        if (p >= pend) {
            uri->host = pbgn;
            uri->hostlen = pend - pbgn;
            uri->rooturilen = pend - pbgn;
 
            if (uri->port == 0)
                uri->port = uri->ssl_link ? 443 : 80;

            goto absend;
 
        } else if (*p == ':') {
            uri->host = pbgn;
            uri->hostlen = p - pbgn;
 
            lport = strtol(p+1, (char **)&ptmp, 10);
            pbgn = p;
 
            uri->port = lport;
 
            pbgn = skipTo(pbgn, pend-pbgn, "/", 1);
            if (pbgn >= pend) {
                uri->rooturilen = pend - uri->rooturi;
                goto absend;
            }
            uri->rooturilen = pbgn - uri->rooturi;
 
        } else if (*p == '/') {
            uri->host = pbgn;
            uri->hostlen = p - pbgn;
            uri->rooturilen = p - uri->rooturi;
 
            if (strncasecmp(uri->scheme, "https", 5) == 0)
                uri->port = 443;
            else if (strncasecmp(uri->scheme, "http", 4) == 0)
                uri->port = 80;
 
            pbgn = p;
        }
 
        uri->path = pbgn;
        p = skipTo(pbgn, pend-pbgn, "?#", 2);
        if (p >= pend) {
            uri->pathlen = pend - pbgn;
            goto absend;
        }
 
        uri->pathlen = p - pbgn;

        if (*p != '?') 
            p = skipTo(p, pend-p, "?", 1);

        if (*p == '?') {
            uri->query = p + 1;
            uri->querylen = pend - p - 1;
        }
 
        goto absend;
    }
 
    /* ke.test.dlinktb.com:8181/app/signin.php */

    uri->rooturilen = p - uri->rooturi;
    uri->path = p;

    if (pbgn < p) {
        uri->host = pbgn;

        ptmp = skipTo(pbgn, pend-pbgn, ":", 1);
        if (ptmp < pend && *ptmp == ':') {
            uri->hostlen = ptmp - pbgn;
 
            lport = strtol(ptmp+1, (char **)&pbgn, 10);
            uri->port = lport;
        } else {
            uri->hostlen = p - pbgn;

            if (uri->port == 0)
                uri->port = uri->ssl_link ? 443 : 80;
        }
    }

    /* /app/signin.php#anchor?name=laoke&code=21837 */

    ptmp = skipTo(p, pend-p, "?#", 2);
    if (ptmp >= pend) {
        uri->pathlen = pend - p;
        goto relend;
    }
 
    uri->pathlen = ptmp - p;

    if (*ptmp != '?') ptmp = skipTo(ptmp, pend-ptmp, "?", 1);
    if (*ptmp == '?') {
        uri->query = ptmp + 1;
        uri->querylen = pend - ptmp - 1;
    }
 
relend:
    uri->type = 0; //relative uri
    http_uri_path_parse(uri);
    return 0;
 
absend:
    uri->type = 1;  //absolute uri
    http_uri_path_parse(uri);
    return 1;
 
connecturi:
    uri->type = 2;  //connect uri
    http_uri_path_parse(uri);
    return 2;
}

int http_uri_path_parse (void * vuri)
{
    HTTPUri * uri = (HTTPUri *)vuri;
    char    * pval = NULL;

    if (!uri) return -1;

    if (uri->path == NULL || uri->pathlen <= 0) {
        /* relative uri or absloute uri, CONNECT ke.dlinktb.com:443 */
        uri->path = "/";
        uri->pathlen = 1;
    }

    uri->reluri = uri->path;
    uri->relurilen = frameL(uri->uri) - (uri->path - (char *)frameP(uri->uri));
    //uri->relurilen = uri->pathlen + uri->querylen + (uri->querylen > 0 ? 1:0);

    uri->dir = uri->path;
    pval = rskipTo(uri->path + uri->pathlen - 1, uri->pathlen, "/\\", 2);
    if (pval && pval >= uri->path)
        uri->dirlen = pval - uri->path + 1;
    else
        uri->dirlen = 0;
 
    if (uri->dirlen < uri->pathlen) {
        uri->file = pval + 1;
        uri->filelen = uri->pathlen - uri->dirlen;
 
        pval = rskipTo(uri->file + uri->filelen - 1, uri->filelen, ".", 1);
        if (pval && *pval == '.') {
            uri->file_base = uri->file;
            uri->file_baselen = pval - uri->file;
 
            uri->file_ext = pval;
            uri->file_extlen = uri->file + uri->filelen - pval;
 
        } else {
            uri->file_base = uri->file;
            uri->file_baselen = uri->filelen;
 
            uri->file_ext = "";
            uri->file_extlen = 0;
        }
 
    } else {
        uri->file = "";
        uri->filelen = 0;
 
        uri->file_ext = "";
        uri->file_extlen = 0;
    }
 
    return 0;
}

char * http_uri_string (void * vuri)
{
    HTTPUri * uri = (HTTPUri *)vuri;

    if (!uri) return "";

    return frame_string(uri->uri);
}

