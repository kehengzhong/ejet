/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"

#include "http_header.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_con.h"
#include "http_request.h"
#include "http_cookie.h"
#include "http_sndpxy.h"
#include "http_listen.h"
#include "http_cgi.h"


/*  Cookie management: parse, add, del, get */

int http_req_addcookie (void * vmsg, char * name, int namelen,
                        char * value, int valuelen)
{       
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HeaderUnit * punit = NULL;
    HeaderUnit * phu = NULL;

    if (!msg) return -1;
    if (!name) return -2;
    
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
    
    if (value && valuelen < 0) valuelen = strlen(value);

    mgmt = msg->httpmgmt;

    punit = hunit_get (msg->req_cookie_table, name, namelen);
    while (punit) {
        phu = punit; punit = punit->next;
        if (phu->valuelen == valuelen &&
            strncasecmp(HUValue(phu), value, valuelen) ==0)
        {
            return 0;
        }
    }

    punit = bpool_fetch(mgmt->header_unit_pool);
    if (!punit) { return -5; }

    punit->frame = msg->req_header_stream;
    punit->name = name;
    punit->namepos = HUPos(punit->frame, name);
    punit->namelen = namelen;
    punit->value = value;
    punit->valuepos = HUPos(punit->frame, value);
    punit->valuelen = valuelen;
    punit->next = NULL;

    if (!phu)
        hunit_add(msg->req_cookie_table, name, namelen, punit);
    else
        phu->next = punit;

    return 0;
}

int http_req_delallcookie (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HeaderUnit * unit = NULL;
    HeaderUnit * uiter = NULL;
    int          i, num;

    if (!msg) return -1;

    mgmt = msg->httpmgmt;

    num = ht_num(msg->req_cookie_table);
    for (i=0; i<num; i++) {
        uiter = ht_value(msg->req_cookie_table, i);
        while (uiter != NULL) {
            unit = uiter; uiter = uiter->next;
            bpool_recycle(mgmt->header_unit_pool, unit);
        }
    }
    ht_zero(msg->req_cookie_table);

    return 0;
}

HeaderUnit * http_req_getcookie (void * vmsg, char * name, int namelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return NULL;
    if (!name) return NULL;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return NULL;

    punit = hunit_get (msg->req_cookie_table, name, namelen);
    while (punit && punit->next) punit = punit->next;
    return punit;
}

int http_req_parse_cookie (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * unit = NULL;
    int          nlen, vlen;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pn = NULL;
    char       * pv = NULL;

    if (!msg) return -1;

    unit = http_header_get(msg, 0, "Cookie", -1);
    if (!unit) return -100;
    if (unit->valuelen <= 0) return -101;

    msg->req_cookie = HUValue(unit);
    msg->req_cookie_len = unit->valuelen;

    pbgn = HUValue(unit);
    pend = pbgn + unit->valuelen;

    while (pbgn < pend) {
        pbgn = skipOver(pbgn, pend-pbgn, " \t;", 3);
        if (pbgn >= pend) return -110;

        pn = pbgn;
        pbgn = skipTo(pbgn, pend-pbgn, ";", 1);

        poct = skipTo(pn, pbgn-pn, "=", 1);
        if (!poct || poct >= pbgn) continue;
        pv = poct + 1;
        poct = rskipOver(poct-1, poct-pn, " \t", 2);
        if (poct < pn) continue;
        nlen = poct - pn + 1;

        vlen = pbgn - pv;
        http_req_addcookie(msg, pn, nlen, pv, vlen);
    }
    return 0;
}

/* Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
 */
int http_req_reqline_decode (void * vmsg, char * pline, int linelen)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    char    * pval = NULL;
    char    * pend = NULL;
    char    * poct = NULL;

    if (!msg) return -1;
    if (!pline || linelen <= 0) return -2;

    msg->req_line = pline;
    msg->req_line_len = linelen - 1;

    poct = pline; pend = pline + linelen;

    /* parse for the field Request-Method */
    pval = skipOver(poct, pend-poct, " \t\r\n;,", 6);
    if (pval >= pend) return -100;
    poct = skipTo(pval, pend-pval, " \t\r", 3);

    http_req_set_reqmeth(msg, pval, poct-pval);

    /* parse for the field Request-URI */
    pval = skipOver(poct, pend-poct, " \t\r\n", 4);
    if (pval >= pend) return -200;
    poct = skipTo(pval, pend-pval, " \t\r", 3);

    if (msg->req_methind == HTTP_METHOD_CONNECT) { //CONNECT method
        /* A CONNECT method requests that a proxy establish a tunnel connection
           on its behalf. The Request-URI portion of the Request-Line is always
           an 'authority' as defined by URI Generic Syntax [2], which is to say
           the host name and port number destination of the requested connection
           separated by a colon:
 
              CONNECT server.example.com:80 HTTP/1.1
              Host: server.example.com:80
 
           https://www.ietf.org/rfc/rfc2817 */

        http_req_set_uri(msg, pval, poct-pval, 0);

    } else {
        if (http_req_set_uri(msg, pval, poct-pval, 0) > 0)
            msg->req_url_type = 1;
    }

    /* parse for the field Request HTTP Version */
    pval = skipOver(poct, pend-poct, " \t\r\n", 4);
    if (pval >= pend) return -100;
    poct = skipTo(pval, pend-pval, " \t\r", 3);

    str_secpy(msg->req_ver, sizeof(msg->req_ver)-1, pval, poct-pval);

    pval = skipTo(pval, poct-pval, "/", 1);
    if (pval < poct) {
        pval += 1;
        msg->req_ver_major = str_to_int(pval, poct-pval, 10, (void **)&pval);

        pval = skipOver(pval, poct-pval, ". \t", 3);
        if (pval < poct)
            msg->req_ver_minor = str_to_int(pval, poct-pval, 10, (void **)&pval);
    }

    return 0;
}

int http_req_reqline_encode (char * meth, int methlen, char * uri,
                             int urilen, char * ver, int verlen, frame_p frame)
{
    if (!meth || methlen <= 0) return -2;
    if (!uri || urilen <= 0) return -3;
    if (!ver || verlen <= 0) return -4;
    if (!frame) return -5;

    frame_put_nlast(frame, meth, methlen);
    frame_put_nlast(frame, "  ", 2);
    frame_put_nlast(frame, uri, urilen);
    frame_put_nlast(frame, "  ", 2);
    frame_put_nlast(frame, ver, verlen);
    frame_put_nlast(frame, "\r\n", 2);

    return 0;
}

static char * g_http_req_meth[] = {
    "-NONE-",
    "CONNECT",
    "DELETE",
    "GET",
    "HEAD",
    "HTTP/1.0", 
    "HTTP/1.1", 
    "OPTIONS",
    "POST",
    "PUT",
    "TRACE",
    NULL
};
static int g_http_req_meth_num = sizeof(g_http_req_meth)/sizeof(char *) - 1;
 
int http_meth_index (char * meth)
{   
    int hi, mid, lo;
    int ret = 0;
    
    if (!meth || strlen(meth) <= 0) return 0;
    
    hi = g_http_req_meth_num - 1;
    lo = -1;
    
    while (hi-lo > 1) {
        mid = (hi + lo)/2;
        ret = strcasecmp((char *)meth, g_http_req_meth[mid]);
        if (ret < 0) hi = mid;
        else if (ret > 0) lo = mid;
        else return mid;
    }

    if (strcasecmp((char*)meth, g_http_req_meth[hi]) == 0) {
        return hi;
    }

    return 0;
}


int http_req_set_reqmeth(void * vmsg, char * meth, int methlen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    int          len = 0;

    if (!msg) return -1;
    if (!meth) return -2;

    if (methlen < 0) len = strlen(meth);
    else len = methlen;
    if (len <= 0) return -3;

    if (len > sizeof(msg->req_meth)-1)
        len = sizeof(msg->req_meth)-1;

    memcpy(msg->req_meth, meth, len);
    msg->req_meth[len] = '\0';

    msg->req_methind = http_meth_index(msg->req_meth);

    return 0;
}


/* As HTTP Server not HTTP Proxy, the request-line from client only contains 
 * path and query, no scheme and host.
 * To form a full URL,  the value of "Host" is prepended to the requested URI.
 */
int http_req_set_absuri (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
    int          ret = 0;

    if (!msg) return -1;

    if (msg->req_methind == HTTP_METHOD_CONNECT) return 0;

    http_uri_init(msg->absuri);

    punit = http_header_get(msg, 0, "Host", 4);
    if (punit) {
        if (msg->ssl_link) {
            frame_append(msg->absuri->uri, "https://");
        } else {
            frame_append(msg->absuri->uri, "http://");
        }
        frame_put_nlast(msg->absuri->uri, HUValue(punit), punit->valuelen);
    }

    if (msg->req_path && msg->req_pathlen > 0) {
        frame_put_nlast(msg->absuri->uri, msg->req_path, msg->req_pathlen);
    } else {
        frame_put_last(msg->absuri->uri, '/');
    }

    if (msg->req_query && msg->req_querylen > 0) {
        frame_append(msg->absuri->uri, "?");
        frame_put_nlast(msg->absuri->uri, msg->req_query, msg->req_querylen);
    }

    ret = http_uri_parse(msg->absuri);
    if (ret >= 0) {
        msg->req_scheme = msg->absuri->scheme;
        msg->req_schemelen = msg->absuri->schemelen;

        msg->req_host = msg->absuri->host;
        msg->req_hostlen = msg->absuri->hostlen;

        msg->req_port = msg->absuri->port;
        if (msg->req_port <= 0) {
            if (msg->ssl_link)
                msg->req_port = 443;
            else
                msg->req_port = 80;
        }
    }

    return ret;
}

int http_req_set_docuri (void * vmsg, char * puri, int urilen, int decode, int instbrk)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    int          ret = 0;
    HTTPLoc    * ploc = NULL;
    char         udoc[8192];

    if (!msg) return -1;
 
    /* new DocURI is completely same as original one, just return */
    if (frameL(msg->docuri->uri) == urilen &&
        strncasecmp(frameS(msg->docuri->uri), puri, urilen) == 0)
        return 0;

    ret = http_uri_set(msg->docuri, puri, urilen, decode);
    if (ret < 0) return ret;

    msg->req_path = msg->docuri->path;
    msg->req_pathlen = msg->docuri->pathlen;
    msg->req_query = msg->docuri->query;
    msg->req_querylen = msg->docuri->querylen;
 
    if (msg->uri->type > 0) {
        msg->ssl_link = msg->docuri->ssl_link;
 
        msg->req_scheme = msg->docuri->scheme;
        msg->req_schemelen = msg->docuri->schemelen;
        msg->req_host = msg->docuri->host;
        msg->req_hostlen = msg->docuri->hostlen;
        msg->req_port = msg->docuri->port;
    }

    if (instbrk) return 0;

    http_loc_instance(msg);

    /* if real file of request after intantiated is a directory,
       check if its index files exists or not. if exists, set new doc-uri */

    if (msg->req_methind != HTTP_METHOD_GET)
        return 0;  //only GET supported for directory request

    ploc = (HTTPLoc *)msg->ploc;
    if (!ploc) return -201;

    if ((ploc->type & SERV_PROXY) || (ploc->type & SERV_FASTCGI))
        return 0;

    /* only directory request needs to append its index file */
    if (msg->GetLocFile(msg, NULL, 0, NULL, 0, udoc, sizeof(udoc)-1) == 2) {

        return http_req_set_docuri(msg, udoc, strlen(udoc), 0, 0);
    }

    return 0;
}

/* resolve the uri to break down into all fields */

int http_req_set_uri (void * vmsg, char * puri, int urilen, int decode)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    int          ret = 0;

    if (!msg) return -1;

    ret = http_uri_set(msg->uri, puri, urilen, decode);
    if (ret < 0) return ret;

    msg->req_url_type = msg->uri->type;
    if (msg->req_methind == HTTP_METHOD_CONNECT) {
        /* It's an URL of CONNECT method.
           eg. CONNECT content-autofill.googleapis.com:443 */
        msg->req_url_type = 0;

        msg->req_host = msg->uri->host;
        msg->req_hostlen = msg->uri->hostlen;
        msg->req_port = msg->uri->port;

        return 0;
    }

    msg->req_path = msg->uri->path;
    msg->req_pathlen = msg->uri->pathlen;
    msg->req_query = msg->uri->query;
    msg->req_querylen = msg->uri->querylen;

    if (msg->uri->type > 0) {
        /* It's an absolute URL */
        msg->ssl_link = msg->uri->ssl_link;

        msg->req_scheme = msg->uri->scheme;
        msg->req_schemelen = msg->uri->schemelen;
        msg->req_host = msg->uri->host;
        msg->req_hostlen = msg->uri->hostlen;
        msg->req_port = msg->uri->port;
    }

    return ret;
}

static char * str2int64 (char * pbgn, char * pend, int64 * pval)
{
    int64 val = 0;

    for (val = 0; pbgn && pbgn < pend && isdigit(*pbgn); pbgn++) {
        val *= 10; val += *pbgn-'0';
    }

    if (pval) *pval = val;

    return pbgn;
}

static int partial_item_parse (void * vbgn, int len, http_partial_t * part)
{
    char * pbgn = (char *)vbgn;
    char * pend = pbgn + len;

    /*
       Range: bytes=0-499  given range from 0 to 499, total 500 bytes
       Range: bytes=500-   given range from 500 to end, total bytes: size-500
       Range: bytes=-200   indicate the last 200 bytes, total bytes: 200
       Range: bytes=500-550,601-999  given 2 ranges, total bytes: 550-500+1 + 999-601+1
     */
 
    if (isdigit(*pbgn)) {
        pbgn = str2int64(pbgn, pend, &part->start);
        if (*pbgn == '-') pbgn += 1;

        if (pbgn < pend && isdigit(*pbgn)) {
            pbgn = str2int64(pbgn, pend, &part->end);
            part->partflag = 1;

            part->length = part->end + 1 - part->start;

        } else {
            part->partflag = 2;

            part->end = -1;
            part->length = -1;
        }

        return 1;

    } else if (*pbgn == '-') {
        pbgn += 1;
        if (pbgn < pend && isdigit(*pbgn)) {
            pbgn = str2int64(pbgn, pend, &part->length);
            part->partflag = 3;

            part->start = -1;
            part->end = -1;

            return 2;
        }
    }

    return -10;
}


int http_partial_parse (void * vmsg, void * vbgn, int len)
{
    HTTPMsg        * msg = (HTTPMsg *)vmsg;
    http_partial_t   part;
    char           * pbgn = (char *)vbgn;
    char           * pend = NULL;
    char           * plist[16];
    int              plen[16];
    int              i, num = 0;

    if (!msg) return -1;

    pend = pbgn + len;

    /* Range: bytes=0-499  given range from 0 to 499, total 500 bytes
       Range: bytes=500-   given range from 500 to end, total bytes: size-500
       Range: bytes=-200   indicate the last 200 bytes, total bytes: 200
       Range: bytes=500-550,601-999  given 2 ranges, total bytes: 550-500+1 + 999-601+1
     */
    if (strncasecmp(pbgn, "bytes", 5) != 0) return -2;
    pbgn += 5;

    pbgn = skipOver(pbgn, pend-pbgn, " \t", 2);
    if (pbgn >= pend || *pbgn != '=') return -3;
    pbgn += 1;

    pbgn = skipOver(pbgn, pend-pbgn, " \t", 2);
    if (pbgn >= pend) return -4;

    num = string_tokenize(pbgn, pend - pbgn, ",;", 2, (void **)plist, plen, 16);
    if (num <= 0) return -2;

    for (i = 0; i < num; i++) {
        memset(&part, 0, sizeof(part));

        if (partial_item_parse(plist[i], plen[i], &part) >= 0)
            vstar_push(msg->partial_list, &part);
    }

    msg->partial_flag = vstar_num(msg->partial_list);

    return 0;
}

int http_req_parse_header (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
    char       * pover = NULL;
    char       * pcolon = NULL;
    char       * pend  = NULL;
    char       * poct  = NULL;
    int          ret = 0;
    char       * name = NULL;
    char       * value = NULL;
    int          namelen, valuelen;

    if (!msg) return -1;

    poct = frameP(msg->req_header_stream);
    pover = poct + frameL(msg->req_header_stream);

    poct = skipOver(poct, pover-poct, " \t\r\n", 4);
    if (!poct || poct >= pover) return -100;

    pend = memchr(poct, '\n', pover-poct);
    if (!pend) return -100;  /* has no line-terminal char */

    ret = http_req_reqline_decode (msg, poct, pend-poct);
    if (ret < 0) return -110;

    for (poct = pend + 1; poct < pover; poct = pend + 1) {
        pend = memchr(poct, '\n', pover - poct);
        if (!pend || pend >= pover) break;

        poct = skipOver(poct, pend-poct, " \t", 2);
        if (!poct || poct >= pend) continue;

        name = value = NULL; namelen = valuelen = 0;

        name = poct;

        pcolon = skipTo(poct, pend-poct, ":", 1);
        if (!pcolon || pcolon>=pend) continue;

        poct = rskipOver(pcolon-1, pcolon-name, " \t", 2);

        if (poct >= name) namelen = poct-name+1;
        else continue;

        poct = skipOver(pcolon+1, pend-pcolon-1, " \t\r", 3);
        if (poct >= pend) continue;

        value = poct;
        poct = rskipOver(pend-1, pend-poct, " \t\r", 3);
        if (poct >= value) valuelen = poct-value+1;
        else { value = NULL; valuelen = 0; }

        http_header_add(msg, 0, name, namelen, value, valuelen);
    }

    http_req_parse_cookie(msg);

    /* determine the body content format */
    if (strncasecmp(msg->req_meth, "POST", 4) != 0 &&
        strncasecmp(msg->req_meth, "PUT", 3) != 0)
    {
        if (strncasecmp(msg->req_meth, "CONNECT", 7) == 0)
            msg->req_body_flag = BC_TUNNEL;
        else 
            msg->req_body_flag = BC_NONE;

    } else {
        /* determine if the request body is encoded in the format of chunked */
        punit = http_header_get(msg, 0, "Transfer-Encoding", -1);

        if (punit) {
            if (punit->valuelen != 7 ||
                strncasecmp("chunked", HUValue(punit), 7) != 0)
            {
                msg->req_body_flag = BC_TE_INVALID;

            } else {
                msg->req_body_flag = BC_TE;
            }

        } else {
            /* determine if the request body is counted in the format of Content-Length */
            punit = http_header_get(msg, 0, "Content-Length", -1);
            if (punit) {
                msg->req_body_flag = BC_CONTENT_LENGTH;
                msg->req_body_length = 0;

                for (ret = 0; ret < punit->valuelen && !isdigit(*(HUValue(punit) + ret)); ret++);

                for (; ret < punit->valuelen && isdigit(*(HUValue(punit) + ret)); ret++) {
                    msg->req_body_length *= 10;
                    msg->req_body_length += *(HUValue(punit) + ret) - '0';
                }

            } else {
                msg->req_body_flag = BC_UNKNOWN;
            }
        }
    }

    /* determine if the request body is multipart form data */
    punit = http_header_get(msg, 0, "Content-Type", -1);
    if (punit) {
        msg->req_content_type = HUValue(punit);
        msg->req_contype_len = punit->valuelen;

        if (strncasecmp(HUValue(punit), "multipart/form-data", 19) == 0)
            msg->req_multipart = 1;
    }

    punit = http_header_get(msg, 0, "User-Agent", -1);
    if (punit) {
        msg->req_useragent = HUValue(punit);
        msg->req_useragent_len = punit->valuelen;
    }

    /* determine if the request connection is keep-alive */
    punit = http_header_get(msg, 0, "Proxy-Connection", -1);
    if (punit) {
        if (punit->valuelen == 10 && strncasecmp("keep-alive", HUValue(punit), 10) == 0) {
            msg->req_conn_keepalive = 1;

        } else {
            msg->req_conn_keepalive = 0;
        }

    } else {
        punit = http_header_get(msg, 0, "Connection", -1);
        if (punit) {
            if (punit->valuelen == 10 || strncasecmp("keep-alive", HUValue(punit), 10) == 0) {
                msg->req_conn_keepalive = 1;

            } else {
                msg->req_conn_keepalive = 0;
            }

        } else {
            msg->req_conn_keepalive = 0;
        }
    }

    /* parse http partial request header:
       Range: bytes=0-499  given range from 0 to 499, total 500 bytes
       Range: bytes=500-   given range from 500 to end, total bytes: size-500
       Range: bytes=-200   indicate the last 200 bytes, total bytes: 200
       Range: bytes=500-550,601-999  given 2 ranges, total bytes: 550-500+1 + 999-601+1
     */
    punit = http_header_get(msg, 0, "Range", -1);
    if (punit) {
        http_partial_parse(msg, HUValue(punit), punit->valuelen);
    }

    if (msg->req_query && msg->req_querylen > 0) {
        if (!msg->req_query_kvobj) {
            msg->req_query_kvobj = kvpair_init(37, "&", "=");
        }

        kvpair_decode(msg->req_query_kvobj, msg->req_query, msg->req_querylen);
    }

    return 0;
}

int http_req_verify (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    if (strncasecmp(msg->req_ver, "HTTP/", 5) != 0) {
        msg->SetStatus(msg, 400, NULL);
        msg->Reply(msg);
        return -100;
    }

    if (msg->req_ver_major != 1) {
        msg->SetStatus(msg, 505, NULL);
        msg->Reply(msg);
        return -101;
    }

    if (msg->req_ver_minor > 0) {
        if (http_header_get(msg, 0, "Host", 4) == NULL) {
            msg->SetStatus(msg, 400, NULL);
            msg->Reply(msg);
            return -102;
        }
    }

    return 0;
}


int http_req_encoding (void * vmsg, int encode)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HeaderUnit * punit = NULL;
    int          i;
    int          num;
    char         buf[256];

    if (!msg) return -1;

    mgmt = msg->httpmgmt;

    frame_empty(msg->req_stream);

    /* check if set proxy addr for next request. if it does, set dstip/dstport */
    http_send_proxy_check(msg);

    /* re-validate the Host header */
    http_header_del(msg, 0, "Host", 4);

    str_secpy(buf, sizeof(buf)-1, msg->req_host, msg->req_hostlen);

    if (!msg->ssl_link && msg->req_port != 80) {
        sprintf(buf + strlen(buf), ":%d", msg->req_port);

    } else if (msg->ssl_link && msg->req_port != 443) {
        sprintf(buf + strlen(buf), ":%d", msg->req_port);
    }

    http_header_append(msg, 0, "Host", -1, buf, str_len(buf));

    http_cookie_add(msg);

    /* building request line */
    frame_append(msg->req_stream, msg->req_meth);
    frame_put_last(msg->req_stream, ' ');
    if (msg->proxy) {
        if (encode)
            frame_uri_encode(msg->req_stream, frameP(msg->uri->uri), frameL(msg->uri->uri), NULL);
        else
            frame_put_nlast(msg->req_stream, frameP(msg->uri->uri), frameL(msg->uri->uri));
        frame_put_last(msg->req_stream, ' ');

        if (strlen(msg->req_ver) > 0)
            frame_append(msg->req_stream, msg->req_ver);//mgmt->httpver1);
        else
            frame_append(msg->req_stream, mgmt->httpver1);

        frame_put_nlast(msg->req_stream, "\r\n", 2);

    } else {
        if (msg->req_pathlen > 0 && msg->req_path) {
            if (encode)
                frame_uri_encode(msg->req_stream, msg->req_path, msg->req_pathlen, NULL);
            else
                frame_put_nlast(msg->req_stream, msg->req_path, msg->req_pathlen);
        } else {
            frame_append(msg->req_stream, "/");
        }

        if (msg->req_querylen > 0 && msg->req_query) {
            frame_put_last(msg->req_stream, '?');

            if (encode)
                frame_uri_encode(msg->req_stream, msg->req_query, msg->req_querylen, NULL);
            else
                frame_put_nlast(msg->req_stream, msg->req_query, msg->req_querylen);
        }

        frame_put_last(msg->req_stream, ' ');
        if (strlen(msg->req_ver) > 0)
            frame_append(msg->req_stream, msg->req_ver);//mgmt->httpver1);
        else
            frame_append(msg->req_stream, mgmt->httpver1);

        frame_append(msg->req_stream, "\r\n");
    }

    if (msg->msgtype == 0) { //HTTPMsg is sending request to origin
        msg->req_line = frameP(msg->req_stream);
        msg->req_line_len = frameL(msg->req_stream) - 2;
    }

    if (!msg->req_useragent || msg->req_useragent_len <= 0) {
        punit = http_header_get(msg, 0, "User-Agent", -1);
        if (punit) {
            msg->req_useragent = HUValue(punit);
            msg->req_useragent_len = punit->valuelen;
        }
    }

    http_header_del(msg, 0, "Proxy-Connection", 16);
    //http_header_del(msg, 0, "If-Modified-Since", 17);
    //http_header_del(msg, 0, "If-None-Match", 13);

    if (msg->req_body_flag == BC_NONE && msg->proxied == 0) {
        /* when Proxy mode, do not remove the body format such as 
           transfer-encoding or content-length */
        http_header_del(msg, 0, "Content-Length", 14);
        http_header_del(msg, 0, "Transfer-Encoding", 17);
    }

    /* checking non-proxied HTTPMsg if it's body-length is equal to the length of body-stream */
    if (msg->req_body_flag == BC_CONTENT_LENGTH && msg->proxied == 0 &&
        msg->req_body_length <= 0)
    {
        msg->req_body_length = chunk_size(msg->req_body_chunk, 0);

        http_header_del(msg, 0, "Content-Length", -1);
        http_header_append_int64(msg, 0, "Content-Length", 14, msg->req_body_length);
    }

    /* append all the headers */
    num = arr_num(msg->req_header_list);
    for (i = 0; i < num; i++) {
        punit = (HeaderUnit *)arr_value(msg->req_header_list, i);
        if (!punit || !punit->name || punit->namelen < 1) {
            continue;
        }

        frame_put_nlast(msg->req_stream, HUName(punit), punit->namelen);
        frame_put_nlast(msg->req_stream, ": ", 2);

        if (HUValue(punit) && punit->valuelen > 0)
            frame_put_nlast(msg->req_stream, HUValue(punit), punit->valuelen);

        frame_put_nlast(msg->req_stream, "\r\n", 2);
    }

    /* append the trailer line of the http request header: a blank line */
    frame_append(msg->req_stream, "\r\n");

    msg->req_header_length = frameL(msg->req_stream);

    msg->reqsent = 0;
    msg->req_stream_sent = 0;

    chunk_prepend_bufptr(msg->req_body_chunk, frameP(msg->req_stream),
                         frameL(msg->req_stream), NULL, NULL, 1);

    return 0;
}


int print_request (void * vmsg, FILE * fp)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    HeaderUnit   * unit = NULL;
    char           buf[2048];
    int            len = 0;
    int            i, num;
    char         * poct = NULL;

    /* printf the request line */
    if (fp == stdout || fp == stderr)
        fprintf(fp, "\n-------------Request ConID=%lu MsgID=%ld  reqfd=%d peer_addr=%s:%d ---------------\n", 
               http_con_id(msg->pcon), msg->msgid, 
               iodev_fd(http_con_iodev(msg->pcon)),
               msg->srcip, msg->srcport);

    fprintf(fp, "  SourceAddr: %s : %d\n", msg->srcip, msg->srcport);

    if (msg->req_host && msg->req_hostlen > 0) {
        str_secpy(buf, sizeof(buf)-1, msg->req_host, msg->req_hostlen);
        fprintf(fp, "  RemoteHost: %s : %d\n", buf, msg->req_port);

    } else {
        fprintf(fp, "  RemoteHost:  : %d\n", msg->req_port);
    }

    if (msg->req_path && msg->req_pathlen > 0) {
        str_secpy(buf, sizeof(buf)-1, msg->uri->path, msg->uri->pathlen);
        fprintf(fp, "  %s %s", msg->req_meth, buf);

    } else if (msg->req_methind == HTTP_METHOD_CONNECT) {
        str_secpy(buf, sizeof(buf)-1, msg->req_host, msg->req_hostlen);
        fprintf(fp, "  %s %s:%d", msg->req_meth, buf, msg->req_port);

    } else {
        fprintf(fp, "  %s <NULL>", msg->req_meth);
    }

    if (msg->req_querylen > 0 && msg->req_query) {
        str_secpy(buf, sizeof(buf)-1, msg->req_query, msg->req_querylen);
        fprintf(fp, "?%s", buf);
    }
    fprintf(fp, " %s\n", msg->req_ver);

    /* printf the request header */
    num = arr_num(msg->req_header_list);
    for (i = 0; i < num; i++) {
        unit = (HeaderUnit *)arr_value(msg->req_header_list, i);
        if (!unit) continue;

        poct = HUName(unit); 
        if (unit->namelen > 0) {
            str_secpy(buf, sizeof(buf)-1, poct, unit->namelen);
            fprintf(fp, "  %s: ", buf);

        } else fprintf(fp, "   : ");

        poct = HUValue(unit); 
        if (unit->valuelen > 0) {
            str_secpy(buf, sizeof(buf)-1, poct, unit->valuelen);
            fprintf(fp, "%s\n", buf);

        } else fprintf(fp, "\n");
    }

    /* printf the request body */
    if ((len = frameL(msg->req_body_stream)) > 0) {
        fprintf(fp, "request body %d bytes:\n", frameL(msg->req_body_stream));
        if (len > 256) len = 256;
        printOctet(fp, frameP(msg->req_body_stream), 0, len, 2);
    }

    if (msg->req_file_cache > 0) {
        printf("request body stored %lld bytes in file:\n", msg->req_body_length);
        printf("  TempCacheFile: %s\n", msg->req_file_name);
    }

    print_hashtab(msg->req_header_table, fp);

    if (fp == stdout || fp == stderr)
        fprintf(fp, "--------------------------end of the request: id=%ld ------------------------\n", msg->msgid);

    fflush(fp);

    return 0;
}

