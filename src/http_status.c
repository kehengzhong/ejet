/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"  
#include "http_status.h"  
#include "http_mgmt.h"    


typedef struct status_code_ {
    int       httpcode;
    char    * desc;
} HTTPStatusCode;

static HTTPStatusCode g_httpstatuscode[] = {
    { 100,  "Continue"},
    { 101,  "Switching Protocols"},
    { 200,  "OK, Success"},
    { 201,  "Created"},
    { 202,  "Accepted"},
    { 203,  "Non-Authoritative Information"},
    { 204,  "No Content"},
    { 205,  "Reset Content"},
    { 206,  "Partial Content"},
    { 300,  "Multiple Choices"},
    { 301,  "Moved Permanently"},
    { 302,  "Moved temporarily"},
    { 303,  "See Other"},
    { 304,  "Not modified"},
    { 305,  "Use Proxy"},
    { 306,  "reserved"},
    { 307,  "Temporary Redirect"},
    { 400,  "Bad Request - server could not understand request"},
    { 401,  "Unauthorized"},
    { 402,  "Payment required"},
    { 403,  "Forbidden - operation is understood but refused"},
    { 404,  "Not Found"},
    { 405,  "Method not allowed"},
    { 406,  "Not Acceptable"},
    { 407,  "Proxy Authentication required"},
    { 408,  "Request Timeout"},
    { 409,  "Conflict"},
    { 410,  "Gone"},
    { 411,  "Length Required"},
    { 412,  "Precondition failed"},
    { 413,  "Request entity too large"},
    { 414,  "Request-URL too large"},
    { 415,  "Unsupported media type"},
    { 416,  "Requested Range Not Satisfiable"},
    { 417,  "Expectation Failed"},
    { 500,  "Internal Server Error"},
    { 501,  "Not Implemented"},
    { 502,  "Bad Gateway"},
    { 503,  "Service Unavailable"},
    { 504,  "Gateway Timeout"},
    { 505,  "HTTP version not supported"}
};

static ulong http_status_hash_func (void * vkey)
{
    int     httpcode = 0;
    ulong   codeval = 0;

    if (!vkey) return 0;

    httpcode = *(int *)vkey;

    if (httpcode < 100) {
    } else if (httpcode < 500 && httpcode >= 100) {
        codeval = (httpcode/100 - 1) * 10 + httpcode % 100;
    } else if (httpcode >= 500) {
        codeval = (httpcode/100 + 1) * 10 + httpcode % 100;
    }
    return codeval;
}

static int http_status_cmp_key (void * a, void * b)
{
    HTTPStatusCode * scode = (HTTPStatusCode *)a;
    int  httpcode = *(int *)b;

    return scode->httpcode - httpcode;
}


int http_status_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPStatusCode * scode = NULL;
    int          i, num = 0;

    if (!mgmt) return -1;

    if (!mgmt->status_table) {
        mgmt->status_table = ht_new(80, http_status_cmp_key);
        ht_set_hash_func (mgmt->status_table, http_status_hash_func);
    }

    num = sizeof(g_httpstatuscode)/sizeof(g_httpstatuscode[0]);
    for (i=0; i<num; i++) {
        scode = (HTTPStatusCode *)&g_httpstatuscode[i];

        ht_set(mgmt->status_table, &scode->httpcode, scode);
    }

    tolog(1, "eJet - HTTP Status table init.\n");
    return 0;
}

int http_status_cleanup (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    ht_free(mgmt->status_table);
    mgmt->status_table = NULL;

    tolog(1, "eJet - HTTP Status table cleaned.\n");
    return 0;
}


int http_get_status (void * vmgmt, char * status, int statuslen, char ** preason)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPStatusCode * scode = NULL;
    int     httpcode = 0;
    int     i = 0;

    if (!mgmt) return -1;
    if (!status || statuslen <= 0) return -2;

    while(*status==' ' || *status=='\t') {status++; statuslen--;}
    for(i=0; i<statuslen && isdigit(status[i]); i++) {
        httpcode *= 10;
        httpcode += status[i] - '0';
    }

    scode = (HTTPStatusCode *) ht_get(mgmt->status_table, &httpcode);
    if (!scode) return -100;

    if (preason) *preason = scode->desc;

    return 0;
}

int http_get_status2 (void * vmgmt, int status, char ** preason)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPStatusCode * scode = NULL;

    if (!mgmt) return -1;

    scode = (HTTPStatusCode *) ht_get(mgmt->status_table, &status);
    if (!scode) return -100;

    if (preason) *preason = scode->desc;

    return 0;
}



