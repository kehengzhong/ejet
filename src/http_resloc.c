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

#ifdef UNIX
#include <dlfcn.h>
#include <regex.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
#define PCRE_STATIC 1
#include "pcre.h"
#endif

#include "adifall.ext"
#include "epump.h"
#include "http_resloc.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_ssl.h"
#include "http_srv.h"
#include "http_uri.h"
#include "http_pump.h"
#include "http_variable.h"
#include "http_script.h"
#include "http_pagetpl.h"

extern HTTPMgmt * gp_httpmgmt;

typedef struct pass_url_item_s {
    char              * url;
    int                 urllen;

    long                weight;
    long                curwei;

    char              * match;
    int                 matchlen;
    uint8               matchtype;

#ifdef UNIX
    regex_t           * preg;
#endif
#if defined(_WIN32) || defined(_WIN64)
    pcre              * preg;
#endif

    uint8               status;
    int                 max_fails;
    int                 fail_timeout;

    char              * host;
    int                 hostlen;
    int                 port;
    uint8               ssl_link;

    void              * srv;
} PassItem;

void * passitem_alloc ();
void   passitem_free (void * vpi);

int    passitem_set_url (void * vpi, char * url, int len);
int    passitem_set_weight (void * vpi, long weight);
int    passitem_set_match (void * vpi, char * match, int len);
int    passitem_set_matchtype (void * vpi, char * matchtype, int len);
int    passitem_set_status (void * vpi, char * status, int len);
int    passitem_set_maxfails (void * vpi, int maxfails);
int    passitem_set_failtimeout (void * vpi, int failtimeout);


void * passitem_alloc ()
{
    PassItem * item = NULL;

    item = kzalloc(sizeof(*item));

    return item;
}

void passitem_free (void * vpi)
{
    PassItem * item = (PassItem *)vpi;

    if (!item) return;

    if (item->matchtype == MATCH_REGEX_CASE || item->matchtype == MATCH_REGEX_NOCASE) {
#ifdef UNIX
        regfree(item->preg);
        kfree(item->preg);
#endif
#if defined(_WIN32) || defined(_WIN64)
        pcre_free(item->preg);
#endif
    }

    kfree(item);
}

int passitem_set_url (void * vpi, char * url, int len)
{
    PassItem * item = (PassItem *)vpi;
    HTTPUri    suri = {0};

    if (!item) return -1;
    if (!url) return -2;
    if (len < 0) len = str_len(url);
    if (len < 0) return -3;

    item->url = url;
    item->urllen = len;

    if (http_uri_parse(&suri, url, len) >= 0) {
        item->host = suri.host;
        item->hostlen = suri.hostlen;
        item->port = suri.port;
        item->ssl_link = suri.ssl_link;
    }

    return 0;
}

int passitem_set_weight (void * vpi, long weight)
{
    PassItem * item = (PassItem *)vpi;

    if (!item) return -1;

    item->weight = weight;

    return 0;
}

int passitem_set_match (void * vpi, char * match, int len)
{
    PassItem * item = (PassItem *)vpi;

    if (!item) return -1;
    if (!match) return -2;
    if (len < 0) len = str_len(match);
    if (len < 0) return -3;

    item->match = match;
    item->matchlen = len;

    return 0;

}

int passitem_set_matchtype (void * vpi, char * matchtype, int len)
{
    PassItem * item = (PassItem *)vpi;

    if (!item) return -1;

    if (!matchtype || len <= 0) {
        item->matchtype = MATCH_DEFAULT;
        return 0;
    }

    if (str_casecmp(matchtype, "=") == 0)
        item->matchtype = MATCH_EXACT;
    else if (str_casecmp(matchtype, " ") == 0)
        item->matchtype = MATCH_PREFIX_DEFAULT;
    else if (str_casecmp(matchtype, "^~") == 0)
        item->matchtype = MATCH_PREFIX;
    else if (str_casecmp(matchtype, "~") == 0)
        item->matchtype = MATCH_REGEX_CASE;
    else if (str_casecmp(matchtype, "~*") == 0)
        item->matchtype = MATCH_REGEX_NOCASE;
    else
        item->matchtype = MATCH_DEFAULT;
    
    return 0;
}

int passitem_set_status (void * vpi, char * status, int len)
{
    PassItem * item = (PassItem *)vpi;

    if (!item) return -1;

    /* status: down(0) up(1) backup(2) */

    if (!status || len <= 0) {
        item->status = 1;
        return 0;
    }

    if (str_casecmp(status, "down") == 0)
        item->status = 0;
    else if (str_casecmp(status, "up") == 0)
        item->status = 1;
    else if (str_casecmp(status, "backup") == 0)
        item->status = 2;
    else
        item->status = 1;

    return 0;
}

int passitem_set_maxfails (void * vpi, int maxfails)
{
    PassItem * item = (PassItem *)vpi;

    if (!item) return -1;

    item->max_fails = maxfails;

    return 0;
}

int passitem_set_failtimeout (void * vpi, int failtimeout)
{
    PassItem * item = (PassItem *)vpi;

    if (!item) return -1;

    item->fail_timeout = failtimeout;

    return 0;
}


void * passurl_alloc ()
{
    PassURL * pass = NULL;

    pass = kzalloc(sizeof(*pass));
    if (!pass) return NULL;

    InitializeCriticalSection(&pass->passCS);

    pass->url_list = arr_new(4);
    pass->back_url_list = arr_new(4);
    pass->down_url_list = arr_new(4);

    return pass;
}

void passurl_free (void * vpu)
{
    PassURL * pass = (PassURL *)vpu;

    if (!pass) return;

    arr_pop_free(pass->down_url_list, passitem_free);
    arr_pop_free(pass->back_url_list, passitem_free);
    arr_pop_free(pass->url_list, passitem_free);

    DeleteCriticalSection(&pass->passCS);

    kfree(pass);
}

int passurl_set_loadbal (void * vpu, char * loadbal, int len)
{
    PassURL * pass = (PassURL *)vpu;

    if (!pass) return -1;

    if (!loadbal || len <= 0) {
        pass->loadbal = LBA_ROUND_ROBIN;
        return 0;
    }

    EnterCriticalSection(&pass->passCS);

    if (str_casecmp(loadbal, "round-robin") == 0)
        pass->loadbal = LBA_ROUND_ROBIN;
    else if (str_casecmp(loadbal, "weight") == 0)
        pass->loadbal = LBA_WEIGHT;
    else if (str_casecmp(loadbal, "fast-transact") == 0)
        pass->loadbal = LBA_FAST_TRANSACT;
    else if (str_casecmp(loadbal, "least-conn") == 0)
        pass->loadbal = LBA_LEAST_CONN;
    else if (str_casecmp(loadbal, "consist-hash") == 0)
        pass->loadbal = LBA_CONSIST_HASH;
    else if (str_casecmp(loadbal, "pattern-match") == 0)
        pass->loadbal = LBA_PATTERN_MATCH;
    else
        pass->loadbal = LBA_ROUND_ROBIN;

    LeaveCriticalSection(&pass->passCS);

    return 0;
}

int passurl_set_lbfields (void * vpu, char * lbfields, int lbflen)
{
    PassURL * pass = (PassURL *)vpu;

    if (!pass) return -1;

    if (!lbfields) return -2;
    if (lbflen < 0) lbflen = str_len(lbfields);

    EnterCriticalSection(&pass->passCS);

    pass->lbfields = lbfields;
    pass->lbflen = lbflen;

    LeaveCriticalSection(&pass->passCS);

    return 0;
}

int passurl_set_url (void * vpu, char * url, int len)
{
    PassURL  * pass = (PassURL *)vpu;

    if (!pass) return -1;

    if (!url) return -2;
    if (len < 0) len = str_len(url);

    EnterCriticalSection(&pass->passCS);
    pass->url = url;
    pass->urllen = len;
    LeaveCriticalSection(&pass->passCS);

    return 0;
}

int passurl_add_passitem (void * vpu, void * vpi)
{
    PassURL  * pass = (PassURL *)vpu;
    PassItem * item = (PassItem *)vpi;
#if defined(_WIN32) || defined(_WIN64)
    char     * errstr = NULL;
    int        erroff = 0;
#endif

    if (!pass) return -1;
    if (!item) return -2;

    EnterCriticalSection(&pass->passCS);

    if (item->status == 0)
        arr_push(pass->down_url_list, item);
    else if (item->status == 1)
        arr_push(pass->url_list, item);
    else if (item->status == 2)
        arr_push(pass->back_url_list, item);
    else
        arr_push(pass->url_list, item);

    pass->weight_changed = 1;

    if (item->matchtype == MATCH_REGEX_CASE) {
#ifdef UNIX
        item->preg = kzalloc(sizeof(regex_t));
        regcomp(item->preg, item->match, REG_EXTENDED);
#endif
#if defined(_WIN32) || defined(_WIN64)
        item->preg = pcre_compile(item->match, 0, &errstr, &erroff, NULL);
#endif

    } else if (item->matchtype == MATCH_REGEX_NOCASE) {
#ifdef UNIX
        item->preg = kzalloc(sizeof(regex_t));
        regcomp(item->preg, item->match, REG_EXTENDED | REG_ICASE);
#endif
#if defined(_WIN32) || defined(_WIN64)
        item->preg = pcre_compile(item->match, PCRE_CASELESS, &errstr, &erroff, NULL);
#endif
    }

    LeaveCriticalSection(&pass->passCS);

    return 0;
}

int passitem_qsort_cmp (void * a, void * b)
{
    PassItem * itema = *(PassItem **)a;
    PassItem * itemb = *(PassItem **)b;

    if (!itema) return -1;
    if (!itemb) return 1;

    if (itema->weight > itemb->weight) return 1;
    if (itema->weight < itemb->weight) return -1;
    return 0;
}

int passitem_cmp_weight (void * a, void * b)
{
    PassItem * item = (PassItem *)a;
    long weight = *(long *)b;

    if (item->weight > weight) return 1;
    if (item->weight < weight) return -1;
    return 0;
}

int passurl_weight_calc (void * vpu)
{
    PassURL  * pass = (PassURL *)vpu;
    PassItem * item = NULL;
    long       weight = 0;
    int        i, num;

    if (!pass) return -1;
    if (!item) return -2;

    EnterCriticalSection(&pass->passCS);

    num = arr_num(pass->url_list);
    for (i = 0; i < num; i++) {
        item = arr_value(pass->url_list, i);
        if (!item) continue;

        weight += item->weight;
    }

    pass->weight = weight;
    pass->weight_changed = 0;

    arr_sort_by(pass->url_list, passitem_qsort_cmp);

    LeaveCriticalSection(&pass->passCS);
    
    return 0;
}

void * passurl_weight_select (void * vpu)
{
    PassURL  * pass = (PassURL *)vpu;
    PassItem * item = NULL;
    PassItem * selitem = NULL;
    long       maxwei = 0;
    int        i, num;

    if (!pass) return NULL;

    num = arr_num(pass->url_list);
    for (i = 0; i < num; i++) {
        item = arr_value(pass->url_list, i);
        if (!item) continue;

        item->curwei += item->weight;

        if (item->curwei >= maxwei) {
            maxwei = item->curwei;
            selitem = item;
        }
    }

    if (selitem) {
        selitem->curwei -= pass->weight;
    }

    return selitem;
}

void * passurl_fast_transact_select (void * vpu)
{
    PassURL  * pass = (PassURL *)vpu;
    HTTPSrv  * srv = NULL;
    PassItem * item = NULL;
    PassItem * selitem = NULL;
    int        i, num;
    uint8      reget = 0;
    int        rtt = 0;

    if (!pass) return NULL;

    if (time(0) - pass->srv_tick > 60) {
        reget = 1;
        pass->srv_tick = time(0);
    }

    num = arr_num(pass->url_list);
    for (i = 0; i < num; i++) {
        item = arr_value(pass->url_list, i);
        if (!item) continue;

        if (reget || item->srv == NULL)
            srv = item->srv = http_mgmt_hostsrv_get(gp_httpmgmt,
                                  item->host, item->hostlen, item->port, item->ssl_link);
        else
            srv = item->srv;

        if (!srv) continue;

        if (rtt == 0 || srv->rtt <= rtt) {
            rtt = srv->rtt;
            selitem = item;
        }
    }

    return selitem;
}

void * passurl_least_conn_select (void * vpu)
{
    PassURL  * pass = (PassURL *)vpu;
    HTTPSrv  * srv = NULL;
    PassItem * item = NULL;
    PassItem * selitem = NULL;
    int        i, num;
    uint8      reget = 0;
    int        concnt = 0;

    if (!pass) return NULL;

    if (time(0) - pass->srv_tick > 60) {
        reget = 1;
        pass->srv_tick = time(0);
    }

    num = arr_num(pass->url_list);
    for (i = 0; i < num; i++) {
        item = arr_value(pass->url_list, i);
        if (!item) continue;

        if (reget || item->srv == NULL)
            srv = item->srv = http_mgmt_hostsrv_get(gp_httpmgmt,
                                  item->host, item->hostlen, item->port, item->ssl_link);
        else
            srv = item->srv;

        if (!srv) continue;

        if (concnt == 0 || srv->concnt <= concnt) {
            concnt = srv->concnt;
            selitem = item;
        }
    }

    return selitem;
}

void * passurl_consist_hash_select (void * vmsg, void * vpu)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    PassURL  * pass = (PassURL *)vpu;
    char       buf[8192];
    int        buflen = 0;
    int        num, selind = 0;
    long       hash = 0;

    if (!msg || !pass) return NULL;

    num = arr_num(pass->url_list);
    if (num <= 0) return NULL;

    buflen = http_var_copy(msg, pass->lbfields, pass->lbflen,
                           buf, sizeof(buf)-1, NULL, 0, "lbfields", 4);
    if (buflen <= 0) return NULL;

    hash = murmur_hash2(buf, buflen, 8327843);

    selind = arr_findloc_by(pass->url_list, &hash, passitem_cmp_weight, NULL);
    selind = selind % num;

    return arr_value(pass->url_list, selind);
}

void * passurl_pattern_match_select (void * vmsg, void * vpu)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    PassURL    * pass = (PassURL *)vpu;
    char         buf[8192];
    int          buflen = 0;
    PassItem   * item = NULL;
    int          i, num, ret;
#ifdef UNIX
    regmatch_t   pmat[16];
#endif
#if defined(_WIN32) || defined(_WIN64)
    int          ovec[36];
#endif

    if (!msg || !pass) return NULL;

    num = arr_num(pass->url_list);
    if (num <= 0) return NULL;

    buflen = http_var_copy(msg, pass->lbfields, pass->lbflen,
                           buf, sizeof(buf)-1, NULL, 0, "lbfields", 4);
    if (buflen <= 0) return NULL;

    for (i = 0; i < num; i++) {
        item = arr_value(pass->url_list, i);
        if (!item) continue;

        switch (item->matchtype) {
        case MATCH_EXACT:
            if (buflen != item->matchlen) continue;
            if (str_ncasecmp(buf, item->match, buflen) != 0) continue;
            return item;

        case MATCH_REGEX_CASE:
        case MATCH_REGEX_NOCASE:
#ifdef UNIX
            ret = regexec(item->preg, buf, 16, pmat, 0);
            if (ret == 0) {
#endif
#if defined(_WIN32) || defined(_WIN64)
            ret = pcre_exec(item->preg, NULL, buf, buflen, 0, 0, ovec, 36);
            if (ret > 0) {
#endif
                return item;
            }
            break;

        case MATCH_PREFIX:
        case MATCH_PREFIX_DEFAULT:
        default:
            if (item->matchlen > buflen) continue;
            if (str_ncasecmp(buf, item->match, item->matchlen) != 0) continue;
            return item;
        }
    }

    return NULL;
}

int passurl_get (void * vmsg, char ** passurl, int * len)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPLoc  * ploc = NULL;
    PassURL  * pass = NULL;
    PassItem * item = NULL;
    int        num = 0;

    if (!msg) return -1;

    if ((ploc = msg->ploc) == NULL)
        return -2;

    if ((pass = ploc->passurl) == NULL)
        return -3;

    if (pass->weight_changed)
        passurl_weight_calc(pass);

    EnterCriticalSection(&pass->passCS);

    if ((num = arr_num(pass->url_list)) <= 0) 
        goto getitem;

    if (num == 1) {
        item = arr_value(pass->url_list, 0);
        goto getitem;
    }

    switch (pass->loadbal) {
    case LBA_WEIGHT:
        item = passurl_weight_select(pass);
        break;

    case LBA_FAST_TRANSACT:
        item = passurl_fast_transact_select(pass);
        break;

    case LBA_LEAST_CONN:
        item = passurl_least_conn_select(pass);
        break;

    case LBA_CONSIST_HASH:
        item = passurl_consist_hash_select(msg, pass);
        break;

    case LBA_PATTERN_MATCH:
        item = passurl_pattern_match_select(msg, pass);
        break;

    case LBA_ROUND_ROBIN:
    default:
        item = arr_value(pass->url_list, pass->passcnt++ % num);
        break;
    }

getitem:
    LeaveCriticalSection(&pass->passCS);

    if (!item) {
        if (arr_num(pass->back_url_list) > 0)
            item = arr_value(pass->back_url_list, 0);
    }

    if (item) {
        if (passurl) *passurl = item->url;
        if (len) *len = item->urllen;
        return 0;

    } else if (pass->url && pass->urllen > 0) {
        if (passurl) *passurl = pass->url;
        if (len) *len = pass->urllen;
        return 0;
    }

    return -100;
}

void passurl_print (void * vpu, FILE * fp)
{
    PassURL  * pass = (PassURL *)vpu;
    PassItem * item = NULL;
    int        i, num;

    if (!pass) return;

    if (!fp) fp = stdout;

    fprintf(fp, "PassURL: ");
    switch (pass->loadbal) {
    case LBA_UNKNOWN: fprintf(fp, "unknown"); break;
    case LBA_ROUND_ROBIN: fprintf(fp, "round-robin"); break;
    case LBA_WEIGHT: fprintf(fp, "weight"); break;
    case LBA_FAST_TRANSACT: fprintf(fp, "fast_transact"); break;
    case LBA_LEAST_CONN: fprintf(fp, "least_conn"); break;
    case LBA_CONSIST_HASH: fprintf(fp, "consist_hash"); break;
    case LBA_PATTERN_MATCH: fprintf(fp, "pattern_match"); break;
    default: fprintf(fp, "Error Value"); break;
    }
    fprintf(fp, " LoadBalanceFields: %s  ItemNum: %d\n",
            pass->lbfields?pass->lbfields:"", arr_num(pass->url_list));

    num = arr_num(pass->url_list);
    for (i = 0; i < num; i++) {
        item = arr_value(pass->url_list, i);
        if (!item) continue;

        fprintf(fp, "  %d: URL=%s Weight=%ld Match='%s' MatchType='",
                i, item->url, item->weight, item->match?item->match:"");
        switch (item->matchtype) {
        case MATCH_EXACT: fprintf(fp, "="); break;
        case MATCH_PREFIX: fprintf(fp, "^~"); break;
        case MATCH_PREFIX_DEFAULT: fprintf(fp, "^~"); break;
        case MATCH_REGEX_CASE: fprintf(fp, "~"); break;
        case MATCH_REGEX_NOCASE: fprintf(fp, "~*"); break;
        default: fprintf(fp, " "); break;
        }
        fprintf(fp, "'");

        fprintf(fp, " Status=");
        switch (item->status) {
        case 0: fprintf(fp, "down"); break;
        case 1: fprintf(fp, "up"); break;
        case 2: fprintf(fp, "backup"); break;
        default: fprintf(fp, "unknown"); break;
        }

        if (item->max_fails > 0)
            fprintf(fp, " Max_Fails=%d", item->max_fails);
        if (item->fail_timeout > 0)
            fprintf(fp, " Fail_Timeout=%d", item->fail_timeout);
        fprintf(fp, "\n");
    }
}


void * http_loc_alloc (char * path, int pathlen, uint8 pathdup, int matchtype, int servtype, char * root)
{
    HTTPLoc * ploc = NULL;

    if (!path) return NULL;
    if (pathlen < 0) pathlen = strlen(path);
    if (pathlen <= 0) return NULL;

    ploc = kzalloc(sizeof(*ploc));
    if (!ploc) return NULL;

    if (pathdup) {
        ploc->path = str_dup(path, pathlen);
        ploc->path_dup = 1;
    } else {
        ploc->path = path;
        ploc->path_dup = 0;
    }

    ploc->matchtype = matchtype;
    ploc->type = servtype;

    if (!root || strlen(root) <= 0) root = ".";
    str_secpy(ploc->root, sizeof(ploc->root)-1, root, strlen(root));

    ploc->script_list = arr_new(2);
    ploc->reply_script_list = arr_new(2);
    ploc->cache_check_script_list = arr_new(2);
    ploc->cache_store_script_list = arr_new(2);

    return ploc;
}

void http_loc_free (void * vloc)
{
    HTTPLoc * ploc = (HTTPLoc *)vloc;

    if (!ploc) return;

    if (ploc->passurl) passurl_free(ploc->passurl);

    if (ploc->path_dup) kfree(ploc->path);

    arr_pop_kfree(ploc->cache_store_script_list);
    arr_pop_kfree(ploc->cache_check_script_list);
    arr_pop_kfree(ploc->reply_script_list);
    arr_pop_kfree(ploc->script_list);

    kfree(ploc);
}

int http_loc_set_root (void * vloc, char * root, int rootlen)
{
    HTTPLoc * ploc = (HTTPLoc *)vloc;

    if (!ploc) return -1;

    return str_secpy(ploc->root, sizeof(ploc->root) - 1, root, rootlen);
}

int http_loc_set_index (void * vloc, char ** indexlist, int num)
{
    HTTPLoc * ploc = (HTTPLoc *)vloc;
    int       i;

    if (!ploc) return -1;

    if (!indexlist || num <= 0) return -2;

    ploc->indexnum = num;

    for (i = 0; i < num; i++) {
        ploc->index[i] = indexlist[i];
    }

    return num;
}

int http_loc_set_proxy (void * vloc, char * passurl, char * cachefile)
{
    HTTPLoc * ploc = (HTTPLoc *)vloc;

    if (!ploc) return -1;

    if (!passurl) return -2;

    ploc->type = SERV_PROXY;

    if (!ploc->passurl) ploc->passurl = passurl_alloc();
    passurl_set_url(ploc->passurl, passurl, -1);

    if (cachefile) {
        ploc->cache = 1;
        ploc->cachefile = cachefile;
    }

    return 0;
}

int http_loc_set_fastcgi (void * vloc, char * passurl)
{
    HTTPLoc * ploc = (HTTPLoc *)vloc;

    if (!ploc) return -1;

    if (!passurl) return -2;

    ploc->type = SERV_FASTCGI;

    if (!ploc->passurl) ploc->passurl = passurl_alloc();
    passurl_set_url(ploc->passurl, passurl, -1);

    return 0;
}


int http_loc_cmp_path (void * vloc, void * vpath)
{
    HTTPLoc * ploc = (HTTPLoc *)vloc;
    char    * path = (char *)vpath;

    if (!ploc) return -1;
    if (!path) return 1;

    return strcasecmp(ploc->path, path);
}

int http_loc_build (void * vhost, void * jhost)
{
    HTTPHost   * host = (HTTPHost *)vhost;
    HTTPLoc    * ploc = NULL;
    HTTPLoc    * ptmp = NULL;
#ifdef UNIX
    regex_t    * preg = NULL;
#endif
#if defined(_WIN32) || defined(_WIN64)
    char       * errstr = NULL;
    int          erroff = 0;
    pcre       * preg = NULL;
#endif

    int          i, locnum;
    int          ret = 0, subret = 0;
    int          j = 0;
 
    char         key[128];
    char       * value = NULL;
    int          valuelen = 0;
 
    void       * jloc = NULL;
    char       * path = NULL;
    int          matchtype = MATCH_DEFAULT;
    int          type = 0;
    char       * root = NULL;
 
    void       * jpassurl = NULL;
    void       * jpassitem = NULL;
    int          k, itemnum;
    PassItem   * passitem = NULL;

    if (!host) return -1;
    if (!jhost) return -2;
 
    sprintf(key, "location");
    ret = json_mget_obj(jhost, key, -1, &jloc);
    if (ret <= 0) {
        /* here one default HTTPLoc should be created and appended */

        tolog(1, "eJet - HTTPHost <%s> has no <Location> configure option!\n", host->hostname);
        return -100;
    }
 
    for (locnum = ret, i = 1; i <= locnum && jloc != NULL; i++) {
        path = NULL;
        matchtype = MATCH_DEFAULT;
        type = 0;
        root = NULL;

        ret = json_mgetP(jloc, "path", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            path = value;

            if (ret > 1) {
                ret = json_mgetP(jloc, "path[1]", -1, (void **)&value, &valuelen);
                if (value && valuelen > 0) {
                    if (strcmp(value, "=") == 0)
                        matchtype = MATCH_EXACT;  //1, exact matching
                    else if (strcmp(value, "^~") == 0)
                        matchtype = MATCH_PREFIX;  //2, prefix matching
                    else if (strcmp(value, " ") == 0 || strcmp(value, "\t") == 0)
                        matchtype = MATCH_PREFIX_DEFAULT;  //3, default prefix matching
                    else if (strcmp(value, "~") == 0)
                        matchtype = MATCH_REGEX_CASE;  //4, regex matching with case censitive
                    else if (strcmp(value, "~*") == 0)
                        matchtype = MATCH_REGEX_NOCASE;  //5, regex matching ignoring case
                } else {
                    matchtype = MATCH_PREFIX_DEFAULT; //3, default prefix matching
                }
            } else {
                matchtype = MATCH_PREFIX_DEFAULT; //3, default prefix matching
            }

            if (strcmp(path, "/") == 0)
                matchtype = MATCH_DEFAULT; //0, default

        } else {
            matchtype = MATCH_DEFAULT; //0, as default when path member not exist
        }

        ret = json_mgetP(jloc, "type", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "server") == 0)
                type = SERV_SERVER;
            else if (strcasecmp(value, "upload") == 0)
                type = SERV_UPLOAD;
            else if (strcasecmp(value, "proxy") == 0)
                type = SERV_PROXY;
            else if (strcasecmp(value, "fastcgi") == 0)
                type = SERV_FASTCGI;
        }

        ret = json_mgetP(jloc, "root", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            root = value;
        } else {
            root = host->root;
        }

        ploc = http_loc_alloc(path, -1, 0, matchtype, type, root);
        if (!ploc) goto nextloc;

        ploc->jsonobj = jloc;
        ploc->matchtype = matchtype;

        if (ploc->type & SERV_UPLOAD) {//upload
            if (host->uploadloc)
                http_loc_free(host->uploadloc);

            host->uploadloc = ploc;

        } else {
            EnterCriticalSection(&host->hostCS);

            switch (ploc->matchtype) {
            case MATCH_DEFAULT:  //default loc
                if (ploc->type & SERV_PROXY || ploc->type & SERV_FASTCGI) { //proxy or fastcgi
                    ploc->matchtype = MATCH_PREFIX_DEFAULT;  //prefix matching
                    arr_push(host->prefix_loc_list, ploc);
                    actrie_add(host->prefix_actrie, ploc->path, -1, ploc);
                    break;
                }

                if (host->defaultloc)
                    http_loc_free(host->defaultloc);

                host->defaultloc = ploc;
                break;

            case MATCH_EXACT:  //exact matching
                ptmp = ht_delete(host->exact_loc_table, ploc->path);
                if (ptmp) {
                    http_loc_free(ptmp);
                }
                ht_set(host->exact_loc_table, ploc->path, ploc);
                break;

            case MATCH_PREFIX:  //prefix matching
            case MATCH_PREFIX_DEFAULT:  //default prefix matching
                arr_push(host->prefix_loc_list, ploc);
                actrie_add(host->prefix_actrie, ploc->path, -1, ploc);
                break;

            case MATCH_REGEX_CASE:  //regex matching with case censitive
            case MATCH_REGEX_NOCASE:  //regex matching ignoring case
                arr_push(host->regex_loc_list, ploc);

#ifdef UNIX
                preg = kzalloc(sizeof(regex_t));
                if (ploc->matchtype == MATCH_REGEX_CASE) { //case censitive
                    regcomp(preg, ploc->path, REG_EXTENDED);

                } else { //ignoring case
                    regcomp(preg, ploc->path, REG_EXTENDED | REG_ICASE);
                }
#endif
#if defined(_WIN32) || defined(_WIN64)
                if (ploc->matchtype == MATCH_REGEX_CASE) { //case censitive
                    preg = pcre_compile(ploc->path, 0, &errstr, &erroff, NULL);

                } else { //ignoring case
                    preg = pcre_compile(ploc->path, PCRE_CASELESS, &errstr, &erroff, NULL);
                }
#endif

                arr_push(host->regex_list, preg);
                break;
            }

            LeaveCriticalSection(&host->hostCS);
        }

        ret = json_mgetP(jloc, "index", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            ploc->indexnum = ret;
            ploc->index[0] = value;

            for (j = 1; j < (int)ploc->indexnum && j < sizeof(ploc->index)/sizeof(ploc->index[0]); j++) {
                sprintf(key, "index[%d]", j);
                ret = json_mgetP(jloc, key, -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0) {
                    ploc->index[j] = value;
                }
            }
        } else {
            ploc->indexnum = host->indexnum;
            for (j = 0; j < (int)host->indexnum && j < sizeof(ploc->index)/sizeof(ploc->index[0]); j++) {
                ploc->index[j] = host->index[j];
            }
        }

        ret = json_mgetP(jloc, "auto redirect", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
                ploc->auto_redirect = 1;
            else
                ploc->auto_redirect = 0;
        } else {
            ploc->auto_redirect = host->auto_redirect;
        }

        ret = json_mgetP(jloc, "show file list", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
                ploc->show_file_list = 1;
            else
                ploc->show_file_list = 0;
        }

        ret = json_mget_value(jloc, "passurl", -1, (void **)&value, &valuelen, &jpassurl);
        if (ret > 0 && jpassurl) {
            ploc->passurl = passurl_alloc();
            if (!ploc->passurl) break;

            ret = json_mgetP(jpassurl, "loadbal", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0)
                passurl_set_loadbal(ploc->passurl, value, valuelen);

            ret = json_mgetP(jpassurl, "lbfields", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0)
                passurl_set_lbfields(ploc->passurl, value, valuelen);

            ret = json_mget_obj(jpassurl, "server", -1, &jpassitem);

            for (itemnum = ret, k = 1; k <= itemnum && jpassitem != NULL; k++) {
                passitem = passitem_alloc();
                if (!passitem) break;
                
                ret = json_mgetP(jpassitem, "url", -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0)
                    passitem_set_url(passitem, value, valuelen);

                json_mget_long(jpassitem, "weight", -1, &passitem->weight);

                ret = json_mgetP(jpassitem, "match", -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0)
                    passitem_set_match(passitem, value, valuelen);

                ret = json_mgetP(jpassitem, "matchtype", -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0)
                    passitem_set_matchtype(passitem, value, valuelen);

                ret = json_mgetP(jpassitem, "status", -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0)
                    passitem_set_status(passitem, value, valuelen);

                json_mget_int(jpassitem, "max_fails", -1, &passitem->max_fails);
                json_mget_int(jpassitem, "fail_timeout", -1, &passitem->fail_timeout);

                passurl_add_passitem(ploc->passurl, passitem);

                sprintf(key, "server[%d]", k);
                ret = json_mget_obj(jpassurl, key, -1, &jpassitem);
                if (ret <= 0) break;
            }

#ifdef _DEBUG
            passurl_print(ploc->passurl, stdout);
#endif

        } else if (ret > 0 && value && valuelen > 0) {
            ploc->passurl = passurl_alloc();
            if (ploc->passurl)
                passurl_set_url(ploc->passurl, value, valuelen);
        }

        ret = json_mgetP(jloc, "cache", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
                ploc->cache = 1;
            else
                ploc->cache = 0;
        } else {
            ploc->cache = host->cache;
        }

        ret = json_mgetP(jloc, "cache file", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            ploc->cachefile = value;
        } else {
            ploc->cachefile = host->cachefile;
        }

        ret = json_mgetP(jloc, "script", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            arr_push(ploc->script_list, ckstr_new(value, valuelen));

            for (j = 1; j < ret; j++) {
                sprintf(key, "script[%d]", j);
                subret = json_mgetP(jloc, key, -1, (void **)&value, &valuelen);
                if (subret > 0 && value && valuelen > 0) {
                    arr_push(ploc->script_list, ckstr_new(value, valuelen));
                }
            }
        }

        ret = json_mgetP(jloc, "reply_script", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            arr_push(ploc->reply_script_list, ckstr_new(value, valuelen));
 
            for (j = 1; j < ret; j++) {
                sprintf(key, "reply_script[%d]", j);
                subret = json_mgetP(jloc, key, -1, (void **)&value, &valuelen);
                if (subret > 0 && value && valuelen > 0) {
                    arr_push(ploc->reply_script_list, ckstr_new(value, valuelen));
                }
            }
        }

        ret = json_mgetP(jloc, "cache_check_script", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            arr_push(ploc->cache_check_script_list, ckstr_new(value, valuelen));

            for (j = 1; j < ret; j++) {
                sprintf(key, "cache_check_script[%d]", j);
                subret = json_mgetP(jloc, key, -1, (void **)&value, &valuelen);
                if (subret > 0 && value && valuelen > 0) {
                    arr_push(ploc->cache_check_script_list, ckstr_new(value, valuelen));
                }
            }
        }

nextloc:
        sprintf(key, "location[%d]", i);
        ret = json_mget_obj(jhost, key, -1, &jloc);
        if (ret <= 0) break;
    }

    return 0;
}


int http_host_cmp (void * vhost, void * vname)
{
    HTTPHost * host = (HTTPHost *)vhost;
    ckstr_t  * ckstr = (ckstr_t *)vname;
    ckstr_t    tmp;

    if (!host) return -1;
    if (!ckstr) return 1;

    tmp.p = host->hostname;
    tmp.len = strlen(host->hostname);

    return ckstr_casecmp(&tmp, ckstr);
}


typedef struct ConnectHost_st {
    char  * host;
    int     hostlen;
    int     port;
} ConnectHost;


int http_host_cmp_connecthost (void * vhost, void * vconhost)
{
    HTTPHost    * host = (HTTPHost *)vhost;
    ConnectHost * conhost = (ConnectHost *)vconhost;
    int           hostlen = 0;
    int           ret = 0;

    if (!host || !conhost) return -1;

    if (host->port > 0 && conhost->port > 0) {
        if (host->port > conhost->port) return 1;
        if (host->port < conhost->port) return -1;
    }

    hostlen = strlen(host->hostname);

    if (conhost->host == NULL || conhost->hostlen == 0) {
        if (hostlen == 0) return 0;
        else return 1;
    }

    if (hostlen == conhost->hostlen) {
        return str_ncasecmp(host->hostname, conhost->host, hostlen);
    } else if (hostlen > conhost->hostlen) {
        ret = str_ncasecmp(host->hostname, conhost->host, conhost->hostlen);
        if (ret == 0) return 1;
        return ret;
    }

    ret = str_ncasecmp(host->hostname, conhost->host, hostlen);
    if (ret == 0) return -1;
    return ret;
}

ulong http_connect_host_hash (void * key)
{
    ConnectHost * conhost = (ConnectHost *)key;
    ulong hash = 0;
    char extstr[16];

    if (!conhost) return 0;

    if (conhost->port > 0) {
        sprintf(extstr, "%d", conhost->port);
        hash = string_hash(extstr, strlen(extstr), 4727621L);
    } else hash = 4727621L;

    hash = string_hash(conhost->host, conhost->hostlen, hash);

    return hash;
}

void * http_host_alloc (char * hostn, int hostlen)
{
    HTTPHost * host = NULL;

    if (!hostn) return NULL;

    if (hostlen < 0) hostlen = strlen(hostn);

    host = kzalloc(sizeof(*host));
    if (!host) return NULL;

    host->matchtype = 0;

    str_secpy(host->hostname, sizeof(host->hostname)-1, hostn, hostlen);
    host->port = 0;

    host->maxcon = 0;
    host->proxyhost[0] = '\0';
    host->proxyport = 0;

    InitializeCriticalSection(&host->hostCS);

    host->exact_loc_table = ht_new(64, http_loc_cmp_path);

    host->prefix_loc_list = arr_new(4);
    host->prefix_actrie = actrie_init(64, NULL, 0);

    host->regex_loc_list = arr_new(4);
    host->regex_list = arr_new(4);

    host->uploadloc = NULL;
    host->defaultloc = NULL;

    host->script_list = arr_new(2);
    host->reply_script_list = arr_new(2);
    host->cache_check_script_list = arr_new(2);
    host->cache_store_script_list = arr_new(2);

    InitializeCriticalSection(&host->texttplCS);
    host->texttpl_tab = ht_new(300, http_pagetpl_cmp_key);
    ht_set_hash_func(host->texttpl_tab, ckstr_string_hash);
     
    InitializeCriticalSection(&host->listtplCS); 
    host->listtpl_tab = ht_new(300, http_pagetpl_cmp_key);
    ht_set_hash_func(host->listtpl_tab, ckstr_string_hash);

    return host;
}

void http_host_free (void * vhost)
{
    HTTPHost * host = (HTTPHost *)vhost;
    int        i, num;
#ifdef UNIX
    regex_t  * preg = NULL;
#endif
#if defined(_WIN32) || defined(_WIN64)
    pcre     * preg = NULL;
#endif

    if (!host) return;

#ifdef HAVE_OPENSSL
    if (host->sslctx) {
        http_ssl_ctx_free(host->sslctx);
        host->sslctx = NULL;
    }
#endif

    /* ploc instanc hash table freed, used as exact path matching */
    if (host->exact_loc_table) {
        ht_free_all(host->exact_loc_table, http_loc_free);
        host->exact_loc_table = NULL;
    }

    /* ploc instanc list freed, used as path prefix matching */
    if (host->prefix_loc_list) {
        arr_pop_free(host->prefix_loc_list, http_loc_free);
        host->prefix_loc_list = NULL;
    }

    /* freeing Wu-Manber multi-pattern matching object */
    if (host->prefix_actrie) {
        actrie_free(host->prefix_actrie);
        host->prefix_actrie = NULL;
    }
    
    /* ploc instance list freed, used as regex matching */
    if (host->regex_loc_list) {
        arr_pop_free(host->regex_loc_list, http_loc_free);
        host->regex_loc_list = NULL;
    }

    if (host->regex_list) {
        num = arr_num(host->regex_list);
        for (i = 0; i < num; i++) {
            preg = arr_value(host->regex_list, i);
#ifdef UNIX
            regfree(preg);
            kfree(preg);
#endif
#if defined(_WIN32) || defined(_WIN64)
            pcre_free(preg);
#endif
        }
        arr_free(host->regex_list);
        host->regex_list = NULL;
    }
    
    if (host->uploadloc) {
        http_loc_free(host->uploadloc);
        host->uploadloc = NULL;
    }

    if (host->defaultloc) {
        http_loc_free(host->defaultloc);
        host->defaultloc = NULL;
    }

    arr_pop_kfree(host->cache_store_script_list);
    arr_pop_kfree(host->cache_check_script_list);
    arr_pop_kfree(host->script_list);
    arr_pop_kfree(host->reply_script_list);

    DeleteCriticalSection(&host->hostCS);

    DeleteCriticalSection(&host->texttplCS);
    if (host->texttpl_tab) {
        ht_free_all(host->texttpl_tab, http_pagetpl_free);
        host->texttpl_tab = NULL;
    }
 
    DeleteCriticalSection(&host->listtplCS);
    if (host->listtpl_tab) {
        ht_free_all(host->listtpl_tab, http_pagetpl_free);
        host->listtpl_tab = NULL;
    }

    kfree(host);
}

void * http_listen_host_create (void * vhl, char * hostn, int hostlen, char * root,
                                char * cert, char * prikey, char * cacert)
{
    HTTPListen * hl = (HTTPListen *)vhl;
    HTTPHost   * host = NULL;
    ckstr_t      key;

    if (!hl) return NULL;

    if (hostn && hostlen < 0) hostlen = strlen(hostn);

    EnterCriticalSection(&hl->hlCS);

    if (!hostn || hostlen <= 0 || (hostlen == 1 && hostn[0] == '*')) {
        if (!hl->defaulthost)
            hl->defaulthost = http_host_alloc("*", 1);

        host = hl->defaulthost;

    } else {
        key.p = hostn; key.len = hostlen;

        host = ht_get(hl->host_table, &key);
        if (!host) {
            host = http_host_alloc(hostn, hostlen);
            ht_set(hl->host_table, &key, host);
        }
    }

    LeaveCriticalSection(&hl->hlCS);

    if (!host) return NULL;

    if (root && strlen(root) > 0) {
        str_secpy(host->root, sizeof(host->root), root, strlen(root));
    } else if (root) {
        host->root[0] = '\0';
    }

    /* SNI mechanism in TLS spec enables the client can select one
       from multiple cetificates coresponding to different host-names.
       Therefore, NULL host-name can not be bound SSL certificate, key. */

    if (hl->ssl_link && host->cert && strlen(host->cert) > 0 &&
        host->prikey && strlen(host->prikey) > 0)
    {
        host->cert = cert;
        host->prikey = prikey;
        host->cacert = cacert;

#ifdef HAVE_OPENSSL
        host->sslctx = http_ssl_server_ctx_init(host->cert, host->prikey, host->cacert);
#endif
    }

    host->hl = hl;

    return host;
}

void * http_connect_host_create (void * vhc, char * hostn, int hostlen, int port, int matchtype,
                                 char * root, char * cert, char * prikey, char * cacert)
{
    HTTPConnect * hc = (HTTPConnect *)vhc;
    HTTPHost    * host = NULL;

    if (!hc) return NULL;

    if (!hostn) return NULL;
    if (hostlen < 0) hostlen = strlen(hostn);
    if (hostlen <= 0) return NULL;

    host = http_connect_host_find(hc, hostn, hostlen, port);
    if (!host) {
        host = http_host_alloc(hostn, hostlen);
    }

    if (!host) return NULL;

    if (root && strlen(root) > 0) {
        str_secpy(host->root, sizeof(host->root), root, strlen(root));
    } else if (root) {
        host->root[0] = '\0';
    }

    host->port = port;
    host->matchtype = matchtype;

    host->cert = cert;
    host->prikey = prikey;
    host->cacert = cacert;

#ifdef HAVE_OPENSSL
    //host->sslctx = http_ssl_client_ctx_init(host->cert, host->prikey, host->cacert);
#endif

    host->hc = hc;

    return host;
}

/* partype value: 0 --> HTTPConnect  1 --> HTTPListen */

int http_host_build (void * vpar, void * jobj, int partype)
{
    HTTPListen  * hl = NULL;
    HTTPConnect * hc = NULL;
    HTTPHost    * host = NULL;

    int          i, hostnum;
    int          ret = 0, subret;
    int          j, num = 0;
    int          code = 0;

    char         key[128];
    int          keylen = 0;
    char       * value = NULL;
    int          valuelen = 0;
 
    void       * jhost = NULL;
    int          matchtype = MATCH_DEFAULT;
    char       * hname = NULL;
    int          hnamelen = 0;
    int          port = 0;
    char       * root = NULL;
    char       * cert = NULL;
    char       * prikey = NULL;
    char       * cacert = NULL;
    char       * plist[4];
    int          plen[4];

    void       * jerrpage = NULL;
 
    if (partype == 1) {
        hl = (HTTPListen *)vpar;
        if (!hl) return -1;
    } else {
        hc = (HTTPConnect *)vpar;
        if (!hc) return -1;
    }
    if (!jobj) return -2;
 
    sprintf(key, "host");
    ret = json_mget_obj(jobj, key, -1, &jhost);
    if (ret <= 0) {
        if (partype == 1)
            tolog(1, "eJet - HTTPListen <%s:%d%s> has no <Host> configure option!\n",
                 strlen(hl->localip) > 0 ? hl->localip : "*",
                  hl->port, hl->ssl_link ? " SSL" : "");
        else
            tolog(1, "eJet - HTTPConnect has no <Host> configure option!\n");
        return -100;
    }

    for (hostnum = ret, i = 1; i <= hostnum && jhost != NULL; i++) {
        matchtype = MATCH_DEFAULT;
        hname = NULL;
        hnamelen = 0;
        port = 0;
        root = NULL;
        cert = NULL; prikey = NULL; cacert = NULL;
 
        ret = json_mgetP(jhost, "host name", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            hname = value;
            hnamelen = valuelen;

            if (ret > 1) {
                ret = json_mgetP(jhost, "host name[1]", -1, (void **)&value, &valuelen);
                if (value && valuelen > 0) {
                    if (strcmp(value, "=") == 0)
                        matchtype = MATCH_EXACT;  //1, exact matching
                    else if (strcmp(value, "^~") == 0)
                        matchtype = MATCH_PREFIX;  //2, prefix matching
                    else if (strcmp(value, " ") == 0 || strcmp(value, "\t") == 0)
                        matchtype = MATCH_PREFIX_DEFAULT;  //3, default prefix matching
                    else if (strcmp(value, "~") == 0)
                        matchtype = MATCH_REGEX_CASE;  //4, regex matching with case censitive
                    else if (strcmp(value, "~*") == 0)
                        matchtype = MATCH_REGEX_NOCASE;  //5, regex matching ignoring case
                } else {
                    matchtype = MATCH_PREFIX_DEFAULT; //3, default prefix matching
                }
            } else {
                matchtype = MATCH_PREFIX_DEFAULT; //3, default prefix matching
            }
        } else {
            matchtype = MATCH_DEFAULT; //0, as default when hostname member not exist
            hnamelen = valuelen;
        }

        json_mget_int(jhost, "port", -1, &port);

        ret = json_mgetP(jhost, "root", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            root = value;
        } else {
            if (partype == 1)
                root = hl->root;
            else
                root = hc->root;
        }

        ret = json_mgetP(jhost, "ssl certificate", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            cert = value;
        } else {
            if (partype == 1)
                cert = hl->cert;
            else
                cert = hc->cert;
        }
 
        ret = json_mgetP(jhost, "ssl private key", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            prikey = value;
        } else {
            if (partype == 1)
                prikey = hl->prikey;
            else
                prikey = hc->prikey;
        }
 
        ret = json_mgetP(jhost, "ssl ca certificate", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            cacert = value;
        } else {
            if (partype == 1)
                cacert = hl->cacert;
            else
                cacert = hc->cacert;
        }

        /* create HTTPHost instance */

        if (partype == 1) {
            host = http_listen_host_create(hl, hname, hnamelen, root, cert, prikey, cacert);
        } else {
            host = http_connect_host_create(hc, hname, hnamelen, port, matchtype, root, cert, prikey, cacert);
            if (host) {
                http_connect_host_add(hc, host);
            }
        }
        if (!host) break;

        host->jsonobj = jhost;

        json_mget_int(jhost, "maxcon", -1, &host->maxcon);

        ret = json_mgetP(jhost, "proxy", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
                host->proxy = 1;
            else
                host->proxy = 0;
        }

        if (host->proxy) {
            ret = json_mgetP(jhost, "proxyhost", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0) {
                ret = string_tokenize(value, valuelen, ":", 1, (void **)plist, plen, 4);
    
                if (ret > 0) str_secpy(host->proxyhost, sizeof(host->proxyhost)-1, plist[0], plen[0]);
                else host->proxyhost[0] = '\0';
    
                if (ret > 1) str_atoi(plist[1], plen[1], &host->proxyport);
                else host->proxyport = 80;
            } else {
                host->proxyhost[0] = '\0';
                host->proxyport = 0;
            }
        } else {
            host->proxyhost[0] = '\0';
            host->proxyport = 0;
        } 

        ret = json_mgetP(jhost, "index", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            host->indexnum = ret;
            host->index[0] = value;

            for (j = 1; j < (int)host->indexnum && j < sizeof(host->index)/sizeof(host->index[0]); j++) {
                sprintf(key, "index[%d]", j);
                ret = json_mgetP(jhost, key, -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0) {
                    host->index[j] = value;
                }
            }
        } else {
            if (partype == 1) {
                host->indexnum = hl->indexnum;
                for (j = 0; j < (int)host->indexnum && j < sizeof(host->index)/sizeof(host->index[0]); j++) {
                    host->index[j] = hl->index[j];
                }
            } else {
                host->indexnum = hc->indexnum;
                for (j = 0; j < (int)host->indexnum && j < sizeof(host->index)/sizeof(host->index[0]); j++) {
                    host->index[j] = hc->index[j];
                }
            }
        }

        ret = json_mgetP(jhost, "auto redirect", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
                host->auto_redirect = 1;
            else
                host->auto_redirect = 0;
        } else {
            if (partype == 1)
                host->auto_redirect = hl->auto_redirect;
            else
                host->auto_redirect = hc->auto_redirect;
        }

        ret = json_mgetP(jhost, "cache", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
                host->cache = 1;
            else
                host->cache = 0;
        } else {
            if (partype == 1)
                host->cache = hl->cache;
            else
                host->cache = hc->cache;
        }

        ret = json_mgetP(jhost, "cache file", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            host->cachefile = value;
        } else {
            if (partype == 1)
                host->cachefile = hl->cachefile;
            else
                host->cachefile = hc->cachefile;
        }

        ret = json_mgetP(jhost, "script", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            arr_push(host->script_list, ckstr_new(value, valuelen));
 
            for (j = 1; j < ret; j++) {
                sprintf(key, "script[%d]", j);
                subret = json_mgetP(jhost, key, -1, (void **)&value, &valuelen);
                if (subret > 0 && value && valuelen > 0)
                    arr_push(host->script_list, ckstr_new(value, valuelen));
            }
        }

        ret = json_mgetP(jhost, "reply_script", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            arr_push(host->reply_script_list, ckstr_new(value, valuelen));
 
            for (j = 1; j < ret; j++) {
                sprintf(key, "reply_script[%d]", j);
                subret = json_mgetP(jhost, key, -1, (void **)&value, &valuelen);
                if (subret > 0 && value && valuelen > 0)
                    arr_push(host->reply_script_list, ckstr_new(value, valuelen));
            }
        }

        ret = json_mgetP(jhost, "cache_check_script", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            arr_push(host->cache_check_script_list, ckstr_new(value, valuelen));

            for (j = 1; j < ret; j++) {
                sprintf(key, "cache_check_script[%d]", j);
                subret = json_mgetP(jhost, key, -1, (void **)&value, &valuelen);
                if (subret > 0 && value && valuelen > 0)
                    arr_push(host->cache_check_script_list, ckstr_new(value, valuelen));
            }
        }

        ret = json_mget_bool(jhost, "gzip", -1, &host->gzip);
 
        /* parse the 'error page' object */

        ret = json_mget_obj(jhost, "error page", -1, &jerrpage);
        if (ret > 0) {
            json_mgetP(jerrpage, "root", -1, (void **)&host->errpage.root, &valuelen);

            num = json_num(jerrpage);
            for (j = 0; j < num; j++) {
                ret = json_iter(jerrpage, j, 0, (void **)&hname, &keylen,
                                 (void **)&value, &valuelen, NULL);
                if (ret > 0 && hname && keylen > 0) {
                    code = strtol(hname, NULL, 10);

                    if (code >= 400 && code < 420)
                        host->errpage.err400[code - 400] = value;

                    else if (code >= 500 && code < 520)
                        host->errpage.err500[code - 500] = value;
                }
            }
        }

        http_loc_build(host, jhost);
 
        sprintf(key, "host[%d]", i);
        ret = json_mget_obj(jobj, key, -1, &jhost);
        if (ret <= 0) break;
    }

    return 0;
}


void * http_listen_alloc (char * localip, int port, uint8 fwdpxy)
{
    HTTPListen * hl = NULL;

    if (port == 0) return NULL;

    if (localip == NULL) localip = "";
    else if (strcmp(localip, "*") == 0) localip = "";

    hl = kzalloc(sizeof(*hl));
    if (!hl) return NULL;

    if (localip)
        strncpy(hl->localip, localip, sizeof(localip)-1);
    hl->port = port;
    hl->forwardproxy = fwdpxy;

    hl->mlisten = NULL;

    InitializeCriticalSection(&hl->hlCS);

    hl->host_table = ht_only_new(64, http_host_cmp);
    ht_set_hash_func(hl->host_table, ckstr_string_hash);

    hl->defaulthost = NULL;

    hl->script_list = arr_new(2);
    hl->reply_script_list = arr_new(2);
    hl->cache_check_script_list = arr_new(2);
    hl->cache_store_script_list = arr_new(2);

    return hl;
}

void http_listen_free (void * vhl)
{
    HTTPListen * hl = (HTTPListen *)vhl;
    int          i;

    if (!hl) return;

    arr_pop_kfree(hl->script_list);
    arr_pop_kfree(hl->reply_script_list);
    arr_pop_kfree(hl->cache_check_script_list);
    arr_pop_kfree(hl->cache_store_script_list);

    if (hl->mlisten) {
        mlisten_close(hl->mlisten);
        hl->mlisten = NULL;
    }

#ifdef HAVE_OPENSSL
    if (hl->sslctx) {
        http_ssl_ctx_free(hl->sslctx);
        hl->sslctx = NULL;
    }
#endif

    DeleteCriticalSection(&hl->hlCS);

    if (hl->host_table) {
        ht_free_all(hl->host_table, http_host_free);
        hl->host_table = NULL;
    }

    if (hl->defaulthost) {
        http_host_free(hl->defaulthost);
        hl->defaulthost = NULL;
    }

    for (i = 0; i < 16 && i < hl->cbargc; i++) {
        if (hl->cbargv[i]) {
            kfree(hl->cbargv[i]);
            hl->cbargv[i] = NULL;
        }
    }

    if (hl->cbhandle) {
        if (hl->cbclean)
            (*hl->cbclean)(hl->cbobj);

#ifdef UNIX
        dlclose(hl->cbhandle);
#endif
#if defined(_WIN32) || defined(_WIN64)
        FreeLibrary(hl->cbhandle);
#endif
        hl->cbhandle = NULL;
    }

    kfree(hl);
}

int http_listen_ssl_ctx_set (void * vhl, char * cert, char * prikey, char * cacert)
{
    HTTPListen * hl = (HTTPListen *)vhl;

    if (!hl) return -1;

    hl->ssl_link = 1;

#ifdef HAVE_OPENSSL
    if (hl->sslctx) {
        http_ssl_ctx_free(hl->sslctx);
        hl->sslctx = NULL;
    }
#endif

    hl->cert = cert;
    hl->prikey = prikey;
    hl->cacert = cacert;

#ifdef HAVE_OPENSSL
    hl->sslctx = http_ssl_server_ctx_init(hl->cert, hl->prikey, hl->cacert);
#endif

    return 0;
}

void * http_listen_ssl_ctx_get (void * vhl)
{
    HTTPListen * hl = (HTTPListen *)vhl;

    if (!hl) return NULL;

    return hl->sslctx;
}

void * http_listen_host_get (void * vhl, char * servname)
{
    HTTPListen * hl = (HTTPListen *)vhl;
    ckstr_t      key;
    void       * host = NULL;

    if (!hl) return NULL;

    key.p = servname; key.len = str_len(servname);

    EnterCriticalSection(&hl->hlCS);
    host = ht_get(hl->host_table, &key);
    LeaveCriticalSection(&hl->hlCS);

    return host;
}

int http_listen_cblibfile_set (void * vhl, char * cblibfile)
{
    HTTPListen * hl = (HTTPListen *)vhl;
#ifdef UNIX
    char       * err = NULL;
#endif
    char       * argv[16];
    int          i, plen[16];

    if (!hl) return -1;

    if (!cblibfile) return -2;

    /* firstly release all resources allocated before */

    if (hl->cbhandle) {
        if (hl->cbclean)
            (*hl->cbclean)(hl->cbobj);

#ifdef UNIX
        dlclose(hl->cbhandle);
#endif
#if defined(_WIN32) || defined(_WIN64)
        FreeLibrary(hl->cbhandle);
#endif

        hl->cbhandle = NULL;
    }

    for (i = 0; i < hl->cbargc; i++) {
        kfree(hl->cbargv[i]);
        hl->cbargv[i] = NULL;
    }
    hl->cbargc = 0;

    /* now create new instance for new lib-file */

    /* After the dynamic library is successfully loaded, the parameter format
       required by the entry initialization function is similar to that of the
       main function. Its format is as follows:
          request process library = libappmgmt.so app.conf
    */
    hl->cbargc = string_tokenize(cblibfile, -1, " \t\r\n\f\v", 6, (void **)argv, plen, 16);
    for (i = 0; i < hl->cbargc; i++) {
        hl->cbargv[i] = str_dup(argv[i], plen[i]);
    }

    hl->cblibfile = cblibfile;

#ifdef UNIX
    hl->cbhandle = dlopen(hl->cbargv[0], RTLD_LAZY | RTLD_GLOBAL);
    err = dlerror();

    if (!hl->cbhandle) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> Loading DynLib <%s> error! %s\n",
              strlen(hl->localip) > 0 ? hl->localip : "*",
              hl->port, hl->ssl_link ? " SSL" : "",
              cblibfile, err ? err : "");
        return -100;
    }

    hl->cbinit = dlsym(hl->cbhandle, "http_handle_init");
    if ((err = dlerror()) != NULL) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> DynLib <%s> callback 'http_handle_init' load failed! %s\n",
              strlen(hl->localip) > 0 ? hl->localip : "*",
              hl->port, hl->ssl_link ? " SSL" : "",
              hl->cblibfile, err);
        hl->cbinit = NULL;
    }

    hl->cbfunc = dlsym(hl->cbhandle, "http_handle");
    if ((err = dlerror()) != NULL) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> DynLib <%s> callback 'http_handle' load failed! %s\n",
              strlen(hl->localip) > 0 ? hl->localip : "*",
              hl->port, hl->ssl_link ? " SSL" : "",
              hl->cblibfile, err);
        hl->cbfunc = NULL;
    }

    hl->cbclean = dlsym(hl->cbhandle, "http_handle_clean");
    if ((err = dlerror()) != NULL) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> DynLib <%s> callback 'http_handle_clean' load failed! %s\n",
              strlen(hl->localip) > 0 ? hl->localip : "*",
              hl->port, hl->ssl_link ? " SSL" : "",
              hl->cblibfile, err);
        hl->cbclean = NULL;
    }
#endif

#if defined(_WIN32) || defined(_WIN64)
    hl->cbhandle = LoadLibrary(hl->cbargv[0]);
    if (!hl->cbhandle) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> Loading DynLib <%s> error! errcode=%ld\n",
              strlen(hl->localip) > 0 ? hl->localip : "*",
              hl->port, hl->ssl_link ? " SSL" : "",
              cblibfile, GetLastError());
        return -100;
    }

    hl->cbinit = (HTTPCBInit *)GetProcAddress(hl->cbhandle, "http_handle_init");
    if (hl->cbinit == NULL) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> DynLib <%s> callback 'http_handle_init' "
                 "load failed! errcode=%ld\n",
              strlen(hl->localip) > 0 ? hl->localip : "*",
              hl->port, hl->ssl_link ? " SSL" : "",
              hl->cblibfile, GetLastError());
        hl->cbinit = NULL;
    }

    hl->cbfunc = (HTTPCBHandler *)GetProcAddress(hl->cbhandle, "http_handle");
    if (hl->cbfunc == NULL) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> DynLib <%s> callback 'http_handle' "
                 "load failed! errcode=%ld\n",
              strlen(hl->localip) > 0 ? hl->localip : "*",
              hl->port, hl->ssl_link ? " SSL" : "",
              hl->cblibfile, GetLastError());
        hl->cbfunc = NULL;
    }
 
    hl->cbclean = (HTTPCBClean *)GetProcAddress(hl->cbhandle, "http_handle_clean");
    if (hl->cbclean == NULL) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> DynLib <%s> callback 'http_handle_clean' "
                 "load failed! errcode=%ld\n",
              strlen(hl->localip) > 0 ? hl->localip : "*",
              hl->port, hl->ssl_link ? " SSL" : "",
              hl->cblibfile, GetLastError());
        hl->cbclean = NULL;
    }
#endif

    /* Call the initialization function of the dynamic library with the
       command line parameters of the configuration file */
    if (hl->cbhandle && hl->cbinit) {
        hl->cbobj = (*hl->cbinit)(hl->httpmgmt, hl->cbargc, hl->cbargv);
    }

    if (hl->cbfunc)
        tolog(1, "eJet - HTTP Listen <%s:%d%s> DynLib <%s> load successfully!\n",
                  strlen(hl->localip) > 0 ? hl->localip : "*",
                  hl->port, hl->ssl_link ? " SSL" : "", hl->cblibfile);

    return 0;
}


int http_listen_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    InitializeCriticalSection(&mgmt->listenlistCS);

    if (!mgmt->listen_list) {
        mgmt->listen_list = arr_new(4);
    }

    return http_listen_build (mgmt);
}


int http_listen_cleanup (void * vmgmt)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    int          i, num;

    if (!mgmt) return -1;

    num = arr_num(mgmt->listen_list);

    for (i = 0; i < num; i++) {
        hl = arr_value(mgmt->listen_list, i);
        if (!hl) continue;

        tolog(1, "eJet - HTTP Listen <%s:%d%s> stopped.\n",
                   strlen(hl->localip) > 0 ? hl->localip : "*",
                   hl->port, hl->ssl_link ? " SSL" : "");

        http_listen_free(hl);
    }

    arr_free(mgmt->listen_list);
    mgmt->listen_list = NULL;

    DeleteCriticalSection(&mgmt->listenlistCS);

    return 0;
}

void * http_listen_add (void * vmgmt, char * localip, int port, uint8 fwdpxy)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    int          i, num;

    if (!mgmt) return NULL;

    if (port == 0) return NULL;

    if (localip == NULL) localip = "";
    else if (strcmp(localip, "*") == 0) localip = "";

    EnterCriticalSection(&mgmt->listenlistCS);

    num = arr_num(mgmt->listen_list);
    for (i = 0; i < num; i++) {

        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;

        if (hl->port == port && strcasecmp(hl->localip, localip) == 0) {
            LeaveCriticalSection(&mgmt->listenlistCS);
            return hl;
        }
    }

    hl = http_listen_alloc(localip, port, fwdpxy);
    if (hl) {
        hl->httpmgmt = mgmt;
        arr_push(mgmt->listen_list, hl);
    }

    LeaveCriticalSection(&mgmt->listenlistCS);

    return hl;
}


int http_listen_start_all (void * vmgmt)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    void       * mlisten = NULL;
    HTTPListen * hl = NULL;
    int          i, num;

    if (!mgmt) return -1;

    EnterCriticalSection(&mgmt->listenlistCS);

    num = arr_num(mgmt->listen_list);
    for (i = 0; i < num; i++) {

        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;

        if (hl->mlisten) continue;

        mlisten = eptcp_mlisten(mgmt->pcore, 
                             strlen(hl->localip) > 0 ? hl->localip : NULL,
                             hl->port, NULL, hl, (IOHandler *)http_pump, mgmt);
        if (!mlisten) {
            tolog(1, "eJet - HTTP Listen <%s:%d%s> failed.\n",
                   strlen(hl->localip) > 0 ? hl->localip : "*",
                   hl->port, hl->ssl_link ? " SSL" : "");
            continue;
        }

        hl->mlisten = mlisten;

        tolog(1, "eJet - HTTP Listen <%s:%d%s> started.\n",
                   strlen(hl->localip) > 0 ? hl->localip : "*",
                   hl->port, hl->ssl_link ? " SSL" : "");
    }

    LeaveCriticalSection(&mgmt->listenlistCS);

    return 0;
}


void * http_ssl_listen_start (void * vmgmt, char * localip, int port, uint8 fwdpxy,
                              uint8 ssl, char * cert, char * prikey, char * cacert, char * libfile)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    void       * mlisten = NULL;

    if (!mgmt) return NULL;

    hl = http_listen_add(mgmt, localip, port, fwdpxy);
    if (!hl) return NULL;

    if (ssl > 0)
        http_listen_ssl_ctx_set(hl, cert, prikey, cacert);

    if (libfile)
        http_listen_cblibfile_set(hl, libfile);

    if (!hl->defaulthost)
        http_listen_host_create(hl, NULL, -1, NULL, NULL, NULL, NULL);

    if (hl->mlisten) return hl;

    mlisten = eptcp_mlisten(mgmt->pcore,
                         strlen(hl->localip) > 0 ? hl->localip : NULL,
                         hl->port, NULL, hl, (IOHandler *)http_pump, mgmt);
    if (!mlisten) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> failed.\n",
               strlen(hl->localip) > 0 ? hl->localip : "*",
               hl->port, hl->ssl_link ? " SSL" : "");
        return hl;
    }

    hl->mlisten = mlisten;

    tolog(1, "eJet - HTTP Listen <%s:%d%s> started.\n",
               strlen(hl->localip) > 0 ? hl->localip : "*",
               hl->port, hl->ssl_link ? " SSL" : "");

    return hl;
}


void * http_listen_start (void * vmgmt, char * localip, int port, uint8 fwdpxy, char * libfile)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return NULL;

    return http_ssl_listen_start(mgmt, localip, port, fwdpxy, 0, NULL, NULL, NULL, libfile);
}

int http_listen_num (void * vmgmt)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    int          num = 0;

    if (!mgmt) return -1;

    EnterCriticalSection(&mgmt->listenlistCS);
    num = arr_num(mgmt->listen_list);
    LeaveCriticalSection(&mgmt->listenlistCS);

    return num;
}

void * http_listen_get (void * vmgmt, int index)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;

    EnterCriticalSection(&mgmt->listenlistCS);
    hl = arr_value(mgmt->listen_list, index);
    LeaveCriticalSection(&mgmt->listenlistCS);

    return hl;
}

void * http_listen_find (void * vmgmt, char * localip, int port)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    int          i, num;

    if (!mgmt) return NULL;

    if (localip == NULL) localip = "";
    else if (strcmp(localip, "*") == 0) localip = "";

    EnterCriticalSection(&mgmt->listenlistCS);

    num = arr_num(mgmt->listen_list);

    for (i = 0; i < num; i++) {

        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;

        if (hl->port == port && strcasecmp(hl->localip, localip) == 0) {
            LeaveCriticalSection(&mgmt->listenlistCS);
            return hl;
        }
    }

    LeaveCriticalSection(&mgmt->listenlistCS);

    return NULL;
}


int http_listen_stop (void * vmgmt, char * localip, int port)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    int          i, num;

    if (!mgmt) return -1;
    if (port == 0) return -2;

    if (localip == NULL) localip = "";
    else if (strcmp(localip, "*") == 0) localip = "";

    EnterCriticalSection(&mgmt->listenlistCS);

    num = arr_num(mgmt->listen_list);

    for (i = 0; i < num; i++) {

        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;

        if (!hl->mlisten) {
            arr_delete(mgmt->listen_list, i); i--; num--;
            http_listen_free(hl);
            continue;
        }

        if (hl->port == port && mlisten_port(hl->mlisten) == port &&
            strcasecmp(hl->localip, localip) == 0)
        {
            arr_delete(mgmt->listen_list, i);

            LeaveCriticalSection(&mgmt->listenlistCS);

            http_listen_free(hl);
            return 0;
        }
    }

    LeaveCriticalSection(&mgmt->listenlistCS);

    return -1;
}

int http_listen_check_self (void * vmgmt, char * host, int hostlen, char * dstip, int dstport)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    int          i, j, num;
    int          port_listened = 0;
    ckstr_t      key;
 
    if (!mgmt) return -1;
 
    EnterCriticalSection(&mgmt->listenlistCS);

    num = arr_num(mgmt->listen_list);
    for (i = 0; i < num; i++) {
        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;
 
        if (hl->port != dstport) continue;
 
        port_listened++;
 
        key.p = host; key.len = hostlen;

        if (ht_get(hl->host_table, &key) != NULL) {
            LeaveCriticalSection(&mgmt->listenlistCS);

            /* checked host is one of hosts under listened port */ 
            return 1;
        }
    }
 
    LeaveCriticalSection(&mgmt->listenlistCS);

    if (!port_listened) return 0;
 
    /* check if the dstpip is loop-back ip */
    if (strcasecmp(dstip, "127.0.0.1") == 0) {
        return 1;
    }
 
    /* check if the dstpip is local server ip */
    for (j = 0; dstip && j < mgmt->addrnum; j++) {
        if (strcasecmp(dstip, mgmt->localaddr[j].ipstr) == 0) {
            return 1;
        }
    }
 
    return 0;
}


int http_listen_build (void * vmgmt)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;

    int          i, j, hlnum, ret = 0, subret;
    char         key[128];
    char       * value = NULL;
    int          valuelen = 0;

    void       * jhl = NULL;
    char       * ip = NULL;
    int          port = 0;
    int          forwardproxy = 0;
    int          ssl = 0;
    char       * cert;
    char       * prikey;
    char       * cacert;
    char       * libfile = NULL;

    if (!mgmt) return -1;

    sprintf(key, "http.listen");
    ret = json_mget_value(mgmt->cnfjson, key, -1, (void **)&value, &valuelen, &jhl);
    if (ret <= 0) {
        tolog(1, "eJet - No HTTPListen configured!\n");
        return -100;
    }

    for (hlnum = ret, i = 1; i <= hlnum && jhl != NULL; i++) {
        ip = NULL;
        port = 0;
        forwardproxy = 0;
        ssl = 0;
        libfile = NULL;
        cert = NULL;
        prikey = NULL;
        cacert = NULL;

        ret = json_mgetP(jhl, "local ip", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            ip = value;
        }

        json_mget_int(jhl, "port", -1, &port);

        ret = json_mgetP(jhl, "forward proxy", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
                forwardproxy = 1;
            else
                forwardproxy = 0;
        }

        ret = json_mgetP(jhl, "ssl", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
                ssl = 1;
            else
                ssl = 0;
        }

        ret = json_mgetP(jhl, "ssl certificate", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            cert = value;
        }

        ret = json_mgetP(jhl, "ssl private key", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            prikey = value;
        }

        ret = json_mgetP(jhl, "ssl ca certificate", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            cacert = value;
        }

        ret = json_mgetP(jhl, "request process library", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            libfile = value;
        }

        hl = http_listen_add(mgmt, ip, port, forwardproxy);
        if (hl) {
            hl->jsonobj = jhl;

            if (ssl)
                http_listen_ssl_ctx_set(hl, cert, prikey, cacert);

            if (libfile)
                http_listen_cblibfile_set(hl, libfile);

            ret = json_mgetP(jhl, "index", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0) {
                hl->indexnum = ret;
                hl->index[0] = value;
    
                for (j = 1; j < (int)hl->indexnum && j < sizeof(hl->index)/sizeof(hl->index[0]); j++) {
                    sprintf(key, "index[%d]", j);
                    ret = json_mgetP(jhl, key, -1, (void **)&value, &valuelen);
                    if (ret > 0 && value && valuelen > 0) {
                        hl->index[j] = value;
                    }
                }
            }

            ret = json_mgetP(jhl, "root", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0) {
                str_secpy(hl->root, sizeof(hl->root)-1, value, valuelen);
            }
        
            ret = json_mgetP(jhl, "cache", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0) {
                if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
                    hl->cache = 1;
                else
                    hl->cache = 0;
            }
        
            ret = json_mgetP(jhl, "cache file", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0) {
                hl->cachefile = value;
            }

            ret = json_mgetP(jhl, "script", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0) {
                arr_push(hl->script_list, ckstr_new(value, valuelen));
     
                for (j = 1; j < ret; j++) {
                    sprintf(key, "script[%d]", j);
                    subret = json_mgetP(jhl, key, -1, (void **)&value, &valuelen);
                    if (subret > 0 && value && valuelen > 0)
                        arr_push(hl->script_list, ckstr_new(value, valuelen));
                }
            }

            ret = json_mgetP(jhl, "reply_script", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0) {
                arr_push(hl->reply_script_list, ckstr_new(value, valuelen));

                for (j = 1; j < ret; j++) {
                    sprintf(key, "reply_script[%d]", j);
                    subret = json_mgetP(jhl, key, -1, (void **)&value, &valuelen);
                    if (subret > 0 && value && valuelen > 0)
                        arr_push(hl->reply_script_list, ckstr_new(value, valuelen));
                }
            }

            ret = json_mgetP(jhl, "cache_check_script", -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0) {
                arr_push(hl->cache_check_script_list, ckstr_new(value, valuelen));

                for (j = 1; j < ret; j++) {
                    sprintf(key, "cache_check_script[%d]", j);
                    subret = json_mgetP(jhl, key, -1, (void **)&value, &valuelen);
                    if (subret > 0 && value && valuelen > 0)
                        arr_push(hl->cache_check_script_list, ckstr_new(value, valuelen));
                }
            }

            http_host_build(hl, jhl, 1);
        }

        sprintf(key, "http.listen[%d]", i);
        ret = json_mget_obj(mgmt->cnfjson, key, -1, &jhl);
        if (ret <= 0) break;
    } 

    http_listen_start_all(mgmt);

    return 0;
}



void * http_connect_alloc ()
{
    HTTPConnect * hc = NULL;

    hc = kzalloc(sizeof(*hc));
    if (!hc) return NULL;

    InitializeCriticalSection(&hc->hcCS);

    hc->exact_host_table = ht_new(1000, http_host_cmp_connecthost);
    ht_set_hash_func(hc->exact_host_table, http_connect_host_hash);

    hc->prefix_host_list = arr_new(4);
    hc->prefix_host_actrie = actrie_init(64, NULL, 0);

    hc->regex_host_list = arr_new(4);
    hc->regex_list = arr_new(4);

    hc->script_list = arr_new(2);
    hc->reply_script_list = arr_new(2);
    hc->cache_check_script_list = arr_new(2);
    hc->cache_store_script_list = arr_new(2);

    return hc;
}

void http_connect_free (void * vhc)
{
    HTTPConnect * hc = (HTTPConnect *)vhc;
    int           i, num;
#ifdef UNIX
    regex_t     * preg = NULL;
#endif
#if defined(_WIN32) || defined(_WIN64)
    pcre        * preg = NULL;
#endif

    if (!hc) return;

    arr_pop_kfree(hc->script_list);
    arr_pop_kfree(hc->reply_script_list);
    arr_pop_kfree(hc->cache_check_script_list);
    arr_pop_kfree(hc->cache_store_script_list);

#ifdef HAVE_OPENSSL
    if (hc->sslctx) {
        http_ssl_ctx_free(hc->sslctx);
        hc->sslctx = NULL;
    }
#endif

    DeleteCriticalSection(&hc->hcCS);

    /* phost instanc hash table freed, used as exact host matching */
    if (hc->exact_host_table) {
        ht_free_all(hc->exact_host_table, http_host_free);
        hc->exact_host_table = NULL;
    }

    /* phost instanc list freed, used as host prefix matching */
    if (hc->prefix_host_list) {
        arr_pop_free(hc->prefix_host_list, http_host_free);
        hc->prefix_host_list = NULL;
    }

    /* freeing Wu-Manber multi-pattern matching object */
    if (hc->prefix_host_actrie) {
        actrie_free(hc->prefix_host_actrie);
        hc->prefix_host_actrie = NULL;
    }
    
    /* phost instance list freed, used as regex matching */
    if (hc->regex_host_list) {
        arr_pop_free(hc->regex_host_list, http_host_free);
        hc->regex_host_list = NULL;
    }

    if (hc->regex_list) {
        num = arr_num(hc->regex_list);
        for (i = 0; i < num; i++) {
            preg = arr_value(hc->regex_list, i);
#ifdef UNIX
            regfree(preg);
            kfree(preg);
#endif
#if defined(_WIN32) || defined(_WIN64)
            pcre_free(preg);
#endif
        }
        arr_free(hc->regex_list);
        hc->regex_list = NULL;
    }

    kfree(hc);
}


int http_connect_host_add (void * vhc, void * vhost)
{
    HTTPConnect * hc = (HTTPConnect *)vhc;
    HTTPHost    * phost = (HTTPHost *)vhost;
    ConnectHost   conhost = {0};
    HTTPHost    * ptmp = NULL;
#ifdef UNIX
    regex_t     * preg = NULL;
#endif
#if defined(_WIN32) || defined(_WIN64)
    char        * errstr = NULL;
    int           erroff = 0;
    pcre        * preg = NULL;
#endif
    if (!hc) return -1;

    EnterCriticalSection(&hc->hcCS);

    switch (phost->matchtype) {
    case MATCH_DEFAULT:  //default loc
        phost->matchtype = MATCH_PREFIX_DEFAULT;  //prefix matching
        arr_push(hc->prefix_host_list, phost);
        actrie_add(hc->prefix_host_actrie, phost->hostname, -1, phost);
        break;

    case MATCH_EXACT:  //exact matching
        conhost.host = phost->hostname;
        conhost.hostlen = strlen(phost->hostname);
        conhost.port = phost->port;
        ptmp = ht_delete(hc->exact_host_table, &conhost);
        if (ptmp && ptmp != phost) {
            http_host_free(ptmp);
        }
        ht_set(hc->exact_host_table, &conhost, phost);
        break;

    case MATCH_PREFIX:  //prefix matching
    case MATCH_PREFIX_DEFAULT:  //default prefix matching
        arr_push(hc->prefix_host_list, phost);
        actrie_add(hc->prefix_host_actrie, phost->hostname, -1, phost);
        break;

    case MATCH_REGEX_CASE:  //regex matching with case censitive
    case MATCH_REGEX_NOCASE:  //regex matching ignoring case
        arr_push(hc->regex_host_list, phost);

#ifdef UNIX
        preg = kzalloc(sizeof(regex_t));
        if (phost->matchtype == MATCH_REGEX_CASE) { //case censitive
            regcomp(preg, phost->hostname, REG_EXTENDED);

        } else { //ignoring case
            regcomp(preg, phost->hostname, REG_EXTENDED | REG_ICASE);
        }
#endif
#if defined(_WIN32) || defined(_WIN64)
        if (phost->matchtype == MATCH_REGEX_CASE) { //case censitive
            preg = pcre_compile(phost->hostname, 0, &errstr, &erroff, NULL);

        } else { //ignoring case
            preg = pcre_compile(phost->hostname, PCRE_CASELESS, &errstr, &erroff, NULL);
        }
#endif

        arr_push(hc->regex_list, preg);
        break;
    }

    LeaveCriticalSection(&hc->hcCS);

    return 0;
}

void * http_connect_host_find (void * vhc, char * host, int hostlen, int port)
{
    HTTPConnect * hc = (HTTPConnect *)vhc;
    ConnectHost   conhost = {0};
    HTTPHost    * phost = NULL;
    int           i, num;
    int           ret = 0;
    char          buf[256];
#ifdef UNIX
    regmatch_t    pmat[16];
#endif
#if defined(_WIN32) || defined(_WIN64)
    int           ovec[36];
#endif

    if (!hc) return NULL;
    if (!host || hostlen <= 0) return NULL;

    conhost.host = host;
    conhost.hostlen = hostlen;
    conhost.port = port;

    str_secpy(buf, sizeof(buf)-1, host, hostlen);

    EnterCriticalSection(&hc->hcCS);

    /* exact matching check if request host:port is completely equal to one HTTPHost */
    phost = ht_get(hc->exact_host_table, &conhost);
    if (phost) {
        LeaveCriticalSection(&hc->hcCS);
        return phost;
    }

    /* regular expression matching check if request path is matched by regex */
    num = arr_num(hc->regex_list);
    for (i = 0; i < num; i++) {
#ifdef UNIX
        ret = regexec(arr_value(hc->regex_list, i), buf, 16, pmat, 0);
        if (ret == 0) {
#endif
#if defined(_WIN32) || defined(_WIN64)
        ret = pcre_exec(arr_value(hc->regex_list, i), NULL, buf, strlen(buf), 0, 0, ovec, 36);
        if (ret > 0) {
#endif
            phost = arr_value(hc->regex_host_list, i);
            if (!phost) continue;

            if (phost->port != 0 && port != 0 && phost->port != port)
                continue;

            LeaveCriticalSection(&hc->hcCS);

            return phost;
        }
    }

    /* prefix matching check if request host has the same prefix with configured HTTPHost */
    ret = actrie_get(hc->prefix_host_actrie, host, hostlen, (void **)&phost);
    if (ret > 0 && phost) {
        LeaveCriticalSection(&hc->hcCS);
        return phost;
    }

    LeaveCriticalSection(&hc->hcCS);

    return NULL;
}


int http_connect_sslctx_set (void * vhc, char * cert, char * prikey, char * cacert)
{
    HTTPConnect * hc = (HTTPConnect *)vhc;

    if (!hc) return -1;

    hc->cert = cert;
    hc->prikey = prikey;
    hc->cacert = cacert;

#ifdef HAVE_OPENSSL
    if (hc->sslctx) {
        http_ssl_ctx_free(hc->sslctx);
        hc->sslctx = NULL;
    }

    hc->sslctx = http_ssl_client_ctx_init(hc->cert, hc->prikey, hc->cacert);
#endif

    return 0;
}

void * http_connect_sslctx_get (void * vhc)
{
    HTTPConnect * hc = (HTTPConnect *)vhc;

    if (!hc) return NULL;

    if (hc->sslctx == NULL) {
#ifdef HAVE_OPENSSL
        hc->sslctx = http_ssl_client_ctx_init(hc->cert, hc->prikey, hc->cacert);
#endif
    }

    return hc->sslctx;
}

int http_connect_init (void * vmgmt)
{
    HTTPMgmt    * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    if (mgmt->connectcfg) return 0;

    mgmt->connectcfg = http_connect_alloc();
    if (!mgmt->connectcfg) return -2;

    return http_connect_build(mgmt);
}

int http_connect_cleanup (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    if (!mgmt->connectcfg) return 0;

    http_connect_free(mgmt->connectcfg);

    mgmt->connectcfg = NULL;

    return 1;
}

int http_connect_build (void * vmgmt)
{
    HTTPMgmt    * mgmt = (HTTPMgmt *)vmgmt;
    HTTPConnect * hc = NULL;

    int           j, ret, subret;

    char          key[128];
    char        * value = NULL;
    int           valuelen = 0;

    char        * cert = NULL;
    char        * prikey = NULL;
    char        * cacert = NULL;

    void        * jhc = NULL;

    if (!mgmt) return -1;

    if ((hc = mgmt->connectcfg) == NULL)
        return -2;

    sprintf(key, "http.connect");
    ret = json_mget_obj(mgmt->cnfjson, key, -1, &jhc);
    if (ret <= 0) return -100;

    ret = json_mget_int(jhc, "max header size", -1, &hc->max_header_size);
    if (ret <= 0)
        hc->max_header_size = 32*1024;

    ret = json_mget_int(jhc, "connecting timeout", -1, &hc->connecting_time);
    if (ret <= 0)
        hc->connecting_time = 8;

    ret = json_mget_int(jhc, "keepalive timeout", -1, &hc->keepalive_time);
    if (ret <= 0)
        hc->keepalive_time = 8;

    ret = json_mget_int(jhc, "connection idle timeout", -1, &hc->conn_idle_time);
    if (ret <= 0)
        hc->conn_idle_time = 8;

    ret = json_mgetP(jhc, "ssl certificate", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        cert = value;
    }

    ret = json_mgetP(jhc, "ssl private key", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        prikey = value;
    }

    ret = json_mgetP(jhc, "ssl ca certificate", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        cacert = value;
    }

    if (cert || prikey || cacert) 
        http_connect_sslctx_set(hc, cert, prikey, cacert);

    ret = json_mgetP(jhc, "index", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        hc->indexnum = ret;
        hc->index[0] = value;

        for (j = 1; j < (int)hc->indexnum && j < sizeof(hc->index)/sizeof(hc->index[0]); j++) {
            sprintf(key, "index[%d]", j);
            ret = json_mgetP(jhc, key, -1, (void **)&value, &valuelen);
            if (ret > 0 && value && valuelen > 0) {
                hc->index[j] = value;
            }
        }
    }

    ret = json_mgetP(jhc, "root", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        str_secpy(hc->root, sizeof(hc->root)-1, value, valuelen);
    }

    ret = json_mgetP(jhc, "cache", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        if (strcasecmp(value, "on") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0)
            hc->cache = 1;
        else
            hc->cache = 0;
    }

    ret = json_mgetP(jhc, "cache file", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        hc->cachefile = value;
    }

    ret = json_mgetP(jhc, "script", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        arr_push(hc->script_list, ckstr_new(value, valuelen));
     
        for (j = 1; j < ret; j++) {
            sprintf(key, "script[%d]", j);
            subret = json_mgetP(jhc, key, -1, (void **)&value, &valuelen);
            if (subret > 0 && value && valuelen > 0)
                arr_push(hc->script_list, ckstr_new(value, valuelen));
        }
    }

    ret = json_mgetP(jhc, "reply_script", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        arr_push(hc->reply_script_list, ckstr_new(value, valuelen));

        for (j = 1; j < ret; j++) {
            sprintf(key, "reply_script[%d]", j);
            subret = json_mgetP(jhc, key, -1, (void **)&value, &valuelen);
            if (subret > 0 && value && valuelen > 0)
                arr_push(hc->reply_script_list, ckstr_new(value, valuelen));
        }
    }

    ret = json_mgetP(jhc, "cache_check_script", -1, (void **)&value, &valuelen);
    if (ret > 0 && value && valuelen > 0) {
        arr_push(hc->cache_check_script_list, ckstr_new(value, valuelen));

        for (j = 1; j < ret; j++) {
            sprintf(key, "cache_check_script[%d]", j);
            subret = json_mgetP(jhc, key, -1, (void **)&value, &valuelen);
            if (subret > 0 && value && valuelen > 0)
                arr_push(hc->cache_check_script_list, ckstr_new(value, valuelen));
        }
    }

    http_host_build(hc, jhc, 0);

    hc->jsonobj = jhc;

    return 0;
}



void * http_host_instance (void * vmsg)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    HTTPListen  * hl = NULL;
    HTTPConnect * hc = NULL;
    HTTPHost    * host = NULL;
    ckstr_t       key;

    if (!msg) return NULL;

    key.p = msg->req_host;
    key.len = msg->req_hostlen;

    if (msg->msgtype) { //received request from client
        hl = (HTTPListen *)msg->hl;
        if (!hl) return NULL;

        EnterCriticalSection(&hl->hlCS);
        host = ht_get(hl->host_table, &key);
        if (!host) {
            host = hl->defaulthost;
        }
        LeaveCriticalSection(&hl->hlCS);

    } else {
        hc = (HTTPConnect *)msg->hc;
        if (!hc) return NULL;

        host = http_connect_host_find(hc, msg->req_host, msg->req_hostlen, msg->req_port);
        if (host && host->proxy) {
            msg->proxy = host->proxyhost;
            msg->proxyport = host->proxyport;
            msg->dstport = host->proxyport;
        }
    }

    return host;
}

void * http_loc_instance (void * vmsg)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    HTTPListen  * hl = NULL;
    HTTPConnect * hc = NULL;
    HTTPHost    * host = NULL;
    HTTPLoc     * ploc = NULL;
    ckstr_t       key;
    char          buf[4096];
    int           ret = 0;
    int           i, j, num;
#ifdef UNIX
    regmatch_t    pmat[16];
#endif
#if defined(_WIN32) || defined(_WIN64)
    int           ovec[36];
#endif

    if (!msg) return NULL;

    /* Location instance times must be not greater than 16 */
    if (++msg->locinst_times >= 16)
        return NULL;

    if (msg->msgtype) { //receiving request from client
        hl = (HTTPListen *)msg->hl;
        if (!hl) return NULL;

        key.p = msg->req_host;
        key.len = msg->req_hostlen;

        EnterCriticalSection(&hl->hlCS);
        host = ht_get(hl->host_table, &key);
        if (!host) {
            host = hl->defaulthost;
        }
        LeaveCriticalSection(&hl->hlCS);

    } else {
        hc = (HTTPConnect *)msg->hc;
        if (!hc) return NULL;

        host = http_connect_host_find(hc, msg->req_host, msg->req_hostlen, msg->req_port);
        if (host && host->proxy) {
            msg->proxy = host->proxyhost;
            msg->proxyport = host->proxyport;
            msg->dstport = host->proxyport;
        }
    }

    if (!host) return NULL;

    msg->phost = host;

    /* for CONNECT method, req_path is NULL */
    if (!msg->docuri->path || msg->docuri->pathlen <= 0)
        return NULL;

    str_secpy(buf, sizeof(buf)-1, msg->docuri->path, msg->docuri->pathlen);

    /* exact matching check if request path is completely equal to location path */
    ploc = ht_get(host->exact_loc_table, buf);
    if (ploc && msg->ploc != ploc) {
        msg->ploc = ploc;

        msg->matchnum = 1;
        msg->matchstr[0].p = msg->docuri->path;
        msg->matchstr[0].len = msg->docuri->pathlen;

        goto retloc;
    }

    /* regular expression matching check if request path is matched by regex */
    num = arr_num(host->regex_list);
    for (i = 0; i < num; i++) {
#ifdef UNIX
        ret = regexec(arr_value(host->regex_list, i), buf, 16, pmat, 0);
        if (ret == 0) {
#endif
#if defined(_WIN32) || defined(_WIN64)
        ret = pcre_exec(arr_value(host->regex_list, i), NULL, buf, strlen(buf), 0, 0, ovec, 36);
        if (ret > 0) {
#endif
            if ((ploc = arr_value(host->regex_loc_list, i)) == msg->ploc) continue;

            msg->ploc = ploc;

            msg->matchnum = 0;
#ifdef UNIX
            for (j = 0; j < 16; j++) {
                if (pmat[j].rm_so >= 0) {
                    msg->matchstr[msg->matchnum].p = msg->docuri->path + pmat[j].rm_so;
                    msg->matchstr[msg->matchnum].len = pmat[j].rm_eo - pmat[j].rm_so;
                    msg->matchnum++;
                    continue;
                }
                break;
            }
#endif
#if defined(_WIN32) || defined(_WIN64)
            for (j = 0; j < ret; j++) {
                msg->matchstr[msg->matchnum].p = msg->docuri->path + ovec[2 * j];
                msg->matchstr[msg->matchnum].len = ovec[2 * j + 1] - ovec[2 * j];
                msg->matchnum++;
            }
#endif

            goto retloc;
        }
    }

    /* prefix matching check if request path has the same prefix with location path */
    ret = actrie_get(host->prefix_actrie, msg->docuri->path, msg->docuri->pathlen, (void **)&ploc);
    if (ret > 0 && ploc && msg->ploc != ploc) {
        msg->ploc = ploc;

        msg->matchnum = 1;
        msg->matchstr[0].p = msg->docuri->path;
        msg->matchstr[0].len = ret;

        goto retloc;
    }

    if (msg->ploc) goto retloc;

    msg->ploc = host->defaultloc;
    ploc = msg->ploc;

    msg->matchnum = 1;
    msg->matchstr[0].p = msg->docuri->path;  // matching '/'
    msg->matchstr[0].len = 1;

retloc:
    /* script is interpreted and executed here */
    http_script_exec(msg);

    return ploc;
}

int http_loc_passurl_get (void * vmsg, int servtype, char * url, int urllen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPLoc    * ploc = NULL;
    char       * passurl = NULL;
    int          len = 0;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pmatend = NULL;

    if (!msg) return -1;
    if (!url) return -2;

    url[0] = '\0';

    ploc = (HTTPLoc *)msg->ploc;
    if (!ploc) return -3;

    /* when location type is not proxy or fastcgi, just return */

    if ((ploc->type & servtype) == 0) {
        return -10;
    }

    if (ploc->passurl == NULL) {
        return -11;
    }

    if (passurl_get(msg, &passurl, &len) < 0 || !passurl || len <= 0)
        return -12;

    if (servtype == SERV_FASTCGI) {
        str_secpy(url, urllen, passurl, len);
        return strlen(url);
    }

    if (ploc->matchtype == MATCH_REGEX_CASE || ploc->matchtype == MATCH_REGEX_NOCASE) {
        /* when matching type is regex matching, subsitude
           $num with matching substring */

        http_var_copy(msg, passurl, len,
                      url, urllen, msg->matchstr, msg->matchnum, "passurl", 4);

    } else {
        /* when matching type is non-regex matching, remove the matching
           substring of req_path and append the rest of req_path to passurl */

        str_secpy(url, urllen, passurl, len);

        pbgn = msg->docuri->path;
        pend = msg->docuri->path + msg->docuri->pathlen;

        if (msg->matchnum > 0) {
            poct = msg->matchstr[0].p;
            pmatend = poct + msg->matchstr[0].len;

            if (poct > pbgn) 
                str_secat(url, urllen - str_len(url), pbgn, poct - pbgn);

            if (pmatend < pend) 
                str_secat(url, urllen - str_len(url), pmatend, pend - pmatend);

        } else {
            str_secat(url, urllen - str_len(url), pbgn, pend - pbgn);
        }
    }

    if (msg->req_query && msg->req_querylen > 0) {
        if (memchr(url, '?', str_len(url)) == NULL) {
            str_secat(url, urllen - str_len(url), "?", 1);
            str_secat(url, urllen - str_len(url), msg->req_query, msg->req_querylen);
        } else {
            /*str_secat(url, urllen - str_len(url), "&", 1);
            str_secat(url, urllen - str_len(url), msg->req_query, msg->req_querylen);*/
        }
    }

    return strlen(url);
}

char * http_root_path (void * vmsg)
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

int http_real_file (void * vmsg, char * path, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPLoc    * ploc = NULL;
    char       * root = NULL;
    int          i, slen = 0;
    int          retlen = 0;

    if (!msg) return -1;
    if (!path || len <= 0) return -2;

    root = http_root_path(msg);
    retlen = str_len(root);

    ploc = msg->ploc;
    if (ploc && (ploc->matchtype == MATCH_REGEX_CASE || ploc->matchtype == MATCH_REGEX_NOCASE)) {
        /* when matching type is regex matching, subsitude
           $num with matching substring */

        retlen = http_var_copy(msg, root, retlen, path, len, msg->matchstr, msg->matchnum, "root", 4);

    } else if (ploc && ploc->matchtype == MATCH_PREFIX) {
        /* if matching type is prefix matching, remove the matching
           substring of req_path and append the rest of req_path to path */

        str_secpy(path, len, root, retlen);

        if (msg->matchnum > 0 && msg->matchstr[0].p == msg->docuri->path && msg->matchstr[0].len > 0) {
            str_secat(path, len - str_len(path),
                      msg->docuri->path + msg->matchstr[0].len,
                      msg->docuri->pathlen - msg->matchstr[0].len);
        } else {
            str_secat(path, len - str_len(path), msg->docuri->path, msg->docuri->pathlen);
        }

    } else {
        str_secpy(path, len, root, retlen);

        if (msg->docuri->path && msg->docuri->pathlen > 0) {
            slen = strlen(path);
            str_secpy(path + slen, len - slen, msg->docuri->path, msg->docuri->pathlen);
            retlen += msg->docuri->pathlen;

        } else {
            slen = strlen(path);
            str_secpy(path + slen, len - slen, "/", 1);
            retlen += 1;
        }
    }

    if (file_is_dir(path) && ploc) {
        slen = strlen(path);
        for (i = 0; i < (int)ploc->indexnum; i++) {
            snprintf(path + slen, len - slen, "%s", ploc->index[i]);
            if (file_is_regular(path)) {
                return strlen(path);
            }
        }
        path[slen] = '\0';
    }

    return strlen(path);
}

int http_real_path (void * vmsg, char * path, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPLoc    * ploc = NULL;
    char       * root = NULL;
    int          slen = 0;
    int          retlen = 0;

    if (!msg) return -1;
    if (!path || len <= 0) return -2;

    root = http_root_path(msg);
    retlen = str_len(root);

    ploc = msg->ploc;
    if (ploc && (ploc->matchtype == MATCH_REGEX_CASE || ploc->matchtype == MATCH_REGEX_NOCASE)) {
        /* when matching type is regex matching, subsitude
           $num with matching substring */

        retlen = http_var_copy(msg, root, retlen, path, len, msg->matchstr, msg->matchnum, "root", 4);

    } else if (ploc && ploc->matchtype == MATCH_PREFIX) {
        /* if matching type is prefix matching, remove the matching
           substring of req_path and append the rest of req_path to path */

        str_secpy(path, len, root, retlen);
        if (msg->matchnum > 0 && msg->matchstr[0].p == msg->docuri->path && msg->matchstr[0].len > 0) {
            str_secat(path, len - str_len(path),
                      msg->docuri->path + msg->matchstr[0].len,
                      msg->docuri->pathlen - msg->matchstr[0].len);
        } else {
            str_secat(path, len - str_len(path), msg->docuri->path, msg->docuri->pathlen);
        }

    } else {
        str_secpy(path, len, root, retlen);

        slen = strlen(path);
        str_secpy(path + slen, len - slen, msg->docuri->dir, msg->docuri->dirlen);
        retlen += msg->docuri->dirlen;
    }

    return strlen(path);
}


void * http_prefix_loc (void * vhl, char * hostn, int hostlen, char * matstr, int len,
                        char * root, void * cbfunc, void * cbobj, void * tplfile)
{
    HTTPListen * hl = (HTTPListen *)vhl;
    HTTPHost   * host = NULL;
    HTTPLoc    * ploc = NULL;
    char       * ptmp = NULL;
    int          i, num;

    if (!hl) return NULL;
    if (!matstr) return NULL;
    if (len < 0) len = strlen(matstr);
    if (len <= 0) return NULL;

    host = http_listen_host_create(hl, hostn, hostlen, NULL, NULL, NULL, NULL);
    if (!host) return NULL;

    EnterCriticalSection(&host->hostCS);

    num = arr_num(host->prefix_loc_list);
    for (i = 0; i < num; i++) {
        ploc = arr_value(host->prefix_loc_list, i);
        if (!ploc) continue;

        if (ploc->path && str_len(ploc->path) == len &&
            str_ncmp(ploc->path, matstr, len) == 0)
        {
            break;
        }
    }

    if (!ploc || i >= num) {
        ploc = http_loc_alloc(matstr, len, 1, MATCH_PREFIX, SERV_CALLBACK, root);
        if (!ploc) {
            LeaveCriticalSection(&host->hostCS);
            return NULL;
        }

        ploc->indexnum = 2;
        ploc->index[0] = "index.html";
        ploc->index[1] = "index.htm";

        arr_push(host->prefix_loc_list, ploc);
        actrie_add(host->prefix_actrie, ploc->path, -1, ploc);

    } else {
        ploc->matchtype = MATCH_PREFIX;
        ploc->type |= SERV_CALLBACK;

        if (root && strlen(root) > 0 && (ptmp = realpath(root, NULL))) {
            str_secpy(ploc->root, sizeof(ploc->root)-1, ptmp, strlen(ptmp));
            free(ptmp);

            if (ploc->root[strlen(ploc->root) - 1] == '/')
                ploc->root[strlen(ploc->root) - 1] = '\0';
        }
    }

    LeaveCriticalSection(&host->hostCS);

    ploc->cbfunc = cbfunc;
    ploc->cbobj = cbobj;
    ploc->tplfile = tplfile;

    return ploc;
}


void * http_exact_loc (void * vhl, char * hostn, int hostlen, char * matstr, int len,
                       char * root, void * cbfunc, void * cbobj, void * tplfile)
{
    HTTPListen * hl = (HTTPListen *)vhl;
    HTTPHost   * host = NULL;
    HTTPLoc    * ploc = NULL;
    char       * ptmp = NULL;
    char         buf[1024];

    if (!hl) return NULL;
    if (!matstr) return NULL;
    if (len < 0) len = strlen(matstr);
    if (len <= 0) return NULL;

    host = http_listen_host_create(hl, hostn, hostlen, NULL, NULL, NULL, NULL);
    if (!host) return NULL;

    str_secpy(buf, sizeof(buf)-1, matstr, len);

    EnterCriticalSection(&host->hostCS);

    ploc = ht_get(host->exact_loc_table, buf);

    if (!ploc) {
        ploc = http_loc_alloc(matstr, len, 1, MATCH_EXACT, SERV_CALLBACK, root);
        if (!ploc) {
            LeaveCriticalSection(&host->hostCS);
            return NULL;
        }

        ht_set(host->exact_loc_table, ploc->path, ploc);

    } else {
        ploc->matchtype = MATCH_EXACT;
        ploc->type |= SERV_CALLBACK;

        if (root && strlen(root) > 0 && (ptmp = realpath(root, NULL))) {
            str_secpy(ploc->root, sizeof(ploc->root)-1, ptmp, strlen(ptmp));
            free(ptmp);
 
            if (ploc->root[strlen(ploc->root) - 1] == '/')
                ploc->root[strlen(ploc->root) - 1] = '\0';
        }
    }

    LeaveCriticalSection(&host->hostCS);

    ploc->cbfunc = cbfunc;
    ploc->cbobj = cbobj;
    ploc->tplfile = tplfile;

    return ploc;
}


void * http_regex_loc (void * vhl, char * hostn, int hostlen, char * matstr, int len, int ignorecase,
                       char * root, void * cbfunc, void * cbobj, void * tplfile)
{
    HTTPListen * hl = (HTTPListen *)vhl;
    HTTPHost   * host = NULL;
    HTTPLoc    * ploc = NULL;
#ifdef UNIX
    regex_t    * preg = NULL;
#endif
#if defined(_WIN32) || defined(_WIN64)
    pcre       * preg = NULL;
    char       * errstr = NULL;
    int          erroff = 0;
#endif
    char       * ptmp = NULL;
    int          i, num;

    if (!hl) return NULL;
    if (!matstr) return NULL;
    if (len < 0) len = strlen(matstr);
    if (len <= 0) return NULL;

    host = http_listen_host_create(hl, hostn, hostlen, NULL, NULL, NULL, NULL);
    if (!host) return NULL;

    EnterCriticalSection(&host->hostCS);

    num = arr_num(host->regex_loc_list);
    for (i = 0; i < num; i++) {
        ploc = arr_value(host->regex_loc_list, i);
        if (!ploc) continue;

        if (ploc->path && str_len(ploc->path) == len &&
            str_ncmp(ploc->path, matstr, len) == 0)
        {
            break;
        }
    }

    if (!ploc || i >= num) {
        ploc = http_loc_alloc(matstr, len, 1, 
                              ignorecase ? MATCH_REGEX_NOCASE : MATCH_REGEX_CASE,
                              SERV_CALLBACK, root);
        if (!ploc) {
            LeaveCriticalSection(&host->hostCS);
            return NULL;
        }

        arr_push(host->regex_loc_list, ploc);

#ifdef UNIX
        preg = kzalloc(sizeof(regex_t));
        if (ploc->matchtype == MATCH_REGEX_CASE) { //case censitive
            regcomp(preg, ploc->path, REG_EXTENDED);

        } else { //ignoring case
            regcomp(preg, ploc->path, REG_EXTENDED | REG_ICASE);
        }
#endif
#if defined(_WIN32) || defined(_WIN64)
        if (ploc->matchtype == MATCH_REGEX_CASE) { //case censitive
            preg = pcre_compile(ploc->path, 0, &errstr, &erroff, NULL);

        } else { //ignoring case
            preg = pcre_compile(ploc->path, PCRE_CASELESS, &errstr, &erroff, NULL);
        }
#endif

        arr_push(host->regex_list, preg);

    } else {
        ploc->matchtype = MATCH_PREFIX;
        ploc->type |= SERV_CALLBACK;

        if (root && strlen(root) > 0 && (ptmp = realpath(root, NULL))) {
            str_secpy(ploc->root, sizeof(ploc->root)-1, ptmp, strlen(ptmp));
            free(ptmp);
 
            if (ploc->root[strlen(ploc->root) - 1] == '/')
                ploc->root[strlen(ploc->root) - 1] = '\0';
        }
    }

    LeaveCriticalSection(&host->hostCS);

    ploc->cbfunc = cbfunc;
    ploc->cbobj = cbobj;
    ploc->tplfile = tplfile;

    return ploc;
}

int http_loc_cache_get (void * vmsg, uint8 * cached, char ** cafn, int * cafnlen, char ** root, int * rootlen)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    HTTPListen  * hl = NULL;
    HTTPConnect * hc = NULL;
    HTTPHost    * phost = NULL;
    HTTPLoc     * ploc = NULL;

    if (!msg) return -1;

    ploc = msg->ploc;
    if (ploc) {
        if (cached) *cached = ploc->cache;
        if (cafn) *cafn = ploc->cachefile;
        if (cafnlen) *cafnlen = ploc->cachefile ? strlen(ploc->cachefile) : 0;
        if (root) *root = ploc->root;
        if (rootlen) *rootlen = strlen(ploc->root);

        return 0;
    }

    phost = msg->phost;
    if (phost) {
        if (cached) *cached = phost->cache;
        if (cafn) *cafn = phost->cachefile;
        if (cafnlen) *cafnlen = phost->cachefile ? strlen(phost->cachefile) : 0;
        if (root) *root = phost->root;
        if (rootlen) *rootlen = strlen(phost->root);

        return 0;
    }

    if (msg->msgtype) { //receiving request from client
        hl = (HTTPListen *)msg->hl;
        if (!hl) return -10;

        if (cached) *cached = hl->cache;
        if (cafn) *cafn = hl->cachefile;
        if (cafnlen) *cafnlen = hl->cachefile ? strlen(hl->cachefile) : 0;
        if (root) *root = hl->root;
        if (rootlen) *rootlen = strlen(hl->root);

        return 0;
    } else {
        hc = (HTTPConnect *)msg->hc;
        if (!hc) return -20;

        if (cached) *cached = hc->cache;
        if (cafn) *cafn = hc->cachefile;
        if (cafnlen) *cafnlen = hc->cachefile ? strlen(hc->cachefile) : 0;
        if (root) *root = hc->root;
        if (rootlen) *rootlen = strlen(hc->root);

        return 0;
    }

    return -100;
}

