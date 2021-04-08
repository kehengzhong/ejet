/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_header.h"
#include "http_cookie.h"

void * http_cookie_alloc ()
{
    cookie_t * ckie = NULL;

    ckie = kzalloc(sizeof(*ckie));
    if (!ckie) return NULL;

    ckie->createtime = time(0);

    return ckie;
}

void http_cookie_free  (void * vckie)
{
    cookie_t * ckie = (cookie_t *)vckie;

    if (!ckie) return;

    if (ckie->name) {
        kfree(ckie->name);
        ckie->name = NULL;
    }

    if (ckie->value) {
        kfree(ckie->value);
        ckie->name = NULL;
    }

    if (ckie->path) {
        kfree(ckie->path);
        ckie->path = NULL;
    }

    if (ckie->domain) {
        kfree(ckie->domain);
        ckie->domain = NULL;
    }

    kfree(ckie);
}

void * cookie_path_alloc ()
{
    cookie_path_t * ckpath = NULL;

    ckpath = kzalloc(sizeof(*ckpath));
    if (!ckpath) return NULL;

    ckpath->cookie_list = arr_new(4);

    return ckpath;
}

void cookie_path_free  (void * vpath)
{
    cookie_path_t * ckpath = (cookie_path_t *)vpath;

    if (!ckpath) return;

    if (ckpath->cookie_list) {
        arr_free(ckpath->cookie_list);
        ckpath->cookie_list = NULL;
    }

    kfree(ckpath);
}


void * cookie_domain_alloc () 
{
    cookie_domain_t * ckdomain = NULL;
 
    ckdomain = kzalloc(sizeof(*ckdomain));
    if (!ckdomain) return NULL;
 
    ckdomain->cookie_path_trie = actrie_init(128, NULL, 0);

    ckdomain->cookie_path_list = arr_new(4);
 
    return ckdomain;
}
 
void cookie_domain_free  (void * vdomain) 
{
    cookie_domain_t * ckdomain = (cookie_domain_t *)vdomain;
 
    if (!ckdomain) return;
 
    if (ckdomain->cookie_path_trie) {
        actrie_free(ckdomain->cookie_path_trie);
        ckdomain->cookie_path_trie = NULL;
    }

    if (ckdomain->cookie_path_list) {
        arr_pop_free(ckdomain->cookie_path_list, cookie_path_free);
        ckdomain->cookie_path_list = NULL;
    }
 
    kfree(ckdomain);
}

int cookie_domain_cmp_name (void * a, void * b)
{
    cookie_domain_t * ckdomain = (cookie_domain_t *)a;
    ckstr_t         * str = (ckstr_t *)b;
    int               len = 0;
    int               ret = 0;

    if (!ckdomain) return -1;
    if (!str || str->len <= 0) return 1;

    ret = strncasecmp(ckdomain->domain, str->p, str->len);
    if (ret == 0) {
        if ((len = strlen(ckdomain->domain)) == str->len)
            return 0;
        else if (len > str->len)
            return 1;
        else
            return -1;
    }

    return ret;
}

ulong cookie_domain_hash (void * vkey)
{
    ckstr_t * key = (ckstr_t *)vkey;

    if (!key) return 0;

    return string_hash(key->p, key->len, 0);
}

void * cookie_domain_path_get (void * vdom, char * path, int pathlen)
{
    cookie_domain_t * ckdomain = (cookie_domain_t *)vdom;
    cookie_path_t   * ckpath = NULL;
    int               i, num;

    if (!ckdomain) return NULL;

    if (!path) return NULL;
    if (pathlen < 0) pathlen = strlen(path);
    if (pathlen <= 0) return NULL;

    num = arr_num(ckdomain->cookie_path_list);
    for (i = 0; i < num; i++) {
        ckpath = arr_value(ckdomain->cookie_path_list, i);
        if (!ckpath) continue;

        if (strncasecmp(ckpath->path, path, pathlen) == 0 && strlen(ckpath->path) == pathlen)
            return ckpath;
    }

    return NULL;
}



void * cookie_mgmt_alloc (void * vhttpmgmt, char * ckiefile)
{
    CookieMgmt * mgmt = NULL;

    mgmt = kzalloc(sizeof(*mgmt));
    if (!mgmt) return NULL;

    mgmt->httpmgmt = vhttpmgmt;

    InitializeCriticalSection(&mgmt->cookieCS);

    mgmt->domain_trie = actrie_init(128, NULL, 1);
    mgmt->domain_table = ht_new(128, cookie_domain_cmp_name);
    ht_set_hash_func(mgmt->domain_table, cookie_domain_hash);

    mgmt->cookie_list = arr_new(4);

    mgmt->cookie_file = ckiefile;
    cookie_mgmt_read(mgmt, ckiefile);

    cookie_mgmt_scan(mgmt);

    tolog(1, "eJet - Cookie storage %s init\n", ckiefile);
    return mgmt;
}

void cookie_mgmt_free (void * vmgmt)
{
    CookieMgmt * mgmt = (CookieMgmt *)vmgmt;

    if (!mgmt) return;

    DeleteCriticalSection(&mgmt->cookieCS);

    if (mgmt->domain_table) {
        ht_free_all(mgmt->domain_table, cookie_domain_free);
        mgmt->domain_table = NULL;
    }

    if (mgmt->domain_trie) {
        actrie_free(mgmt->domain_trie);
        mgmt->domain_trie = NULL;
    }

    if (mgmt->cookie_list) {
        arr_pop_free(mgmt->cookie_list, http_cookie_free);
        mgmt->cookie_list = NULL;
    }

    if (mgmt->scan_timer) {
        iotimer_stop(mgmt->scan_timer);
        mgmt->scan_timer = NULL;
    }

    kfree(mgmt);
    tolog(1, "eJet - Cookie resource freed.\n");
}
 
void * cookie_mgmt_domain_get (void * vmgmt, char * domain, int domainlen)
{
    CookieMgmt      * mgmt = (CookieMgmt *)vmgmt;
    ckstr_t           str = ckstr_init(domain, domainlen);
    cookie_domain_t * domobj = NULL;

    if (!mgmt) return NULL;

    if (!domain) return NULL;
    if (domainlen < 0) domainlen = strlen(domain);
    if (domainlen <= 0) return NULL;
 
    domobj = ht_get(mgmt->domain_table, &str);

    return domobj;
}

int cookie_mgmt_domain_set (void * vmgmt, char * domain, int domainlen, void * domobj)
{
    CookieMgmt      * mgmt = (CookieMgmt *)vmgmt;
    ckstr_t           str = ckstr_init(domain, domainlen);
 
    if (!mgmt) return -1;

    if (!domain) return -2;
    if (domainlen < 0) domainlen = strlen(domain);
    if (domainlen <= 0) return -3;
 
    if (!domobj) return -4;

    ht_set(mgmt->domain_table, &str, domobj);

    return 0;
}


int cookie_mgmt_read  (void * vmgmt, char * cookiefile)
{
    CookieMgmt * mgmt = (CookieMgmt *)vmgmt;
    FILE       * fp = NULL;
    char         buf[4096];
    char       * p = NULL;
    int          len = 0;

    if (!mgmt) return -1;

    if (!cookiefile || !file_exist(cookiefile))
        return -2;
 
    fp = fopen(cookiefile, "r+");
    if (!fp) return -3;

    mgmt->cookie_file = cookiefile;

    buf[0] = '\0';
    for ( ; !feof(fp); ) {
        fgets(buf, sizeof(buf)-1, fp);
        p = str_trim(buf);
        len = strlen(p);

        if (len <= 0 || *p == '#')
            continue;

        cookie_mgmt_parse(mgmt, p, len, "", 0);
    }

    if (fp) fclose(fp);

    return 0;
}

int cookie_mgmt_write (void * vmgmt, char * cookiefile)
{
    CookieMgmt      * mgmt = (CookieMgmt *)vmgmt;
    cookie_domain_t * ckdomain = NULL;
    cookie_path_t   * ckpath = NULL;
    cookie_t        * ckie = NULL;
    FILE            * fp = NULL;
    frame_p           frm = NULL;
    char              buf[64];
    int               i, num;
    int               j, pathnum;
    int               k, cknum;

    if (!mgmt) return -1;

    if (!cookiefile) cookiefile = mgmt->cookie_file;

    fp = fopen(cookiefile, "w");
    if (!fp) return -3;

    frm = frame_new(4096);

    EnterCriticalSection(&mgmt->cookieCS);

    num = ht_num(mgmt->domain_table);
    for (i = 0; i < num; i++) {
        ckdomain = ht_value(mgmt->domain_table, i);
        if (!ckdomain) continue;

        pathnum = arr_num(ckdomain->cookie_path_list);
        for (j = 0; j < pathnum; j++) {
            ckpath = arr_value(ckdomain->cookie_path_list, j);
            if (!ckpath) continue;

            cknum = arr_num(ckpath->cookie_list);
            for (k = 0; k < cknum; k++) {
                ckie = arr_value(ckpath->cookie_list, k);
                if (!ckie || !ckie->name || ckie->namelen <= 0) continue;

                if (!ckie->domain || ckie->domainlen <= 0) continue;

                frame_empty(frm);
                frame_appendf(frm, "%s=%s;", ckie->name, ckie->value ? ckie->value : "");

                if (ckie->expire > 0) {
                    str_time2gmt(&ckie->expire, buf, sizeof(buf)-1, 0);
                    frame_appendf(frm, " Expires=%s;", buf);
                }

                if (ckie->maxage > 0) {
                    frame_appendf(frm, " Max-Age=%d;", ckie->maxage);
                }

                if (ckie->path && ckie->pathlen > 0)
                    frame_appendf(frm, " Path=%s;", ckie->path);
                else
                    frame_appendf(frm, " Path=/;");

                frame_appendf(frm, " Domain=%s;", ckie->domain);

                if (ckie->httponly)
                    frame_appendf(frm, " HTTPOnly;");

                if (ckie->secure)
                    frame_appendf(frm, " Secure;");

                if (ckie->samesite == 1 || ckie->samesite == 2)
                    frame_appendf(frm, " SameSite=%s;", ckie->samesite == 1 ? "Strict" : "Lax");

                frame_appendf(frm, " createtime=%lu", ckie->createtime);

                fprintf(fp, "%s\n", frameS(frm));
            }
        }
    }

    LeaveCriticalSection(&mgmt->cookieCS);

    frame_free(frm);
    fclose(fp);

    return 0;
}

 
int cookie_mgmt_scan (void * vmgmt)
{
    CookieMgmt    * mgmt = (CookieMgmt *)vmgmt;
    HTTPMgmt      * httpmgmt = NULL;
    cookie_path_t * ckpath = NULL;
    cookie_t      * ckie = NULL;
    int             rmnum = 0;
    int             i, num;
    time_t          curt = 0;

    if (!mgmt) return -1;

    httpmgmt = (HTTPMgmt *)mgmt->httpmgmt;
    if (!httpmgmt) return -2;

    curt = time(0);

    EnterCriticalSection(&mgmt->cookieCS);

    num = arr_num(mgmt->cookie_list);
    for (i = 0; i < num; i++) {
        ckie = arr_value(mgmt->cookie_list, i);
        if (!ckie) continue;

        if ((ckie->expire > 0 && ckie->expire < curt) || 
            (ckie->maxage > 0 && ckie->createtime + ckie->maxage < curt)
           ) {
            arr_delete(mgmt->cookie_list, i); i--; num--;

            ckpath = ckie->ckpath;
            if (ckpath)
                arr_delete_ptr(ckpath->cookie_list, ckie);

            http_cookie_free(ckie);
            rmnum++;
        }
    }

    LeaveCriticalSection(&mgmt->cookieCS);

    if (rmnum > 0) {
        cookie_mgmt_write(mgmt, mgmt->cookie_file);
    }

    if (arr_num(mgmt->cookie_list) > 0)
        mgmt->scan_timer = iotimer_start(httpmgmt->pcore,
                                     10*60*1000,
                                     t_http_cookie_scan,
                                     NULL,
                                     cookie_callback, mgmt);

    return rmnum;
}
 
int cookie_mgmt_add (void * vmgmt, void * vckie)
{
    CookieMgmt      * mgmt = (CookieMgmt *)vmgmt;
    HTTPMgmt        * httpmgmt = NULL;
    cookie_t        * ckie = (cookie_t *)vckie;
    cookie_domain_t * ckdomain = NULL;
    cookie_path_t   * ckpath = NULL;
    cookie_t        * iter = NULL;
    int               i, num;

    if (!mgmt) return -1;
    if (!ckie) return -2;

    httpmgmt = (HTTPMgmt *)mgmt->httpmgmt;
    if (!httpmgmt) return -3;

    EnterCriticalSection(&mgmt->cookieCS);

    /* get the domain object, if not existing, create it */
    ckdomain = cookie_mgmt_domain_get(mgmt, ckie->domain, ckie->domainlen);
    if (!ckdomain) {
        ckdomain = cookie_domain_alloc();
        if (!ckdomain) {
            LeaveCriticalSection(&mgmt->cookieCS);

            return -100;
        }

        str_secpy(ckdomain->domain, sizeof(ckdomain->domain)-1, ckie->domain, ckie->domainlen);

        actrie_add(mgmt->domain_trie, ckie->domain, ckie->domainlen, ckdomain);
        cookie_mgmt_domain_set(mgmt, ckie->domain, ckie->domainlen, ckdomain);
    }

    /* get the path object of the domain, if not existing, create it */
    ckpath = cookie_domain_path_get(ckdomain, ckie->path, ckie->pathlen);
    if (!ckpath) {
        ckpath = cookie_path_alloc();
        if (!ckdomain) {
           LeaveCriticalSection(&mgmt->cookieCS);

            return -200;
        }

        str_secpy(ckpath->path, sizeof(ckpath->path)-1, ckie->path, ckie->pathlen);

        actrie_add(ckdomain->cookie_path_trie, ckie->path, ckie->pathlen, ckpath);
        arr_push(ckdomain->cookie_path_list, ckpath);
    }

    /* iterate the cookie list to find an existing one */
    num = arr_num(ckpath->cookie_list);
    for (i = 0; i < num; i++) {
        iter = arr_value(ckpath->cookie_list, i);
        if (!iter) continue;

        if (iter->namelen != ckie->namelen) continue;

        if (strncasecmp(iter->name, ckie->name, iter->namelen) == 0) {
            if (iter->valuelen != ckie->valuelen ||
                strncasecmp(iter->value, ckie->value, iter->valuelen) != 0) {
                if (iter->value) kfree(iter->value);
                iter->value = str_dup(ckie->value, ckie->valuelen);
                iter->valuelen = ckie->valuelen;
            }

            iter->expire = ckie->expire;
            iter->maxage = ckie->maxage;
            iter->httponly = ckie->httponly;
            iter->secure = ckie->secure;
            iter->samesite = ckie->samesite;

            iter->createtime = ckie->createtime;

            iter->ckpath = ckpath;

            LeaveCriticalSection(&mgmt->cookieCS);

            return 0;
        }
    }

    /* not found an existing cookie object in ckpath object */
    arr_push(ckpath->cookie_list, ckie);
    ckie->ckpath = ckpath;

    arr_push(mgmt->cookie_list, ckie);

    LeaveCriticalSection(&mgmt->cookieCS);

    if (mgmt->scan_timer == NULL)
        mgmt->scan_timer = iotimer_start(httpmgmt->pcore,
                                     10*60*1000,
                                     t_http_cookie_scan,
                                     NULL,
                                     cookie_callback, mgmt);

    return 1;
}

void * cookie_mgmt_get (void * vmgmt, char * domain, int domainlen,
                        char * path, int pathlen, char * ckname, int cklen)
{
    CookieMgmt      * mgmt = (CookieMgmt *)vmgmt;
    cookie_domain_t * ckdomain = NULL;
    cookie_path_t   * ckpath = NULL;
    cookie_t        * iter = NULL;
    int               i, num;
    int               ret = 0;

    if (!mgmt) return NULL;

    if (!domain) return NULL;
    if (domainlen < 0) domainlen = strlen(domain);
    if (domainlen <= 0) return NULL;

    if (!path) return NULL;
    if (pathlen < 0) pathlen = strlen(path);
    if (pathlen <= 0) return NULL;

    if (!ckname) return NULL;
    if (cklen < 0) cklen = strlen(ckname);
    if (cklen <= 0) return NULL;

    EnterCriticalSection(&mgmt->cookieCS);

    ret = actrie_get(mgmt->domain_trie, domain, domainlen, (void **)&ckdomain);
    if (ret <= 0 || !ckdomain) {
        LeaveCriticalSection(&mgmt->cookieCS);

        return NULL;
    }

    ret = actrie_get(ckdomain->cookie_path_trie, path, pathlen, (void **)&ckpath);
    if (ret <= 0 || !ckpath) {
        LeaveCriticalSection(&mgmt->cookieCS);

        return NULL;
    }

    /* iterate the cookie list to find an existing one */
    num = arr_num(ckpath->cookie_list);
    for (i = 0; i < num; i++) {
        iter = arr_value(ckpath->cookie_list, i);
        if (!iter) continue;
 
        if (iter->namelen != cklen) continue;
 
        if (strncasecmp(iter->name, ckname, cklen) == 0) {
            LeaveCriticalSection(&mgmt->cookieCS);

            return iter;
        }
    }

    LeaveCriticalSection(&mgmt->cookieCS);

    return NULL;
}

int cookie_mgmt_mget (void * vmgmt, char * domain, int domainlen, char * path, int pathlen, arr_t ** cklist)
{
    CookieMgmt      * mgmt = (CookieMgmt *)vmgmt;
    cookie_domain_t * ckdomain = NULL;
    cookie_path_t   * ckpath = NULL;
    int               ret = 0;

    if (!mgmt) return -1;

    if (!domain) return -2;
    if (domainlen < 0) domainlen = strlen(domain);
    if (domainlen <= 0) return -3;

    if (!path) return -4;
    if (pathlen < 0) pathlen = strlen(path);
    if (pathlen <= 0) return -5;

    EnterCriticalSection(&mgmt->cookieCS);

    ret = actrie_get(mgmt->domain_trie, domain, domainlen, (void **)&ckdomain);
    if (ret <= 0 || !ckdomain) {
        LeaveCriticalSection(&mgmt->cookieCS);

        return -100;
    }

    ret = actrie_get(ckdomain->cookie_path_trie, path, pathlen, (void **)&ckpath);
    if (ret <= 0 || !ckpath) {
        LeaveCriticalSection(&mgmt->cookieCS);

        return -200;
    }

    if (cklist) *cklist = ckpath->cookie_list;
    ret = arr_num(ckpath->cookie_list);

    LeaveCriticalSection(&mgmt->cookieCS);

    return ret;
}

 
int cookie_mgmt_set  (void * vmgmt, char * ckname, int cknlen, char * ckvalue, int ckvlen,
                      char * domain, int domainlen, char * path, int pathlen, time_t expire,
                      int maxage, uint8 httponly, uint8 secure, uint8 samesite)
{
    CookieMgmt  * mgmt = (CookieMgmt *)vmgmt;
    cookie_t    * ckie = NULL;

    if (!mgmt) return -1;

    if (!ckname) return -2;
    if (cknlen < 0) cknlen = strlen(ckname);
    if (cknlen <= 0) return -3;

    if (!ckvalue) return -2;
    if (ckvlen < 0) ckvlen = strlen(ckvalue);
    if (ckvlen <= 0) return -3;

    if (!domain) return -2;
    if (domainlen < 0) domainlen = strlen(domain);
    if (domainlen <= 0) return -3;

    if (!path) return -2;
    if (pathlen < 0) pathlen = strlen(path);
    if (pathlen <= 0) return -3;

    ckie = http_cookie_alloc();
    if (!ckie) return -100;

    ckie->name = ckname;
    ckie->namelen = cknlen;

    ckie->value = ckvalue;
    ckie->valuelen = ckvlen;

    ckie->domain = domain;
    ckie->domainlen = domainlen;

    ckie->path = path;
    ckie->pathlen = pathlen;

    ckie->expire = expire;
    ckie->maxage = maxage;

    ckie->httponly = httponly;
    ckie->secure = secure;
    ckie->samesite = samesite;

    if (cookie_mgmt_add(mgmt, ckie) <= 0) 
        http_cookie_free(ckie);

    return 0;
}
 
int cookie_mgmt_parse (void * vmgmt, char * pbyte, int bytelen, char * defdom, int defdomlen)
{
    CookieMgmt * mgmt = (CookieMgmt *)vmgmt;
    cookie_t   * ckie = NULL;
    arr_t      * cklist = NULL;

    char       * domain = NULL;
    int          domainlen = 0;
    char       * path = NULL;
    int          pathlen = 0;
    time_t       expire = 0;
    int          maxage = 0;
    uint8        httponly = 0;
    uint8        secure = 0;
    uint8        samesite = 0;
    time_t       createtime = 0;

    char       * plist[32];
    int          plen[32];
    char       * key;
    int          keylen;
    char       * data;
    int          datalen;
    char       * p;
    char       * pend;
    int          i, num;
    char       * pkv[2];
    int          kvlen[2];
    int          ret;

    if (!mgmt) return -1;

    if (!pbyte) return -2;
    if (bytelen < 0) bytelen = strlen(pbyte);
    if (bytelen <= 0) return -3;

    num = string_tokenize(pbyte, bytelen, ";", 1, (void **)plist, plen, 32);
    if (num <= 0) return -100;

    cklist = arr_new(4);

    for (i = 0; i < num; i++) {
        pend = plist[i] + plen[i];
        p = skipOver(plist[i], plen[i], " \t\r\n;", 5);
        if (p >= pend) continue;

        ret = string_tokenize(p, pend-p, "=", 1, (void **)pkv, kvlen, 2);
        if (ret <= 0) continue;

        key = pkv[0]; pend = key + kvlen[0];
        p = rskipOver(pend-1, pend-key, " \t\r\n=;", 6);
        if (p < key) continue;
        keylen = p - key + 1;

        if (ret < 2) {
            data = NULL;
            datalen = 0;
        } else {
            data = pkv[1]; pend = data + kvlen[1];
            p = rskipOver(pend-1, pend-data, " \t\r\n;=", 6);
            if (p < data) datalen = 0;
            else datalen = p - data + 1;
        }

        if (keylen == 4 && strncasecmp(key, "path", 4) == 0) {
            path = data; pathlen = datalen;

        } else if (keylen == 6 && strncasecmp(key, "domain", 6) == 0) {
            pend = data + datalen;
            data = skipOver(data, pend-data, " .\t", 3);
            domain = data; domainlen = pend-data;

        } else if (keylen == 7 && strncasecmp(key, "expires", 7) == 0) {
            str_gmt2time(data, datalen, &expire);

        } else if (keylen == 7 && strncasecmp(key, "max-age", 7) == 0) {
            maxage = str_to_int(data, datalen, 10, NULL);

        } else if (keylen == 8 && strncasecmp(key, "samesite", 8) == 0) {
            if (datalen == 6 && strncasecmp(data, "Strict", 6) == 0)
                samesite = 1;
            else if (datalen == 3 && strncasecmp(data, "Lax", 3) == 0)
                samesite = 2;
            else
                samesite = 0;

        } else if (keylen == 6 && strncasecmp(key, "secure", 6) == 0) {
            if (data == NULL || datalen <= 0)
                secure = 1;

        } else if (keylen == 8 && strncasecmp(key, "httponly", 8) == 0) {
            if (data == NULL || datalen <= 0)
                httponly = 1;

        } else if (keylen == 10 && strncasecmp(key, "createtime", 10) == 0) {
            if (data && datalen > 0)
                createtime = strtoull(data, NULL, 10);

        } else {
            ckie = http_cookie_alloc();
            ckie->name = str_dup(key, keylen);
            ckie->namelen = keylen;
            ckie->value = str_dup(data, datalen);
            ckie->valuelen = datalen;

            arr_push(cklist, ckie);
        }
    }

    if (!domain || domainlen <= 0) {
        domain = defdom;
        domainlen = defdomlen;
    }

    num = arr_num(cklist);
    for (i = 0; i < num; i++) {
        ckie = arr_value(cklist, i);
        if (!ckie) continue;

        ckie->path = str_dup(path, pathlen);
        ckie->pathlen = pathlen;
        ckie->domain = str_dup(domain, domainlen);
        ckie->domainlen = domainlen;
        ckie->expire = expire;
        ckie->maxage = maxage;
        ckie->secure = secure;
        ckie->httponly = httponly;
        ckie->samesite = samesite;

        if (createtime > 0)
            ckie->createtime = createtime;

        if (cookie_mgmt_add(mgmt, ckie) <= 0) {
            tolog(1, "eJet - Update Cookie: %s=%s; path=%s; domain=%s; expire=%ld; maxage=%d%s%s%s\n",
                  ckie->name, ckie->value, ckie->path, ckie->domain, ckie->expire, ckie->maxage,
                  ckie->secure > 0 ? "; Secure" : "",
                  ckie->httponly > 0 ? "; HTTPOnly" : "",
                  ckie->samesite == 1 ? "; Strict" : (ckie->samesite == 2 ? "; Lax" : ""));

            http_cookie_free(ckie);

        } else {
            tolog(1, "eJet - New Cookie: %s=%s; path=%s; domain=%s; expire=%ld; maxage=%d%s%s%s\n",
                  ckie->name, ckie->value, ckie->path, ckie->domain, ckie->expire, ckie->maxage,
                  ckie->secure > 0 ? "; Secure" : "",
                  ckie->httponly > 0 ? "; HTTPOnly" : "",
                  ckie->samesite == 1 ? "; Strict" : (ckie->samesite == 2 ? "; Lax" : ""));
        }
    }

    arr_free(cklist);

    if (num > 0)
        cookie_mgmt_write(mgmt, mgmt->cookie_file);

    return 0;
}

int cookie_callback (void * vmgmt, void * vobj, int event, int fdtype)
{
    CookieMgmt  * mgmt = (CookieMgmt *)vmgmt;
    int           cmd;

    if (!mgmt) return -1;

    switch (event) {
    case IOE_TIMEOUT:
        cmd = iotimer_cmdid(vobj);
 
        if (cmd == t_http_cookie_scan) {
            mgmt->scan_timer = NULL;
            return cookie_mgmt_scan(mgmt);
        }
        break;
    }

    return -1;
}


int http_cookie_add (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * httpmgmt = NULL;
    CookieMgmt * ckiemgmt = NULL;
    cookie_t   * ckie = NULL;
    arr_t      * cklist = NULL;
    HeaderUnit * unit = NULL;
    frame_t    * frm = NULL;
    int          ret = 0;
    int          i, num;

    if (!msg) return -1;

    httpmgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!httpmgmt) return -2;

    ckiemgmt = (CookieMgmt *)httpmgmt->cookiemgmt;
    if (!ckiemgmt) return -3;

    ret = cookie_mgmt_mget(ckiemgmt, msg->req_host, msg->req_hostlen,
                           msg->req_path, msg->req_pathlen, &cklist);
    if (ret <= 0 || !cklist) return -100;

    frm = frame_new(4096);

    unit = http_header_get(msg, 0, "Cookie", -1);
    if (unit && unit->valuelen > 0) {
        frame_put_nfirst(frm, HUValue(unit), unit->valuelen);
    }

    num = arr_num(cklist);

    for (i = 0, ret = 0; i < num; i++) {
        ckie = arr_value(cklist, i);
        if (!ckie) continue;

        frame_appendf(frm, "%s%s=%s", frameL(frm) > 0 ? "; " : "", ckie->name, ckie->value);
        ret++;
    }

    if (ret > 0) {
        http_header_del(msg, 0, "Cookie", -1);
        http_header_append(msg, 0, "Cookie", -1, frameP(frm), frameL(frm));
    }

    frame_free(frm);

    return 0;
}

int http_set_cookie_parse (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * httpmgmt = NULL;
    CookieMgmt * ckiemgmt = NULL;
    HeaderUnit * unit = NULL;
    int          ret = 0;

    if (!msg) return -1;

    httpmgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!httpmgmt) return -2;

    ckiemgmt = (CookieMgmt *)httpmgmt->cookiemgmt;
    if (!ckiemgmt) return -3;

    unit = http_header_get(msg, 1, "Set-Cookie", -1);
    while (unit && unit->valuelen > 0) {
        ret = cookie_mgmt_parse(ckiemgmt, HUValue(unit), unit->valuelen, msg->req_host, msg->req_hostlen);
        unit = unit->next;
    }

    return ret;
}

