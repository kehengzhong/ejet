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

#ifndef _HTTP_COOKIE_H_
#define _HTTP_COOKIE_H_

#ifdef __cplusplus
extern "C" {
#endif

#define t_http_cookie_scan   2170

typedef struct http_cookie_ {
    uint8     alloctype;//0-default kalloc/kfree 1-os-specific malloc/free 2-kmempool alloc/free 3-kmemblk alloc/free
    void    * mpool;

    /* do not contain following characters:
        CTRLs Space \t ( ) < > @ , ; : \ " /  [ ] ? = { } */
    char    * name;
    int       namelen;

    /* do not contain following characters:
       CTRLs Space " , ; \ */
    char    * value;
    int       valuelen;

    char    * path;
    int       pathlen;

    char    * domain;
    int       domainlen;

    time_t    expire;
    int       maxage;

    uint8     httponly;
    uint8     secure;

    uint8     samesite;  //0-unknown  1-Strict  2-Lax

    time_t    createtime;
    void    * ckpath;

} HTTPCookie, cookie_t;

void * http_cookie_alloc (int alloctype, void * mpool);
void   http_cookie_free  (void * vckie);


typedef struct cookie_path_ {
    uint8     alloctype;//0-default kalloc/kfree 1-os-specific malloc/free 2-kmempool alloc/free 3-kmemblk alloc/free
    void    * mpool;

    char       path[128];
    arr_t    * cookie_list;

} cookie_path_t, CookiePath;

void * cookie_path_alloc (int alloctype, void * mpool);
void   cookie_path_free  (void * vpath);

typedef struct cookie_domain_ {

    uint8     alloctype;//0-default kalloc/kfree 1-os-specific malloc/free 2-kmempool alloc/free 3-kmemblk alloc/free
    void    * mpool;

    char         domain[128];
    actrie_t   * cookie_path_trie;
    arr_t      * cookie_path_list;

} cookie_domain_t, CookieDomain;

void * cookie_domain_alloc (int alloctype, void * mpool);
void   cookie_domain_free  (void * vdomain);

typedef struct http_cookie_mgmt {

    uint8     alloctype;//0-default kalloc/kfree 1-os-specific malloc/free 2-kmempool alloc/free 3-kmemblk alloc/free
    void    * mpool;

    /* reverse multi-pattern matching based on domain */
    CRITICAL_SECTION   cookieCS;
    actrie_t         * domain_trie;
    hashtab_t        * domain_table;

    /* all cookies list under different domains and paths */
    arr_t            * cookie_list;

    /* scan the cookie list to remove the expired cookies every 300 seconds */
    void             * scan_timer;

    char             * cookie_file;

    void             * httpmgmt;

} CookieMgmt, cookie_mgmt_t;

void * cookie_mgmt_alloc (void * vhttpmgmt, char * ckiefile);
void   cookie_mgmt_free (void * vmgmt);

int    cookie_mgmt_read  (void * vmgmt, char * cookiefile);
int    cookie_mgmt_write (void * vmgmt, char * cookiefile);

int    cookie_mgmt_scan (void * vmgmt);

int    cookie_mgmt_add (void * vmgmt, void * vckie);

void * cookie_mgmt_get (void * vmgmt, char * domain, int domainlen,
                         char * path, int pathlen, char * ckiename, int ckienlen);
int    cookie_mgmt_mget(void * vmgmt, char * domain, int domainlen, char * path, int pathlen, arr_t ** cklist);

int    cookie_mgmt_set (void * vmgmt, char * ckname, int cknlen, char * ckvalue, int ckvlen,
                        char * domain, int domainlen, char * path, int pathlen, time_t expire,
                        int maxage, uint8 httponly, uint8 secure, uint8 samesite);

int    cookie_mgmt_parse (void * vmgmt, char * setcookie, int len, char * defdom, int defdomlen, int needwrite);

int    cookie_callback (void * vmgmt, void * vobj, int event, int fdtype);


int http_cookie_add       (void * vmsg);
int http_set_cookie_parse (void * vmsg);


#ifdef __cplusplus
}
#endif

#endif


