/*
 * Copyright (c) 2003-2020 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include <dlfcn.h>
#include <regex.h>

#include "adifall.ext"
#include "epump.h"
#include "http_listen.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_ssl.h"
#include "http_pump.h"
#include "http_variable.h"
#include "http_script.h"


void * http_loc_alloc (char * path, int type, char * root)
{
    HTTPLoc * ploc = NULL;
    char    * ptmp = NULL;

    if (!path || strlen(path) <= 0)
        return NULL;

    if (type == SERV_SERVER || type == SERV_UPLOAD) { //file or upload
        /* check if the root path exists */
        if (!root) return NULL;
    }

    ploc = kzalloc(sizeof(*ploc));
    if (!ploc) return NULL;

    ploc->path = path;
    ploc->type = type;

    if (!root) root = ".";

    if (root && strlen(root) > 0 && (ptmp = realpath(root, NULL))) {
        str_secpy(ploc->root, sizeof(ploc->root)-1, ptmp, strlen(ptmp));
        free(ptmp);

        if (ploc->root[strlen(ploc->root) - 1] == '/')
            ploc->root[strlen(ploc->root) - 1] = '\0';

        /*if (!file_is_dir(ploc->root)) {
            file_dir_create(ploc->root, 0);
        }*/
    }

    ploc->script_list = arr_new(2);

    return ploc;
}

void http_loc_free (void * vloc)
{
    HTTPLoc * ploc = (HTTPLoc *)vloc;

    if (!ploc) return;

    arr_pop_kfree(ploc->script_list);

    kfree(ploc);
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
    regex_t    * preg = NULL;

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
                    else if (strcmp(value, "~") == 0)
                        matchtype = MATCH_REGEX_CASE;  //3, regex matching with case censitive
                    else if (strcmp(value, "~*") == 0)
                        matchtype = MATCH_REGEX_NOCASE;  //4, regex matching ignoring case
                } else {
                    matchtype = MATCH_PREFIX; //2, prefix matching
                }
            } else {
                matchtype = MATCH_PREFIX; //2, prefix matching
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

        ploc = http_loc_alloc(path, type, root);
        if (!ploc) goto nextloc;

        ploc->jsonobj = jloc;
        ploc->matchtype = matchtype;

        if (ploc->type == SERV_UPLOAD) {//upload
            if (host->uploadloc)
                http_loc_free(host->uploadloc);

            host->uploadloc = ploc;

        } else {
            switch (ploc->matchtype) {
            case MATCH_DEFAULT:  //default loc
                if (ploc->type == SERV_PROXY || ploc->type == SERV_FASTCGI) { //proxy or fastcgi
                    ploc->matchtype = MATCH_PREFIX;  //prefix matching
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
                arr_push(host->prefix_loc_list, ploc);
                actrie_add(host->prefix_actrie, ploc->path, -1, ploc);
                break;

            case MATCH_REGEX_CASE:  //regex matching with case censitive
            case MATCH_REGEX_NOCASE:  //regex matching ignoring case
                arr_push(host->regex_loc_list, ploc);

                preg = kzalloc(sizeof(regex_t));
                if (ploc->matchtype == MATCH_REGEX_CASE) { //case censitive
                    regcomp(preg, path, REG_EXTENDED);

                } else { //ignoring case
                    regcomp(preg, path, REG_EXTENDED | REG_ICASE);
                }

                arr_push(host->regex_list, preg);
                break;
            }
        }

        ret = json_mgetP(jloc, "index", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            ploc->indexnum = ret;
            ploc->index[0] = value;

            for (j = 1; j < ploc->indexnum && j < sizeof(ploc->index)/sizeof(ploc->index[0]); j++) {
                sprintf(key, "index[%d]", j);
                ret = json_mgetP(jloc, key, -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0) {
                    ploc->index[j] = value;
                }
            }
        }

        ret = json_mgetP(jloc, "passurl", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            ploc->passurl = value;
        }

        ret = json_mgetP(jloc, "cache", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0)
                ploc->cache = 1;
            else
                ploc->cache = 0;
        }

        ret = json_mgetP(jloc, "cache file", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            ploc->cachefile = value;
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

nextloc:
        sprintf(key, "location[%d]", i);
        ret = json_mget_obj(jhost, key, -1, &jloc);
        if (ret <= 0) break;
    }

    return 0;
}


void * http_host_alloc (char * hostname)
{
    HTTPHost * host = NULL;

    if (!hostname) return NULL;

    host = kzalloc(sizeof(*host));
    if (!host) return NULL;

    str_secpy(host->hostname, sizeof(host->hostname)-1, hostname, strlen(hostname));

    host->exact_loc_table = ht_new(64, http_loc_cmp_path);

    host->prefix_loc_list = arr_new(4);
    host->prefix_actrie = actrie_init(128, NULL, 0);

    host->regex_loc_list = arr_new(4);
    host->regex_list = arr_new(4);

    host->uploadloc = NULL;
    host->defaultloc = NULL;

    host->script_list = arr_new(2);

    return host;
}

void http_host_free (void * vhost)
{
    HTTPHost * host = (HTTPHost *)vhost;
    int        i, num;
    regex_t  * preg = NULL;

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
            regfree(preg);
            kfree(preg);
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

    arr_pop_kfree(host->script_list);

    kfree(host);
}

int http_host_cmp (void * vhost, void * vname)
{
    HTTPHost * host = (HTTPHost *)vhost;
    char     * hostname = (char *)vname;

    if (!host) return -1;
    if (!hostname) return 1;

    return strcasecmp(host->hostname, hostname);
}

int http_host_build (void * vhl, void * jhl)
{
    HTTPListen * hl = (HTTPListen *)vhl;
    HTTPHost   * host = NULL;

    uint8        defhost = 0;
    int          i, hostnum;
    int          ret = 0, subret;
    int          j, num = 0;
    int          code = 0;

    char         key[128];
    int          keylen = 0;
    char       * value = NULL;
    int          valuelen = 0;
 
    void       * jhost = NULL;
    char       * hname = NULL;

    void       * jerrpage = NULL;
 
    if (!hl) return -1;
    if (!jhl) return -2;
 
    sprintf(key, "host");
    ret = json_mget_obj(jhl, key, -1, &jhost);
    if (ret <= 0) {
        tolog(1, "eJet - HTTP Listen <%s:%d%s> has no <Host> configure option!\n",
              strlen(hl->localip) > 0 ? hl->localip : "*",
              hl->port, hl->ssl_link ? " SSL" : "");
        return -100;
    }

    for (hostnum = ret, i = 1; i <= hostnum && jhost != NULL; i++) {
        hname = NULL;
        defhost = 0;
 
        ret = json_mgetP(jhost, "host name", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            hname = value;
        } else {
            defhost = 1;
        }

        /* create HTTPHost instance */

        if (defhost || (hname && strlen(hname) == 1 && hname[0] == '*')) {
            if (hl->defaulthost)
                http_host_free(hl->defaulthost);

            host = hl->defaulthost = http_host_alloc("*");

        } else {
            host = ht_get(hl->host_table, hname); 
            if (!host) {
                host = http_host_alloc(hname);
                ht_set(hl->host_table, hname, host);
            }

            /* SNI mechanism in TLS spec enables the client can select one 
               from multiple cetificates coresponding to different host-names.
               Therefore, NULL host-name can not be bound SSL certificate, key. */

#ifdef HAVE_OPENSSL
            if (hl->ssl_link && host->sslctx == NULL) {
                ret = json_mgetP(jhost, "ssl certificate", -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0) {
                    host->cert = value;
                }
         
                ret = json_mgetP(jhost, "ssl private key", -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0) {
                    host->prikey = value;
                }
         
                ret = json_mgetP(jhost, "ssl ca certificate", -1, (void **)&value, &valuelen);
                if (ret > 0 && value && valuelen > 0) {
                    host->cacert = value;
                }

                if (host->cert && strlen(host->cert) > 0 && host->prikey && strlen(host->prikey) > 0)
                    host->sslctx = http_ssl_server_ctx_init(host->cert, host->prikey, host->cacert);
            }
#endif
        }

        host->jsonobj = jhost;

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

        ret = json_mgetP(jhost, "root", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            str_secpy(host->root, sizeof(host->root)-1, value, valuelen);
        } else {
            host->root[0] = '\0';
        }

        ret = json_mgetP(jhost, "gzip", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0)
                host->gzip = 1;
            else
                host->gzip = 0;
        }
 
        /* parse the 'error page' object */

        ret = json_mget_obj(jhost, "error page", -1, &jerrpage);
        if (ret > 0) {
            json_mgetP(jerrpage, "root", -1, (void **)&host->errpage.root, &valuelen);

            num = json_num(jerrpage);
            for (j = 0; j < num; j++) {
                ret = json_iter(jerrpage, j, (void **)&hname, &keylen,
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
        ret = json_mget_obj(jhl, key, -1, &jhost);
        if (ret <= 0) break;
    }

    return 0;
}


void * http_listen_alloc (char * localip, int port, int ssl, char * cblibfile)
{
    HTTPListen * hl = NULL;
    char       * err = NULL;
    char       * argv[16];
    int          i, plen[16];

    if (port == 0) return NULL;

    if (localip == NULL) localip = "";
    else if (strcmp(localip, "*") == 0) localip = "";

    hl = kzalloc(sizeof(*hl));
    if (!hl) return NULL;

    if (localip)
        strncpy(hl->localip, localip, sizeof(localip)-1);
    hl->port = port;
    hl->forwardproxy = 0;

    hl->ssl_link = ssl > 0 ? 1 : 0;
 
    if (cblibfile) {
        hl->cbargc = string_tokenize(cblibfile, -1, " \t\r\n\f\v", 6, (void **)argv, plen, 16);
        for (i = 0; i < hl->cbargc; i++) {
            hl->cbargv[i] = str_dup(argv[i], plen[i]);
        }

        hl->cblibfile = hl->cbargv[0];

        hl->cbhandle = dlopen(cblibfile, RTLD_LAZY);
        if (!hl->cbhandle) {
            tolog(1, "eJet - HTTP Listen <%s:%d%s> Loading DynLib <%s> error! %s\n",
                  strlen(hl->localip) > 0 ? hl->localip : "*",
                  hl->port, hl->ssl_link ? " SSL" : "",
                  cblibfile, dlerror());

        } else {
            dlerror();

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

            if (hl->cbinit) {
                hl->cbobj = (*hl->cbinit)(hl->httpmgmt, hl->cbargc, hl->cbargv);
            }

            tolog(1, "eJet - HTTP Listen <%s:%d%s> DynLib <%s> load successfully!\n",
                      strlen(hl->localip) > 0 ? hl->localip : "*",
                      hl->port, hl->ssl_link ? " SSL" : "", hl->cblibfile);
        }
    }

    hl->mlisten = NULL;

    hl->host_table = ht_only_new(64, http_host_cmp);
    hl->defaulthost = NULL;

    hl->reqdiag = NULL;
    hl->reqdiagobj = NULL;

    hl->script_list = arr_new(2);

    return hl;
}

void http_listen_free (void * vhl)
{
    HTTPListen * hl = (HTTPListen *)vhl;
    int          i;

    if (!hl) return;

    arr_pop_kfree(hl->script_list);

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

        dlclose(hl->cbhandle);
        hl->cbhandle = NULL;
    }

    kfree(hl);
}

void * http_listen_ssl_ctx_get (void * vhl, void * vcon)
{
    HTTPListen * hl = (HTTPListen *)vhl;

    if (!hl) return NULL;

    return hl->sslctx;
}

void * http_listen_get_host (void * vhl, char * servname)
{
    HTTPListen * hl = (HTTPListen *)vhl;

    if (!hl) return NULL;

    return ht_get(hl->host_table, servname);
}


int http_listen_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

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

    return 0;
}

void * http_listen_add (void * vmgmt, char * localip, int port, int ssl, char * libfile)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    int          i, num;

    if (!mgmt) return NULL;

    if (port == 0) return NULL;
 
    if (localip == NULL) localip = "";
    else if (strcmp(localip, "*") == 0) localip = "";
 
    num = arr_num(mgmt->listen_list);
    for (i = 0; i < num; i++) {
 
        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;
 
        if (hl->port == port && strcasecmp(hl->localip, localip) == 0)
            return hl;
    }
 
    hl = http_listen_alloc(localip, port, ssl, libfile);
    if (hl) {
        hl->httpmgmt = mgmt;
        arr_push(mgmt->listen_list, hl);
    }

    return hl;
}


int http_listen_start (void * vmgmt)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    void       * mlisten = NULL;
    HTTPListen * hl = NULL;
    int          i, num;

    if (!mgmt) return -1;

    num = arr_num(mgmt->listen_list);
    for (i = 0; i < num; i++) {

        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;

        if (hl->mlisten) continue;

        mlisten = eptcp_mlisten(mgmt->pcore, 
                             strlen(hl->localip) > 0 ? hl->localip : NULL,
                             hl->port, hl, (IOHandler *)http_pump, mgmt);
        if (!mlisten) {
            tolog(1, "eJet - HTTP Listen <%s:%d%s> failed.\n",
                   strlen(hl->localip) > 0 ? hl->localip : "*",
                   hl->port, hl->ssl_link ? " SSL" : "");
            continue;
        }

        hl->mlisten = mlisten;

        #if defined _DEBUG
        printf("HTTPListen: LocalIP=%s Port=%d %s being listened...\n",
              strlen(hl->localip) ? hl->localip : "*", hl->port, hl->ssl_link ? "SSL" : "");
        #endif

        tolog(1, "eJet - HTTP Listen <%s:%d%s> started.\n",
                   strlen(hl->localip) > 0 ? hl->localip : "*",
                   hl->port, hl->ssl_link ? " SSL" : "");
    }

    return 0;
}

void * http_listen_find (void * vmgmt, int port)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    int          i, num;

    if (!mgmt) return NULL;

    num = arr_num(mgmt->listen_list);

    for (i = 0; i < num; i++) {

        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;

        if (hl->port == port) {
            return hl;
        }
    }

    return NULL;
}


int http_listen_stop (void * vmgmt, int port)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    int          i, num;

    if (!mgmt) return -1;
    if (port == 0) return -2;

    num = arr_num(mgmt->listen_list);

    for (i = 0; i < num; i++) {

        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;

        if (!hl->mlisten) {
            arr_delete(mgmt->listen_list, i); i--; num--;
            http_listen_free(hl);
            continue;
        }

        if (hl->port == port && mlisten_port(hl->mlisten) == port) {
            arr_delete(mgmt->listen_list, i);
            http_listen_free(hl);
            return 0;
        }
    }

    return -1;
}

int http_listen_check_self (void * vmgmt, char * host, int hostlen, char * dstip, int dstport)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPListen * hl = NULL;
    int          i, j, num;
    int          port_listened = 0;
    char         buf[256];
 
    if (!mgmt) return -1;
 
    num = arr_num(mgmt->listen_list);
    for (i = 0; i < num; i++) {
        hl = (HTTPListen *)arr_value(mgmt->listen_list, i);
        if (!hl) continue;
 
        if (hl->port != dstport) continue;
 
        port_listened++;
 
        str_secpy(buf, sizeof(buf)-1, host, hostlen);
        if (ht_get(hl->host_table, buf) != NULL) {
            /* checked host is one of hosts under listened port */ 
            return 1;
        }
    }
 
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

        json_get_int(jhl, "port", -1, &port);

        ret = json_mgetP(jhl, "forward proxy", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0)
                forwardproxy = 1;
            else
                forwardproxy = 0;
        }

        ret = json_mgetP(jhl, "ssl", -1, (void **)&value, &valuelen);
        if (ret > 0 && value && valuelen > 0) {
            if (strcasecmp(value, "on") == 0)
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

        hl = http_listen_add(mgmt, ip, port, ssl, libfile);
        if (hl) {
            hl->jsonobj = jhl;
            hl->forwardproxy = forwardproxy;

            hl->cert = cert;
            hl->prikey = prikey;
            hl->cacert = cacert;

#ifdef HAVE_OPENSSL
            if (hl->ssl_link) {
                hl->sslctx = http_ssl_server_ctx_init(hl->cert, hl->prikey, hl->cacert);
            }
#endif

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

            http_host_build(hl, jhl);
        }

        sprintf(key, "http.listen[%d]", i);
        ret = json_mget_obj(mgmt->cnfjson, key, -1, &jhl);
        if (ret <= 0) break;
    } 

    http_listen_start(mgmt);

    return 0;
}


void * http_host_instance (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPListen * hl = NULL;
    HTTPHost   * host = NULL;
    char         buf[256];
 
    if (!msg) return NULL;
 
    hl = (HTTPListen *)msg->hl;
    if (!hl) return NULL;
 
    str_secpy(buf, sizeof(buf)-1, msg->req_host, msg->req_hostlen);
 
    host = ht_get(hl->host_table, buf);
    if (!host) {
        host = hl->defaulthost;
    }

    return host;
}

void * http_loc_instance (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPListen * hl = NULL;
    HTTPHost   * host = NULL;
    HTTPLoc    * ploc = NULL;
    char         buf[4096];
    int          ret = 0;
    int          i, j, num;
    regmatch_t   pmat[16];

    if (!msg) return NULL;

    hl = (HTTPListen *)msg->hl;
    if (!hl) return NULL;

    /* Location instance times must be not greater than 16 */
    if (++msg->locinst_times >= 16)
        return NULL;

    buf[0] = '\0';
    str_secpy(buf, sizeof(buf)-1, msg->req_host, msg->req_hostlen);

    host = ht_get(hl->host_table, buf);
    if (!host) {
        host = hl->defaulthost;
    }
    if (!host) return NULL;

    msg->phost = host;

    /* for CONNECT method, req_path is NULL */
    if (!msg->docuri->path || msg->docuri->pathlen <= 0)
        return NULL;

    str_secpy(buf, sizeof(buf)-1, msg->docuri->path, msg->docuri->pathlen);

    /* exact matching check if request path is completely equal to location path */
    ploc = ht_get(host->exact_loc_table, buf);
    if (ploc) {
        msg->ploc = ploc;

        msg->matchnum = 1;
        msg->matchstr[0].p = msg->docuri->path;
        msg->matchstr[0].len = msg->docuri->pathlen;

        goto retloc;
    }

    /* prefix matching check if request path has the same prefix with location path */
    ret = actrie_get(host->prefix_actrie, msg->docuri->path, msg->docuri->pathlen, (void **)&ploc);
    if (ret > 0 && ploc) {
        msg->ploc = ploc;

        msg->matchnum = 1;
        msg->matchstr[0].p = msg->docuri->path;
        msg->matchstr[0].len = ret;

        goto retloc;
    }
    
    /* regular expression matching check if request path is matched by regex */
    num = arr_num(host->regex_list);
    for (i = 0; i < num; i++) {
        ret = regexec(arr_value(host->regex_list, i), buf, 16, pmat, 0);
        if (ret == 0) {
            ploc = arr_value(host->regex_loc_list, i);

            msg->ploc = ploc;

            msg->matchnum = 0;
            for (j = 0; j < 16; j++) {
                if (pmat[j].rm_so >= 0) {
                    msg->matchstr[msg->matchnum].p = msg->docuri->path + pmat[j].rm_so;
                    msg->matchstr[msg->matchnum].len = pmat[j].rm_eo - pmat[j].rm_so;
                    msg->matchnum++;
                    continue;
                }
                break;
            }

            goto retloc;
        }
    }

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

    if (ploc->type != servtype) {
        return -10;
    }

    if (ploc->passurl == NULL) {
        return -11;
    }

    if (servtype == SERV_FASTCGI) {
        str_secpy(url, urllen, ploc->passurl, strlen(ploc->passurl));
        return strlen(url);
    }

    if (ploc->matchtype == MATCH_REGEX_CASE || ploc->matchtype == MATCH_REGEX_NOCASE) {
        /* when matching type is regex matching, subsitude
           $num with matching substring */

        http_var_copy(msg, ploc->passurl, strlen(ploc->passurl),
                      url, urllen, msg->matchstr, msg->matchnum, "passurl", 7);

    } else {
        /* when matching type is non-regex matching, remove the matching
           substring of req_path and append the rest of req_path to passurl */

        str_secpy(url, urllen, ploc->passurl, str_len(ploc->passurl));

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
        if (memchr(url, '?', urllen) == NULL) {
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
    HTTPLoc    * ploc = NULL;

    if (!msg || !msg->ploc) return "";

    ploc = (HTTPLoc *)msg->ploc;

    return ploc->root;
}

int http_real_file (void * vmsg, char * path, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPLoc    * ploc = NULL;
    int          slen = 0;
    int          retlen = 0;

    if (!msg || !msg->ploc) return -1;
    if (!path || len <= 0) return -2;

    ploc = (HTTPLoc *)msg->ploc;

    retlen = strlen(ploc->root);

    if (path && len > 0)
        str_secpy(path, len, ploc->root, retlen);

    if (msg->docuri->path && msg->docuri->pathlen > 0) {
        if (path) {
            slen = strlen(path);
            str_secpy(path + slen, len - slen, msg->docuri->path, msg->docuri->pathlen);
        }
        retlen += msg->docuri->pathlen;

    } else {
        if (path) {
            slen = strlen(path);
            str_secpy(path + slen, len - slen, "/", 1);
        }
        retlen += 1;
    }

    if (path) return strlen(path);
    return retlen;
}

int http_real_path (void * vmsg, char * path, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPLoc    * ploc = NULL;
    int          slen = 0;
    int          retlen = 0;

    if (!msg || !msg->ploc) return -1;
    if (!path || len <= 0) return -2;

    ploc = (HTTPLoc *)msg->ploc;

    retlen = strlen(ploc->root);

    if (path && len > 0)
        str_secpy(path, len, ploc->root, retlen);

    if (path) {
        slen = strlen(path);
        str_secpy(path + slen, len - slen, msg->docuri->dir, msg->docuri->dirlen);
    }
    retlen += msg->docuri->dirlen;

    if (path) return strlen(path);

    return retlen;
}

