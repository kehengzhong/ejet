/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"
#include "http_listen.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_header.h"
#include "http_pagetpl.h"

int http_pagetpl_cmp_key (void * a, void * b)
{
    HTTPPageTpl * ptpl = (HTTPPageTpl *)a;
    ckstr_t     * key = (ckstr_t *)b;
    ckstr_t       tpl;
 
    if (!ptpl || !key) return -1;
 
    tpl.p = ptpl->text; tpl.len = ptpl->textlen;

    return ckstr_cmp(&tpl, key);
}

void http_pagetpl_free (void * a)
{
    HTTPPageTpl * ptpl = (HTTPPageTpl *)a;

    if (ptpl) kfree(ptpl);
}

int http_pagetpl_callback (void * vmsg, void * vtplunit, void * tplvar, frame_p cfrm)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    PageTplUnit * tplunit = (PageTplUnit *)vtplunit;
    HTTPPageTpl * pagetpl = NULL;
    HTTPHost    * host = NULL;
    ckstr_t       key;

    if (!msg) return -1;
    if (!tplunit) return -2;

    host = msg->phost;
    if (!host) return -10;

    key.p = tplunit->text;
    key.len = tplunit->textlen;

    //1-TEXT, 2-LINK, 3-IMG, 4-LIST, 0-Unknown
    if (tplunit->type == 1 || tplunit->type == 2 || tplunit->type == 3) {
        EnterCriticalSection(&host->texttplCS);
        pagetpl = ht_get(host->texttpl_tab, &key);
        LeaveCriticalSection(&host->texttplCS);
 
    } else if (tplunit->type == 4) {
        EnterCriticalSection(&host->listtplCS);
        pagetpl = ht_get(host->listtpl_tab, &key);
        LeaveCriticalSection(&host->listtplCS);
    }

    if (!pagetpl || !pagetpl->func) return -100;

    return (*pagetpl->func)(pagetpl->cbobj, msg, tplvar, tplunit, cfrm);
}


int http_pagetpl_parse (void * vmsg, char * tplfile, void * vbyte, int bytelen, void * tplvar, frame_p objfrm)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    char        * pbyte = (char *)vbyte;

    void        * hfile = NULL;
    int64         fsize = 0;
#if defined(_WIN32) || defined(_WIN64)
    HANDLE        hmap;
    void        * pmap = NULL;
    int64         maplen = 0;
    int64         mapoff = 0;
#endif

    char        * pbgn = NULL;
    char        * pend = NULL;
    char        * pval = NULL;
    char        * pvalend = NULL;
    char        * poct = NULL;
    char        * ptxt = NULL;
 
    int           len, tplnum = 0;
    PageTplUnit   tpl;
    frame_p       cfrm = NULL;
    char          fname[1024];
 
    if (!msg) return -1;
 
    if (tplfile && (hfile = native_file_open(tplfile, NF_READ)) != NULL) {
        fsize = native_file_size(hfile);
        if (fsize > 128 * 1024 * 1024)
            return -101;

#ifdef UNIX
        pbyte = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, native_file_fd(hfile), 0);
#elif defined(_WIN32) || defined(_WIN64)
        pbyte = file_mmap (NULL, native_file_handle(hfile), 0, fsize, NULL, &hmap, &pmap, &maplen, &mapoff);
#endif
        if (!pbyte) {
            native_file_close(hfile);
            return -300;
        }

        bytelen = (int)fsize;
 
    } else {
        tplfile = NULL;
 
        if (!pbyte) return -2;
        if (bytelen < 0) bytelen = str_len(pbyte);
        if (bytelen <= 0) return -3;
    }
 
    cfrm = msg->GetFrame(msg);
 
    pbgn = pbyte;
    pend = pbyte + bytelen;
 
    for ( ; pbgn < pend; ) {
        /* <?ejetpl TEXT $CURROOT PARA=abcd ?>                                               */
        /* <?ejetpl LINK $LINKNAME URL=/csc/disponlist.so SHOW=第一页 PARA=listfile?>        */
        /* <?ejetpl IMG $IMGNAME URL=/csc/drawimg.so?randval=234 SHOW=实时走势 PARA="a=1"?>  */
        /* <?ejetpl LIST $ACCESSLOG PARA=1?>                                                 */
        /* <?ejetpl INCLUDE /home/hzke/dxcang/httpdoc/foot.html PARA=1?>                     */
 
        pval = sun_find_string(pbgn, pend - pbgn, "<?ejetpl", 8, NULL);
        if (!pval || pval >= pend) break;
 
        pvalend = sun_find_string(pval + 8, pend - pval - 8, "?>", 2, NULL);
        if (!pvalend || pvalend >= pend) break;
 
        if (pval > pbgn) {
            if (objfrm)
                frame_put_nlast(objfrm, pbgn, pval - pbgn);
            else if (tplfile)
                chunk_add_file(msg->res_body_chunk, tplfile, pbgn - pbyte, pval - pbgn, 1);
            else
                chunk_add_buffer(msg->res_body_chunk, pbgn, pval - pbgn);
        }
 
        memset(&tpl, 0, sizeof(tpl));
        tpl.bgnpos = pval - pbyte;
        tpl.endpos = pvalend + 2 - pbyte;
        tpl.tplfile = tplfile;
 
        /* move pval to the begining, pbgn to the end of pagetpl tag: <?ejetpl xxxx xxx ?> */
        pval = pval + 8;
        pbgn = pvalend + 2;
 
        /* pval is begining of command keyword, poct is the end of command.
                      |   |
                      V   V
             <?ejetpl LIST xxxx ..... ?> xxxxxx  */
        pval = skipOver(pval, pvalend - pval, " \t\r\n\f\v", 6);
        if (pval >= pvalend) continue;
        poct = skipTo(pval, pvalend-pval, ",; \t\r\n\f\v", 8);
 
        ptxt = pval;
        len = poct - pval;
 
        /* pval is begining of command content, poct is the end of content.
                              |      |
                              V      V
             <?ejetpl INCLUDE abc.txt PARA=..... ?> xxxxxx  */
        pval = skipOver(poct, pvalend - poct, ",; \t\r\n\f\v", 8);
        if (pval >= pvalend) continue;
        poct = skipTo(pval, pvalend-pval, ",; \t\r\n\f\v", 8);
 
        frame_empty(cfrm);
 
        if (len == 4 && str_ncasecmp(ptxt, "TEXT", 4) == 0) {
            tpl.type = 1;
 
        } else if (len == 4 && str_ncasecmp(ptxt, "LINK", 4) == 0) {
            /* <?ejetpl LINK $LINKNAME URL=/csc/disponlist.so SHOW=第一页 PARA=listfile?>        */
            tpl.type = 2;
 
        } else if (len == 3 && str_ncasecmp(ptxt, "IMG", 3) == 0) {
            /* <?ejetpl IMG $IMGNAME URL=/csc/drawimg.so?randval=234 SHOW=实时走势 PARA="a=1"?>  */
            tpl.type = 3;
 
        } else if (len == 4 && str_ncasecmp(ptxt, "LIST", 4) == 0) {
            tpl.type = 4;
 
        } else if (len == 7 && str_ncasecmp(ptxt, "INCLUDE", 7) == 0) {
            /* <?ejetpl INCLUDE /home/hzke/dxcang/httpdoc/foot.html PARA=1?>  */
            tpl.type = 5;
 
            pval = skipOver(pval, poct-pval, "'\"", 2);
            poct = rskipOver(poct-1, poct-pval, "'\"", 2);
            if (poct < pval) continue;
 
            tpl.url = pval; tpl.urllen = poct - pval + 1;
            str_secpy(fname, sizeof(fname)-1, tpl.url, tpl.urllen);
 
            if (file_is_regular(fname)) {
                http_pagetpl_parse(msg, fname, NULL, 0, tplvar, objfrm);
 
            } else {
                msg->GetRealPath(msg, fname, sizeof(fname)-1);
                len = strlen(fname);
                str_secpy(fname + len, sizeof(fname)-1-len, tpl.url, tpl.urllen);
                if (file_is_regular(fname))
                    http_pagetpl_parse(msg, fname, NULL, 0, tplvar, objfrm);
            }
            tplnum++;
            continue;
 
        } else {
            continue;
        }
 
        tpl.text = pval;
        tpl.textlen = poct - pval;
        if (tpl.textlen <= 0) continue;
 
        if (tpl.text[0] != '$') {
            frame_put_nlast(cfrm, tpl.text, tpl.textlen);
        } else {
            tpl.text++; tpl.textlen--;
            if (tpl.textlen <= 0) continue;
 
            str_value_by_key(pval, pvalend-pval, "PARA", (void **)&tpl.para, &tpl.paralen);
            if (tpl.type == 2 || tpl.type == 3) {
                str_value_by_key(pval, pvalend-pval, "URL", (void **)&tpl.url, &tpl.urllen);
                str_value_by_key(pval, pvalend-pval, "SHOW", (void **)&tpl.show, &tpl.showlen);
            }
 
            http_pagetpl_callback(msg, &tpl, tplvar, cfrm);
        }
        tplnum++;
 
        if (frameL(cfrm) > 0) {
            if (objfrm)
                frame_put_nlast(objfrm, pbgn, pval - pbgn);
            else
                chunk_add_buffer(msg->res_body_chunk, frameP(cfrm), frameL(cfrm));
        }
    }
 
    msg->RecycleFrame(msg, cfrm);
 
    if (pbgn < pend) {
        if (objfrm)
            frame_put_nlast(objfrm, pbgn, pend - pbgn);
        else if (tplfile)
            chunk_add_file(msg->res_body_chunk, tplfile, pbgn - pbyte, pend - pbgn, 1);
        else
            chunk_add_buffer(msg->res_body_chunk, pbgn, pend - pbgn);
    }
 
    if (tplfile && hfile != NULL) {
#ifdef UNIX
        munmap(pbyte, fsize);
#elif defined(_WIN32) || defined(_WIN64)
        file_munmap(hmap, pmap);
#endif
        native_file_close(hfile);
    }
 
    return 0;
}
 
 
int http_pagetpl_add (void * vmsg, void * pbyte, int bytelen, void * tplvar)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    int ret = 0;
 
    if (!msg) return -1;
 
    ret = http_pagetpl_parse(msg, NULL, pbyte, bytelen, tplvar, NULL);
    if (ret >= 0) {
        if (http_header_get(msg, 1, "Content-Type", 12) == NULL) {
            msg->SetResContentType (msg, "text/html", 9);
        }
    }
 
    return ret;
}
 
int http_pagetpl_add_file (void * vmsg, char * tplfile, void * tplvar)
{
    HTTPMsg * msg = (HTTPMsg *)vmsg;
    int ret = 0;
 
    if (!msg) return -1;
 
    ret = http_pagetpl_parse(msg, tplfile, NULL, 0, tplvar, NULL);
    if (ret >= 0) {
        if (http_header_get(msg, 1, "Content-Type", 12) == NULL) {
            msg->SetResContentType (msg, "text/html", 9);
        }
    }
 
    return ret;
}


int http_pagetpl_text_cb (void * vhl, char * hostn, int hostlen,
                                  void * text, int textlen, void * func, void * cbobj)
{
    HTTPListen  * hl = (HTTPListen *)vhl;
    HTTPHost    * host = NULL;
    ckstr_t       key;
    HTTPPageTpl * ptpl = NULL;

    if (!hl) return -1;
    if (!text) return -2;
    if (textlen < 0) textlen = strlen(text);
    if (textlen <= 0) return -3;
 
    host = http_host_create(hl, hostn, hostlen, NULL, NULL, NULL, NULL);
    if (!host) return -100;

    key.p = text;
    key.len = textlen;
 
    EnterCriticalSection(&host->texttplCS);
 
    ptpl = ht_get(host->texttpl_tab, &key);
    if (!ptpl) {
        ptpl = kzalloc(sizeof(*ptpl));
 
        str_secpy(ptpl->text, sizeof(ptpl->text)-1, text, textlen);
        ptpl->textlen = textlen;
        ptpl->func = func;
        ptpl->cbobj = cbobj;

        ht_set(host->texttpl_tab, &key, ptpl);
 
    } else {
        str_secpy(ptpl->text, sizeof(ptpl->text)-1, text, textlen);
        ptpl->textlen = textlen;
        ptpl->func = func;
        ptpl->cbobj = cbobj;
    }
 
    LeaveCriticalSection(&host->texttplCS);
 
    return 0;

}

int http_pagetpl_list_cb (void * vhl, char * hostn, int hostlen,
                                  void * text, int textlen, void * func, void * cbobj)
{
    HTTPListen  * hl = (HTTPListen *)vhl;
    HTTPHost    * host = NULL;
    ckstr_t       key;
    HTTPPageTpl * ptpl = NULL;

    if (!hl) return -1;
    if (!text) return -2;
    if (textlen < 0) textlen = strlen(text);
    if (textlen <= 0) return -3;
 
    host = http_host_create(hl, hostn, hostlen, NULL, NULL, NULL, NULL);
    if (!host) return -100;
 
    key.p = text;
    key.len = textlen;

    EnterCriticalSection(&host->listtplCS);
 
    ptpl = ht_get(host->listtpl_tab, &key);
    if (!ptpl) {
        ptpl = kzalloc(sizeof(*ptpl));
 
        str_secpy(ptpl->text, sizeof(ptpl->text)-1, text, textlen);
        ptpl->textlen = textlen;
        ptpl->func = func;
        ptpl->cbobj = cbobj;
 
        ht_set(host->listtpl_tab, &key, ptpl);
 
    } else {
        str_secpy(ptpl->text, sizeof(ptpl->text)-1, text, textlen);
        ptpl->textlen = textlen;
        ptpl->func = func;
        ptpl->cbobj = cbobj;
    }
 
    LeaveCriticalSection(&host->listtplCS);

    return 0;
}

