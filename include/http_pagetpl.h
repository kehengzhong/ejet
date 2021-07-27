/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_PAGETPL_H_
#define _HTTP_PAGETPL_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef int PageTplCB (void * cbobj, void * vmsg, void * tplvar, void * tplunit, frame_p cfrm);

/* <?ejetpl TEXT $CURROOT PARA=abcd ?>                                                  */
/* <?ejetpl LINK $LINKNAME URL=/csc/disponlist.so SHOW=第一页 PARA=listfile?>           */
/* <?ejetpl IMG $IMGNAME URL=/csc/drawimg.so?randval=234 SHOW=实时走势 PARA="a=1"?>     */
/* <?ejetpl LIST $ACCESSLOG PARA=1?>                                                    */
/* <?ejetpl INCLUDE /home/hzke/dxcang/httpdoc/foot.html ?>                        */

typedef struct pagetplunit {   
    uint8    type; //1-TEXT, 2-LINK, 3-IMG, 4-LIST, 5-INCLUDE, 0-Unknown
    char   * text;
    int      textlen;        
    char   * url;     
    int      urllen;
    char   * show;     
    int      showlen;
    char   * para;    
    int      paralen;
    size_t   bgnpos; 
    size_t   endpos; 
    char   * tplfile;
} PageTplUnit;


typedef struct http_pagetpl_s {
    char        text[128];
    int         textlen;

    PageTplCB * func;
    void      * cbobj;

} HTTPPageTpl;


int    http_pagetpl_cmp_key (void * a, void * b);

void   http_pagetpl_free (void * a);

int    http_pagetpl_callback (void * vmsg, void * vtplunit, void * tplvar, frame_p cfrm);

int    http_pagetpl_parse    (void * msg, char * file, void * vb, int len, void * var, frame_p frm);
int    http_pagetpl_add      (void * msg, void * pbyte, int bytelen, void * tplvar);
int    http_pagetpl_add_file (void * msg, char * tplfile, void * tplvar);

int    http_pagetpl_text_cb (void * vhl, char * hostn, int hostlen,
                             void * text, int textlen, void * func, void * cbobj);
int    http_pagetpl_list_cb (void * vhl, char * hostn, int hostlen,
                             void * text, int textlen, void * func, void * cbobj);

#ifdef __cplusplus
}
#endif

#endif

