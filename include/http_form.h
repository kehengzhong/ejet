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

#ifndef _HTTP_FORM_H_
#define _HTTP_FORM_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HTTPForm_ {
    char      * name;        //allocated, need free
    char      * ctype;       //allocated, need free
     
    uint8       formtype  : 6; //0-form data  1-file
    uint8       alloctype : 2; //0-default kalloc/kfree 1-os-specific malloc/free 2-kmempool alloc/free 3-kmemblk alloc/free

    void      * mpool;
 
    char      * filename;    //allocated, need free
    char      * basename;    //allocated, need free
    char      * extname;
 
    int64       valuepos;
    int64       valuelen;
 
    chunk_t   * body_chunk;
    uint8       filecache;
 
} HTTPForm, http_form_t;

void * http_form_alloc();
void   http_form_free (void * vform);

void * http_form_node (void * vmsg, char * key);
int http_form_get    (void * vmsg, char * key, char ** ctype, uint8 * formtype, char ** fname, int64 * valuelen);
int http_form_value  (void * vmsg, char * key, char * value, int64 valuelen);
int http_form_valuep (void * vmsg, char * key, int64 pos, char ** pvalue, int64 * valuelen);
int http_form_tofile (void * vmsg, char * key, int filefd);

int http_form_multipart_parse (void * vmsg, arr_t * formlist);

#ifdef __cplusplus
}
#endif

#endif


