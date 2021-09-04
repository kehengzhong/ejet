/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "http_header.h"
#include "http_msg.h"
#include "http_mgmt.h"


typedef struct comm_strkey_ {
    char   * name;
    int      namelen;
} CommStrkey;


HeaderUnit * hunit_alloc ()
{
    HeaderUnit * hunit = NULL;

    hunit = kzalloc(sizeof(*hunit));
    return hunit;
}

int hunit_free (void * vhunit)
{
    HeaderUnit * hunit = (HeaderUnit *)vhunit;

    if (!hunit) return -1;

    kfree(hunit);
    return 0;
}

void hunit_void_free (void * vhunit)
{
    hunit_free(vhunit);
}


int hunit_cmp_hunit_by_name(void * a, void * b)
{
    HeaderUnit * hua = (HeaderUnit *)a;
    HeaderUnit * hub = (HeaderUnit *)b;
    int          len = 0;
    int          ret = 0;

    if (!a || !b) return -1;

    if (hua->namelen != hub->namelen) {

        len = (hua->namelen > hub->namelen) ? hub->namelen : hua->namelen;
        if (len <= 0) {
            if (hua->namelen > 0) return 1;
            else return -1;
        }

        ret = str_ncasecmp(HUName(hua), HUName(hub), len);
        if (ret == 0) {
            if (hua->namelen > hub->namelen)
                return 1;
            else return -1;
        } else return ret;
    }

    if (hua->namelen <= 0) return 0;

    return str_ncasecmp(HUName(hua), HUName(hub), hua->namelen);
}


ulong hunit_hash_func (void * vkey)
{
    CommStrkey * key = (CommStrkey *)vkey;
    static long  hunit_mask = ~0U << 26;
    ulong        ret = 0;
    uint8      * p = NULL;
    int          i;

    if (!key) return 0;

    p = (uint8 *)key->name;

    for (i = 0; i < key->namelen; i++) {
        ret = (ret & hunit_mask) ^ (ret << 6) ^ (tolower(*p));
        p++;
    }

    return ret;
}


int hunit_cmp_key (void * a, void * b)
{
    HeaderUnit * unit = (HeaderUnit *)a;
    CommStrkey * key = (CommStrkey *)b;
    int          len = 0, ret;
 
    if (!unit || !key) return -1;

    if (unit->namelen != key->namelen) {

        len = (unit->namelen > key->namelen) ? key->namelen : unit->namelen;
        if (len <= 0) {
            if (unit->namelen > 0) return 1;
            return -1;
        }

        ret = str_ncasecmp(HUName(unit), key->name, len);
        if (ret == 0) {
            if (unit->namelen > key->namelen)
                return 1;
            else
                return -1;

        } else
            return ret;
    }
 
    len = unit->namelen;
    if (len <= 0) return 0;
 
    return str_ncasecmp(HUName(unit), key->name, len);
}


int hunit_set_hashfunc (hashtab_t * htab)
{
    if (!htab) return -1;

    ht_set_hash_func(htab, hunit_hash_func);
    return 0;
}


int hunit_add (hashtab_t * htab, char * name, int namelen, void * value)
{
    CommStrkey  key;

    if (!htab) return -1;
    if (!name || namelen <= 0) return -2;
    if (!value) return -3;

    key.name = name;
    key.namelen = namelen;

    return ht_set(htab, &key, value);
}


HeaderUnit * hunit_get (hashtab_t * htab, char * name, int namelen)
{
    CommStrkey   key;
    HeaderUnit * punit = NULL;

    if (!htab) return NULL;
    if (!name || namelen <= 0) return NULL;

    key.name = name;
    key.namelen = namelen;

    punit = (HeaderUnit *)ht_get(htab, &key);
    return punit;
}


HeaderUnit * hunit_del (hashtab_t * htab, char * name, int namelen)
{
    CommStrkey   key;
    HeaderUnit * punit = NULL;
    
    if (!htab) return NULL;
    if (!name || namelen <= 0) return NULL;

    key.name = name;
    key.namelen = namelen;

    punit = (HeaderUnit *)ht_delete(htab, &key);
    return punit;
}


HeaderUnit * hunit_get_from_list (arr_t * hlist, char * name, int namelen)
{
    CommStrkey   key;
    HeaderUnit * punit = NULL;

    if (!hlist) return NULL;
    if (!name || namelen <= 0) return NULL;

    key.name = name;
    key.namelen = namelen;

    punit = (HeaderUnit *)arr_find_by(hlist, &key, hunit_cmp_key);
    return punit;
}


int http_header_add (void * vmsg, int type, char * name, int namelen, char * value, int valuelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HeaderUnit * phu = NULL;
    HeaderUnit * punit = NULL;
 
    hashtab_t  * header_table = NULL;
    arr_t      * header_list = NULL;
    frame_p      frame = NULL;
 
    if (!msg) return -1;
 
    if (!name) return -2;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
 
    mgmt = msg->httpmgmt;
 
    if (type == 0) { //REQUEST
        header_table = msg->req_header_table;
        header_list = msg->req_header_list;
        frame = msg->req_header_stream;
    } else {
        header_table = msg->res_header_table;
        header_list = msg->res_header_list;
        frame = msg->res_header_stream;
    }
 
    punit = hunit_get (header_table, name, namelen);
    while (punit) {
        phu = punit; punit = punit->next;
        if (phu->valuelen == valuelen &&
            str_ncasecmp(HUValue(phu), value, valuelen) ==0)
        {
            phu->frame = frame;
            phu->name = name;
            phu->namepos = HUPos(frame, name);
            phu->namelen = namelen;
            phu->value = value;
            phu->valuepos = HUPos(frame, value);
            phu->valuelen = valuelen;
            return 0;
        }
    }
 
    punit = bpool_fetch(mgmt->header_unit_pool);
    if (!punit) {
        tolog(1, "http_header_add: fetchUnit null. type=%d name=%s\n", type, name);
        return -5;
    }
    punit->frame = frame;
    punit->name = name;
    punit->namepos = HUPos(frame, name);
    punit->namelen = namelen;
    punit->value = value;
    punit->valuepos = HUPos(frame, value);
    punit->valuelen = valuelen;
    punit->next = NULL;
 
    if (!phu)
        hunit_add(header_table, name, namelen, punit);
    else {
        phu->next = punit;
    }
    arr_insert_by(header_list, punit, hunit_cmp_hunit_by_name);
 
    return 0;
}
 
int http_header_del (void * vmsg, int type, char * name, int namelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HeaderUnit * phu = NULL;
    HeaderUnit * punit = NULL;
 
    hashtab_t  * header_table = NULL;
    arr_t      * header_list = NULL;
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
 
    mgmt = msg->httpmgmt;
 
    if (type == 0) { //REQUEST
        header_table = msg->req_header_table;
        header_list = msg->req_header_list;
    } else {
        header_table = msg->res_header_table;
        header_list = msg->res_header_list;
    }
 
    phu = hunit_del (header_table, name, namelen);
    while (phu) {
        punit = phu; phu = phu->next;

        if (punit && arr_delete_ptr(header_list, punit)) {
            bpool_recycle(mgmt->header_unit_pool, punit);
        }
    }
    if (punit)
        return 0;
 
    return -100;
}
 
int http_header_delall (void * vmsg, int type)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HeaderUnit * unit = NULL;
    int          i, num;
 
    hashtab_t    * header_table = NULL;
    arr_t      * header_list = NULL;
    frame_p    frame = NULL;
 
    if (!msg) return -1;
 
    mgmt = msg->httpmgmt;
 
    if (type == 0) { //REQUEST
        header_table = msg->req_header_table;
        header_list = msg->req_header_list;
        frame = msg->req_header_stream;
    } else {
        header_table = msg->res_header_table;
        header_list = msg->res_header_list;
        frame = msg->res_header_stream;
    }
 
    num = arr_num(header_list);
    for (i = 0; i < num; i++) {
        unit = arr_value(header_list, i);
        if (!unit) continue;
        bpool_recycle(mgmt->header_unit_pool, unit);
    }
    arr_zero(header_list);
    ht_zero(header_table);
    frame_empty(frame);
 
    return 0;
}
 
HeaderUnit * http_header_get (void * vmsg, int type, char * name, int namelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
    hashtab_t    * header_table = NULL;
    arr_t      * header_list = NULL;
 
    if (!msg) return NULL;
    if (!name) return NULL;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return NULL;
 
    if (type == 0) { //REQUEST
        header_table = msg->req_header_table;
        header_list = msg->req_header_list;
    } else {
        header_table = msg->res_header_table;
        header_list = msg->res_header_list;
    }
 
    punit = hunit_get (header_table, name, namelen);
    if (!punit)
        punit = hunit_get_from_list (header_list, name, namelen);
 
    return punit;
}
 
int http_header_get_int (void * vmsg, int type, char * name, int namelen)
{
    HeaderUnit * punit = NULL;
 
    punit = http_header_get(vmsg, type, name, namelen);
    if (punit) {
        return strtod(HUValue(punit), NULL);
    }
    return 0;
}
 
uint32 http_header_get_uint32 (void * vmsg, int type, char * name, int namelen)
{
    HeaderUnit * punit = NULL;
 
    punit = http_header_get(vmsg, type, name, namelen);
    if (punit) {
        return strtoul(HUValue(punit), NULL, 10);
    }
    return 0;
}

long http_header_get_long (void * vmsg, int type, char * name, int namelen)
{
    HeaderUnit * punit = NULL;
 
    punit = http_header_get(vmsg, type, name, namelen);
    if (punit) {
        return strtol(HUValue(punit), NULL, 10);
    }
    return 0;
}
 
ulong http_header_get_ulong (void * vmsg, int type, char * name, int namelen)
{
    HeaderUnit * punit = NULL;
 
    punit = http_header_get(vmsg, type, name, namelen);
    if (punit) {
        return strtoul(HUValue(punit), NULL, 10);
    }
    return 0;
}
 
int64 http_header_get_int64 (void * vmsg, int type, char * name, int namelen)
{
    HeaderUnit * punit = NULL;
 
    punit = http_header_get(vmsg, type, name, namelen);
    if (punit) {
        return strtoll(HUValue(punit), NULL, 10);
    }
    return 0;
}
 
uint64 http_header_get_uint64 (void * vmsg, int type, char * name, int namelen)
{
    HeaderUnit * punit = NULL;
 
    punit = http_header_get(vmsg, type, name, namelen);
    if (punit) {
        return strtoull(HUValue(punit), NULL, 10);
    }
    return 0;
}

HeaderUnit * http_header_get_index (void * vmsg, int type, int index)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
    int          num;
    arr_t      * header_list = NULL;
 
    if (!msg) return NULL;
 
    if (type == 0) { //REQUEST
        header_list = msg->req_header_list;
    } else {
        header_list = msg->res_header_list;
    }
 
    num = arr_num(header_list);
    if (index < 0 || index >= num) return NULL;
 
    punit = arr_value(header_list, index);
 
    return punit;
}
 
int http_header_append (void * vmsg, int type, char * name, int namelen, char * value, int valuelen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HeaderUnit * punit = NULL;
    HeaderUnit * phu = NULL;
 
    hashtab_t  * header_table = NULL;
    arr_t      * header_list = NULL;
    frame_p      frame = NULL;
 
    if (!msg) return -1;
    if (!name) return -2;
 
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
 
    if (value && valuelen < 0) valuelen = str_len(value);
 
    mgmt = msg->httpmgmt;
 
    if (type == 0) { //REQUEST
        header_table = msg->req_header_table;
        header_list = msg->req_header_list;
        frame = msg->req_header_stream;
    } else {
        header_table = msg->res_header_table;
        header_list = msg->res_header_list;
        frame = msg->res_header_stream;
    }
 
    punit = hunit_get (header_table, name, namelen);
    while (punit) {
        phu = punit; punit = punit->next;
        if (phu->valuelen == valuelen &&
            str_ncasecmp(HUValue(phu), value, valuelen) ==0)
        {
            return 0;
        }
    }
 
    punit = bpool_fetch(mgmt->header_unit_pool);
    if (!punit) {
        return -5;
    }
 
    punit->frame = frame;
 
    punit->namepos = frameL(frame);
    frame_put_nlast(frame, name, namelen);
    punit->name = (char *)frameP(frame) + punit->namepos;
    punit->namelen = namelen;

    frame_append(frame, ": ");
 
    if (value && valuelen > 0) {
        punit->valuepos = frameL(frame);
        frame_put_nlast(frame, value, valuelen);
        punit->value = (char *)frameP(frame) + punit->valuepos;
        punit->valuelen = valuelen;
    } else {
        punit->valuepos = 0;
        punit->value = NULL;
        punit->valuelen = 0;
    }

    frame_append(frame, "\r\n");
 
    punit->next = NULL;
 
    if (!phu)
        hunit_add(header_table, name, namelen, punit);
    else
        phu->next = punit;
 
    arr_insert_by(header_list, punit, hunit_cmp_hunit_by_name);
 
    if (type == 0) { //REQUEST
        if (msg->req_header_stream == NULL)
            msg->req_header_stream = frame;
    } else {
        if (msg->res_header_stream == NULL)
            msg->res_header_stream = frame;
    }
 
    return 0;
}
 
/* date string defined by RFC 822, updated by RFC 1123
   Sun, 17 Dec 2000 08:21:33 GMT   */
int http_header_append_date (void * vmsg, int type, char * name, int namelen, time_t dtval)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    struct tm    gmtval;
    static char * monthname[12] = {
                       "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    static char * weekname[7] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    char          value[48];
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
 
    memset(value, 0, sizeof(value));
 
    gmtval = *gmtime((time_t *)&dtval);
 
    sprintf(value, "%s, %02d %s %4d %02d:%02d:%02d GMT",
             weekname[gmtval.tm_wday],
             gmtval.tm_mday,
             monthname[gmtval.tm_mon],
             gmtval.tm_year + 1900,
             gmtval.tm_hour,
             gmtval.tm_min,
             gmtval.tm_sec);
 
    return http_header_append(msg, type, name, namelen, value, strlen(value));
}
 
int http_header_append_int (void * vmsg, int type, char * name, int namelen, int ival)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char        value[64];
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
 
    memset(value, 0, sizeof(value));
 
    sprintf(value, "%d", ival);
 
    return http_header_append(msg, type, name, namelen, value, strlen(value));
}
 
int http_header_append_uint32 (void * vmsg, int type, char * name, int namelen, uint32 ival)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char        value[64];
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
 
    memset(value, 0, sizeof(value));
 
    sprintf(value, "%u", ival);
 
    return http_header_append(msg, type, name, namelen, value, strlen(value));
}

 
int http_header_append_long (void * vmsg, int type, char * name, int namelen, long ival)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char        value[64];
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
 
    memset(value, 0, sizeof(value));
 
    sprintf(value, "%ld", ival);
 
    return http_header_append(msg, type, name, namelen, value, strlen(value));
}
 
int http_header_append_ulong (void * vmsg, int type, char * name, int namelen, ulong ival)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char        value[64];
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
 
    memset(value, 0, sizeof(value));
 
    sprintf(value, "%lu", ival);
 
    return http_header_append(msg, type, name, namelen, value, strlen(value));
}
 
int http_header_append_int64 (void * vmsg, int type, char * name, int namelen, int64 ival)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char        value[128];
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;
 
    memset(value, 0, sizeof(value));
 
#if defined(_WIN32) || defined(_WIN64)
    sprintf(value, "%I64d", ival);
#else
    sprintf(value, "%lld", ival);
#endif

    return http_header_append(msg, type, name, namelen, value, strlen(value));
}

int http_header_append_uint64 (void * vmsg, int type, char * name, int namelen, uint64 ival)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char         value[128];
 
    if (!msg) return -1;
    if (!name) return -2;
    if (namelen < 0) namelen = strlen(name);
    if (namelen <= 0) return -3;

    memset(value, 0, sizeof(value));

#if defined(_WIN32) || defined(_WIN64)
    sprintf(value, "%I64u", ival);
#else
    sprintf(value, "%llu", ival);
#endif

    return http_header_append(msg, type, name, namelen, value, strlen(value));
}

int http_entity_header_parse (void * vmsg, int type, char * pbyte, int len)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    char     * pend = NULL;
    char     * pcolon = NULL;
    char     * poct = NULL;
    char     * name = NULL;
    char     * value = NULL;
    int        namelen = 0, valuelen = 0;

    if (!msg) return -1;
    if (!pbyte || len < 1) return -2;

    pend = pbyte + len;
    pbyte = skipOver(pbyte, len, " \t\r\n", 3);
    if (pbyte >= pend) return -100;

    name = pbyte;

    pcolon = skipTo(pbyte, pend-pbyte, ":", 1);
    if (!pcolon || pcolon >= pend) return -101;

    poct = rskipOver(pcolon-1, pcolon-name, " \t", 2);
    if (poct < name) return -102;
    namelen = poct - name + 1;

    poct = skipOver(pcolon+1, pend-pcolon-1, " \t\r", 3);
    if (poct >= pend) return -200;

    value = poct;

    poct = rskipOver(pend-1, pend-poct, " \t\r\n", 4);
    if (poct < value) {value = NULL; valuelen = 0; }
    else valuelen = poct - value + 1;

    http_header_append(msg, type, name, namelen, value, valuelen);

    return 0;
}

