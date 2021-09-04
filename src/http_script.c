/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"
#ifdef UNIX
#include <regex.h>
#endif
#if defined(_WIN32) || defined(_WIN64)
#define PCRE_STATIC 1
#include "pcre.h"
#endif

#include "http_listen.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_header.h"
#include "http_variable.h"
#include "http_script.h"

typedef char * ScriptParser (void * vhsc, char * p, int slen);

typedef struct script_cmd_s {
    char    * cmd;
    int       len;
    void    * parser;
} scmd_t;

hashtab_t * script_parser_table = NULL;


void * http_script_alloc ()
{
    HTTPScript * hsc = NULL;

    hsc = kzalloc(sizeof(*hsc));
    if (!hsc) return NULL;

    hsc->alloc = 1;

    return hsc;
}

int http_script_init (void * vhsc, void * vmsg, char * psc, int sclen, uint8 sctype, char * vname, int vtype)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;

    if (!hsc) return -1;

    hsc->msg = vmsg;
    hsc->script = psc;
    hsc->scriptlen = sclen;
    hsc->sctype = sctype;

    hsc->replied = 0;
    hsc->exitflag = 0;
    hsc->reloc = 0;

    hsc->retval = NULL;
    hsc->retvallen = 0;

    hsc->vname = vname;
    hsc->vtype = vtype;

    return 0;
}

void http_script_free (void * vhsc)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;

    if (!hsc) return;

    if (hsc->retval) {
        kfree(hsc->retval);
        hsc->retval = NULL;
    }
    hsc->retvallen = 0;

    hsc->msg = NULL;
    hsc->script = NULL;
    hsc->scriptlen = 0;
    hsc->sctype = 0;

    hsc->replied = 0;
    hsc->exitflag = 0;
    hsc->reloc = 0;

    hsc->vname = NULL;
    hsc->vtype = 0;

    if (hsc->alloc) {
        kfree(hsc);
    }
}


int is_symbol_char (int c)
{
    if ( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
         ( c >= '0' && c <= '9') || (c == '_') )
        return 1;
 
    switch (c) {
    case '.':
    case '-':
    case ':':
    case '/':
    case '&':
    case '?':
    case '#':
    case '%':
    case '@':
    case '*':
    case '!':
    case '~':
    case ',':
    case ';':
        return 1;
    }

    return 0;
}

static int is_exp_char (int c)
{
    if ( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         ( c >= '0' && c <= '9') || (c == '_') )
        return 1;

    return 0;
}

static int is_var_char (int c)
{
    if ( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c == '_') )
        return 1;
 
    return 0;
}

char * trim_var (char * p, int len)
{
    int  i;

    if (!p) return p;
    if (len < 0) len = strlen(p);
    if (len <= 0) return p;

    for ( ; len > 0 && (ISSPACE(p[len-1]) || p[len-1] == '"' || p[len-1] == '\''); len--)
        p[len-1] = '\0';

    for (i = 0; i < len && (p[i] == '"' || p[i] == '\'' || ISSPACE(p[i])); i++);

    return p + i;
}

char * goto_var_end (char * p, int len)
{
    char  * pbgn = p;
    char  * pend = NULL;
    char  * poct = NULL;
 
    if (!p) return p;
    if (len < 0) len = strlen(p);
    if (len <= 0) return p;
 
    pend = pbgn + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;

    if (*pbgn != '$') return pbgn;

    pbgn++;
    if (*pbgn == '{') {
        /* ${ fid }$query[0] */
        pbgn = skipToPeer(pbgn, pend-pbgn, '{', '}');
        if (pbgn >= pend) return pbgn;

        return pbgn + 1;
    }

    poct = pbgn;
    while (poct < pend && is_var_char(*poct)) poct++;
    if (poct == pbgn) return poct + 1;  //$$abc $@abc
    if (poct >= pend) return poct;

    /* $request_header[accept] */
    if (poct < pend && *poct == '[') {
        poct = skipToPeer(poct, pend-poct, '[', ']');
        if (poct >= pend) return poct;
        if (*poct == ']') poct++;
    }

    return poct;
}

char * goto_symbol_end (char * p, int len)
{
    char  * pbgn = p;
    char  * pend = NULL;

    if (!p) return p;
    if (len < 0) len = strlen(p);
    if (len <= 0) return p;

    pend = pbgn + len;

    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;

    /* $abc$efg${ fid }istillhere */

    for ( ; pbgn < pend; ) {
        if (*pbgn == '$') {
            pbgn = goto_var_end(pbgn, pend-pbgn);
            if (pbgn >= pend) return pbgn;

        } else if (*pbgn == '"' || *pbgn == '\'') {
            pbgn = skipEscTo(pbgn+1, pend-pbgn-1, pbgn, 1);
            if (pbgn >= pend) return pbgn;
            pbgn++;

        } else if (*pbgn == '(') {
            pbgn = skipToPeer(pbgn, pend-pbgn, '(', ')');
            if (pbgn >= pend) return pbgn;
            pbgn++;

        } else if (ISSPACE(*pbgn)) {
            return pbgn;

        } else {
            pbgn++;
        }
    }

    return pbgn;
}

char * get_var_name (char * p, int len, char * vname, int vlen)
{
    char  * pbgn = p;
    char  * pend = NULL;
    char  * poct = NULL;
    char  * pvarend = NULL;
 
    if (!p) return p;
    if (len < 0) len = strlen(p);
    if (len <= 0) return p;
 
    if (!vname || vlen <= 0) return p;

    vname[0] = '\0';

    pend = pbgn + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;

    if (*pbgn != '$') return pbgn;

    if (pbgn[1] == '{') {
        poct = skipToPeer(pbgn+1, pend-pbgn-1, '{', '}');
        if (!poct || poct >= pend) return poct;

        pbgn = skipOver(pbgn+2, poct-pbgn-2, " \t\r\n", 4);
        if (pbgn >= poct) return poct + 1;

        /* ${ remote_addr }, or ${ query [ fid ] } */
        pvarend = rskipOver(poct-1, poct-pbgn, " \t\r\n", 4);

        str_secpy(vname, vlen, pbgn, pvarend-pbgn+1);
        pbgn = poct + 1;

    } else {
       poct = pbgn + 1;
       while (is_var_char(*poct) && poct < pend) poct++;
       if (poct <= pbgn + 1) return pbgn;

        /* $request_header[accept] */
        if (poct < pend && *poct == '[') {
            poct = skipTo(poct, pend-poct, "]", 1);
            if (*poct == ']') poct++;
        }

        str_secpy(vname, vlen, pbgn + 1, poct-pbgn-1);
        pbgn = poct;
    }

    return pbgn;
}

int get_var_value (void * vhsc, char * p, int len, char * value, int vallen, int getvar)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char       * pbgn = p;
    char       * pend = NULL;
    char       * poct = NULL;

    if (!hsc) return -1;

    if (!p) return -2;
    if (len < 0) len = strlen(p);
    if (len <= 0) return -3;

    if (!value || vallen <= 0) return -10;

    value[0] = '\0';

    pend = pbgn + len;

    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return -100;

    poct = rskipOver(pend-1, pend-pbgn, " \t\r\n\f\v", 6);
    if (poct < pbgn) return -101;
    pend = poct + 1;

    if ( ((*pbgn == '"' || *pbgn == '\'') && *poct == *pbgn) ||
         (*pbgn == '(' && *poct == ')') ) {
        pbgn++;
        poct--;
        pend--;
        if (pbgn >= pend) return 0;
    }

    if (getvar)
        return http_var_copy(hsc->msg, pbgn, pend-pbgn, value, vallen, NULL, 0, hsc->vname, hsc->vtype);

    return str_secpy(value, vallen, pbgn, pend-pbgn);
}


/* if ( -d /opt/abc.html && -x aaa.txt ) */

static int script_if_file_parse (void * vhsc, char * pbgn, int len, char ** pterm)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char         buf[4096];
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
#ifdef UNIX
    struct stat  fs;
#endif

    if (pterm) *pterm = pbgn;

    if (!hsc || !pbgn || len <= 0) return 0;

    pend = pbgn + len;

    if (pend - pbgn > 2 && pbgn[0] == '-' &&
        (pbgn[1] == 'f' || pbgn[1] == 'd' || pbgn[1] == 'e' || pbgn[1] == 'x'))
    {
        poct = skipOver(pbgn+2, pend-pbgn-2, " \t\r\n\f\v", 6);
        if (poct >= pend) {
            if (pterm) *pterm = poct;
            return 0;
        }

        pexpend = goto_symbol_end(poct, pend-poct);
        if (pterm) *pterm = pexpend;

        get_var_value(hsc, poct, pexpend-poct, buf, sizeof(buf)-1, 1);
        poct = trim_var(buf, strlen(buf));

        if (pbgn[1] == 'f') {
            if (file_is_regular(poct)) return 1;

        } else if (pbgn[1] == 'd') {
            if (file_is_dir(poct)) return 1;

        } else if (pbgn[1] == 'e') {
            if (file_exist(poct)) return 1;

        } else if (pbgn[1] == 'x') {
#ifdef UNIX
            if (file_stat(poct, &fs) < 0) return 0;
            if (fs.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
                return 1;
#endif
        }
    }

    return 0;
}

/* if ( !-d /opt/abc.html && -x aaa.txt ) */

static int script_if_not_file_parse (void * vhsc, char * pbgn, int len, char ** pterm)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char         buf[4096];
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
#ifdef UNIX
    struct stat  fs;
#endif

    if (pterm) *pterm = pbgn;

    if (!hsc || !pbgn || len <= 0) return 0;

    pend = pbgn + len;

    if (pend - pbgn > 3 && pbgn[0] == '!' && pbgn[1] == '-' &&
        (pbgn[2] == 'f' || pbgn[2] == 'd' || pbgn[2] == 'e' || pbgn[2] == 'x'))
    {
        poct = skipOver(pbgn+3, pend-pbgn-3, " \t\r\n\f\v", 6);
        if (poct >= pend) {
            if (pterm) *pterm = poct;
            return 0;
        }

        pexpend = goto_symbol_end(poct, pend-poct);
        if (pterm) *pterm = pexpend;

        get_var_value(hsc, poct, pexpend-poct, buf, sizeof(buf)-1, 1);
        poct = trim_var(buf, strlen(buf));

        if (pbgn[2] == 'f') {
            if (!file_is_regular(poct)) return 1;

        } else if (pbgn[2] == 'd') {
            if (!file_is_dir(poct)) return 1;

        } else if (pbgn[2] == 'e') {
            if (!file_exist(poct)) return 1;

        } else if (pbgn[2] == 'x') {
#ifdef UNIX
            if (file_stat(poct, &fs) < 0) return 1;
            if (!(fs.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
                return 1;
#endif
        }
    }

    return 0;
}

static int str_val_type (char * p, int len)
{
    int    i;
    int    hasdot = 0;

    if (!p) return -1;
    if (len < 0) len = strlen(p);
    if (len <= 0) return -2;

    if (p[0] < '0' || p[0] > '9')
        return 0;  //string

    for (i = 1; i < len; i++) {
        if (p[i] == '.') {
            hasdot++;
            if (hasdot > 1) return 0;
        } else if (p[i] < '0' || p[i] > '9') {
            return 0; //string
        }
    }

    if (hasdot == 0) return 1; //integer

    return 2; //double
}

static int script_if_objcmp (void * vhsc, char * avar, int avarlen, char * cmpsym, char * bvar, int bvarlen)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;

    char         bufa[4096];
    char         bufb[4096];
    int          lena = 0;
    int          lenb = 0;
    char       * pa = NULL;
    char       * pb = NULL;

    int          valtypea = 0;
    int          valtypeb = 0;
    int64        aival64 = 0;
    int64        bival64 = 0;
    double       adval = 0;
    double       bdval = 0;

#ifdef UNIX
    regex_t      regobj;
    regmatch_t   pmat[4];
#endif
#if defined(_WIN32) || defined(_WIN64)
    pcre       * regobj = NULL;
    char       * errstr = NULL;
    int          erroff = 0;
    int          ovec[36];
#endif
    int          ret = 0;

    if (!hsc) return 0;

    if (!avar || avarlen <= 0) return 0;
    if (!cmpsym && strlen(cmpsym) <= 0) return 0;
    if (!bvar || bvarlen <= 0) return 0;

    get_var_value(hsc, avar, avarlen, bufa, sizeof(bufa)-1, 1);
    get_var_value(hsc, bvar, bvarlen, bufb, sizeof(bufb)-1, 1);

    pa = trim_var(bufa, strlen(bufa));
    pb = trim_var(bufb, strlen(bufb));

    lena = strlen(pa);
    lenb = strlen(pb);

    /* do comparing or matching calculation */
    if (strcasecmp(cmpsym, "==") == 0) {
        valtypea = str_val_type(pa, lena);
        valtypeb = str_val_type(pb, lenb);
        if (valtypea == 1 && valtypeb == 1) {
            aival64 = strtoll(pa, NULL, 10);
            bival64 = strtoll(pb, NULL, 10);
            if (aival64 == bival64) return 1;
            return 0;
        } else if (valtypea == 2 && valtypeb == 2) {
            adval = strtoll(pa, NULL, 10);
            bdval = strtoll(pb, NULL, 10);
            if (adval == bdval) return 1;
            return 0;
        }
        return (strcasecmp(pa, pb) == 0) ? 1 : 0;

    } else if (strcasecmp(cmpsym, ">") == 0) {
        valtypea = str_val_type(pa, lena);
        valtypeb = str_val_type(pb, lenb);
        if (valtypea == 1 && valtypeb == 1) {
            aival64 = strtoll(pa, NULL, 10);
            bival64 = strtoll(pb, NULL, 10);
            if (aival64 > bival64) return 1;
            return 0;
        } else if (valtypea == 2 && valtypeb == 2) {
            adval = strtoll(pa, NULL, 10);
            bdval = strtoll(pb, NULL, 10);
            if (adval > bdval) return 1;
            return 0;
        }
        return (strcasecmp(pa, pb) > 0) ? 1 : 0;

    } else if (strcasecmp(cmpsym, ">=") == 0) {
        valtypea = str_val_type(pa, lena);
        valtypeb = str_val_type(pb, lenb);
        if (valtypea == 1 && valtypeb == 1) {
            aival64 = strtoll(pa, NULL, 10);
            bival64 = strtoll(pb, NULL, 10);
            if (aival64 >= bival64) return 1;
            return 0;
        } else if (valtypea == 2 && valtypeb == 2) {
            adval = strtoll(pa, NULL, 10);
            bdval = strtoll(pb, NULL, 10);
            if (adval >= bdval) return 1;
            return 0;
        }
        return (strcasecmp(pa, pb) >= 0) ? 1 : 0;

    } else if (strcasecmp(cmpsym, "<") == 0) {
        valtypea = str_val_type(pa, lena);
        valtypeb = str_val_type(pb, lenb);
        if (valtypea == 1 && valtypeb == 1) {
            aival64 = strtoll(pa, NULL, 10);
            bival64 = strtoll(pb, NULL, 10);
            if (aival64 < bival64) return 1;
            return 0;
        } else if (valtypea == 2 && valtypeb == 2) {
            adval = strtoll(pa, NULL, 10);
            bdval = strtoll(pb, NULL, 10);
            if (adval < bdval) return 1;
            return 0;
        }
        return (strcasecmp(pa, pb) < 0) ? 1 : 0;

    } else if (strcasecmp(cmpsym, "<=") == 0) {
        valtypea = str_val_type(pa, lena);
        valtypeb = str_val_type(pb, lenb);
        if (valtypea == 1 && valtypeb == 1) {
            aival64 = strtoll(pa, NULL, 10);
            bival64 = strtoll(pb, NULL, 10);
            if (aival64 <= bival64) return 1;
            return 0;
        } else if (valtypea == 2 && valtypeb == 2) {
            adval = strtoll(pa, NULL, 10);
            bdval = strtoll(pb, NULL, 10);
            if (adval <= bdval) return 1;
            return 0;
        }
        return (strcasecmp(pa, pb) <= 0) ? 1 : 0;

    } else if (strcasecmp(cmpsym, "!=") == 0) {
        valtypea = str_val_type(pa, lena);
        valtypeb = str_val_type(pb, lenb);
        if (valtypea == 1 && valtypeb == 1) {
            aival64 = strtoll(pa, NULL, 10);
            bival64 = strtoll(pb, NULL, 10);
            if (aival64 != bival64) return 1;
            return 0;
        } else if (valtypea == 2 && valtypeb == 2) {
            adval = strtoll(pa, NULL, 10);
            bdval = strtoll(pb, NULL, 10);
            if (adval != bdval) return 1;
            return 0;
        }
        return (strcasecmp(pa, pb) == 0) ? 0 : 1;
 
    } else if (strcasecmp(cmpsym, "^~") == 0) {
        return (strncasecmp(pa, pb, strlen(pb)) == 0) ? 1 : 0;
 
    } else if (strcasecmp(cmpsym, "~") == 0) {
#ifdef UNIX
        memset(&regobj, 0, sizeof(regobj));
        regcomp(&regobj, pb, REG_EXTENDED);
        ret = regexec(&regobj, pa, 4, pmat, 0);
        regfree(&regobj);

        if (ret == 0) return 1;
        if (ret == REG_NOMATCH) return 0;
#endif
#if defined(_WIN32) || defined(_WIN64)
        regobj = pcre_compile(pb, 0, &errstr, &erroff, NULL);
        if (!regobj) return 0;

        ret = pcre_exec(regobj, NULL, pa, strlen(pa), 0, 0, ovec, 36);
        pcre_free(regobj);

        if (ret > 0) return 1;
        if (ret <= 0) return 0;
#endif
 
    } else if (strcasecmp(cmpsym, "~*") == 0) {
#ifdef UNIX
        memset(&regobj, 0, sizeof(regobj));
        regcomp(&regobj, pb, REG_EXTENDED | REG_ICASE);
 
        ret = regexec(&regobj, pa, 4, pmat, 0);
        regfree(&regobj);
 
        if (ret == 0) return 1;
        if (ret == REG_NOMATCH) return 0;
#endif
#if defined(_WIN32) || defined(_WIN64)
        regobj = pcre_compile(pb, PCRE_CASELESS, &errstr, &erroff, NULL);
        if (!regobj) return 0;

        ret = pcre_exec(regobj, NULL, pa, strlen(pa), 0, 0, ovec, 36);
        pcre_free(regobj);

        if (ret > 0) return 1;
        if (ret <= 0) return 0;
#endif
    }

    return 0;
}

/* if ( $request_header[content-type] == "text/html" ) */

static int script_if_objcmp_parse (void * vhsc, char * pbgn, int len, char ** pterm,
                                   char * pa, int palen, char * pcmp, char * pb, int pblen)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char       * pend = NULL;
    char       * poct = NULL;

    char       * avar = NULL;
    char       * bvar = NULL;
    int          alen = 0;
    int          blen = 0;

    char         cmpsym[8];
    int          cmplen = 0;

    if (pterm) *pterm = pbgn;

    if (!hsc) return 0;

    if (pbgn && len > 0) {
        pend = pbgn + len;

        pbgn = skipOver(pbgn, pend - pbgn, " \t\r\n\f\v", 6);
        if (pbgn > pend) {
            if (pterm) *pterm = pbgn;
            return 0;
        }
    }

    if (pa && palen > 0) {
        avar = pa; alen = palen;

    } else {
        poct = goto_symbol_end(pbgn, pend - pbgn);
        avar = pbgn; alen = poct - pbgn;

        if (pterm) *pterm = poct;

        pbgn = skipOver(poct, pend - poct, " \t\r\n\f\v", 6);
        if (pbgn > pend) {
            return 2;  //indicate only one obj
        }
    }

    if (pcmp) {
        str_secpy(cmpsym, sizeof(cmpsym)-1, pcmp, strlen(pcmp));
    } else {
        /* all kinds of comparing symbol: ==  !=  ~  ^~  ~*  >  <  >=  <= */
        for (poct = pbgn; poct < pend; poct++) {
            if (is_exp_char(*poct)) break;
            if (ISSPACE(*poct)) break;
        }
        cmplen = poct - pbgn;
        if (poct > pbgn)
            str_secpy(cmpsym, sizeof(cmpsym)-1, pbgn, poct-pbgn);
        else
            cmpsym[0] = '\0';

        pbgn = skipOver(poct, pend - poct, " \t\r\n\f\v", 6);
        if (pbgn > pend) {
            return 2;  //indicate only one obj
        }
    }
    cmplen = strlen(cmpsym);

    if (pa && palen > 0) {
        bvar = pa; blen = palen;

    } else {
        /* extracting the second variable */
        poct = goto_symbol_end(pbgn, pend - pbgn);
        bvar = pbgn; blen = poct - pbgn;

        if (pterm) *pterm = poct;
    }

    if (cmplen <= 0 || cmplen > 2) return 100;
    if (cmplen == 1 && (cmpsym[0] != '~' && cmpsym[0] != '>' && cmpsym[0] != '<'))
        return 101;
    if (cmplen == 2 && (cmpsym[0] != '=' || cmpsym[1] != '=') &&
        (cmpsym[0] != '!' || cmpsym[1] != '=') &&
        (cmpsym[0] != '^' || cmpsym[1] != '~') &&
        (cmpsym[0] != '~' || cmpsym[1] != '*') &&
        (cmpsym[0] != '>' || cmpsym[1] != '=') &&
        (cmpsym[0] != '<' || cmpsym[1] != '=')   )
    {
        return 102;
    }
 
    return script_if_objcmp(hsc, avar, alen, cmpsym, bvar, blen);
}

int script_if_condition_parse (void * vhsc, char * cond, int condlen, char ** pterm)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char         buf[4096];
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pval = NULL;
    char       * pexpend = NULL;

    int          condnum = 0;
    int          reverse = 0;
    int          condval = 0;
    int          condcmp = 0;  //0-none 1-and(&&) 2-or(||)

    int          ret = 0;

    if (!hsc) return 0;

    if (!cond) return 0;
    if (condlen < 0) condlen = strlen(cond);
    if (condlen <= 0) return 0;

    pbgn = cond;
    pend = cond + condlen;

    pbgn = skipOver(pbgn, condlen, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return 0;

    pexpend = rskipOver(pend-1, pend-pbgn, " \t\r\n\f\v", 6);
    pend = pexpend + 1;

    for ( ; pbgn < pend; ) {
        pbgn = skipOver(pbgn, pend-pbgn, " \t\r\n\f\v", 6);
        if (pbgn >= pend) return condval;

        if (pend - pbgn > 2 && pbgn[0] == '-' &&
            (pbgn[1] == 'f' || pbgn[1] == 'd' || pbgn[1] == 'e' || pbgn[1] == 'x'))
        {
            ret = script_if_file_parse(hsc, pbgn, pend-pbgn, &poct);
            if (reverse) ret = ret > 0 ? 0 : 1;

            if (condcmp == 1) condval = condval && ret;
            else if (condcmp == 2) condval = condval || ret;
            else condval = ret;

            pbgn = poct;
            condcmp = 0;
            reverse = 0;
            condnum++;
        }

        else if (pend - pbgn > 3 && pbgn[0] == '!' && pbgn[1] == '-' &&
                 (pbgn[2] == 'f' || pbgn[2] == 'd' || pbgn[2] == 'e' || pbgn[2] == 'x'))
        {
            ret = script_if_not_file_parse(hsc, pbgn, pend-pbgn, &poct);
            if (reverse) ret = ret > 0 ? 0 : 1;

            if (condcmp == 1) condval = condval && ret;
            else if (condcmp == 2) condval = condval || ret;
            else condval = ret;

            pbgn = poct;
            condcmp = 0;
            reverse = 0;
            condnum++;

        } else if (pbgn[0] == '(') {
            poct = skipToPeer(pbgn, pend-pbgn, '(', ')');
            if (*poct != ')') return condval;

            pbgn = skipOver(pbgn+1, poct-pbgn-1, " \t\r\n\f\v", 6);
            if (pbgn >= poct) {
                pbgn = poct + 1;
                continue;
            }

            ret = script_if_condition_parse(hsc, pbgn, poct-pbgn, &pval);
            if (ret >= 2) { /* the content in bracket will be considered as one variable-object */
                /* if ( ($request_path) != "/opt/hls.html" ) */
                /*                    ^                      */
                /*                    |                      */
                ret = script_if_objcmp_parse(hsc, poct+1, pend-poct-1, &pval, pbgn, pval-pbgn, NULL, NULL, 0);
                if (ret >= 2) {
                    pbgn = pval;
                    condcmp = 0;
                    reverse = 0;
                    condnum++;
                    continue;
                }
            }

            pbgn = poct + 1;

            if (ret == 0 || ret == 1) {
                if (reverse) ret = ret > 0 ? 0 : 1;

                if (condcmp == 1) condval = condval && ret;
                else if (condcmp == 2) condval = condval || ret;
                else condval = ret;

                condcmp = 0;
                reverse = 0;
                condnum++;
            }

        } else if (pbgn[0] == '!') {
            reverse = 1;
            pbgn++;
            continue;

        } else {
            ret = script_if_objcmp_parse(hsc, pbgn, pend-pbgn, &poct, NULL, 0, NULL, NULL, 0);
            if (ret == 2) { //only one varobj, eg. if (($request_path) != "/opt/abc.txt") {
                pval = skipOver(poct, pend-poct, " \t\r\n\f\v", 6);
                if (pval >= pend) {
                    if (pterm) *pterm = poct;
                    if (condnum < 1) return 2;
                }

                get_var_value(hsc, pbgn, poct-pbgn, buf, sizeof(buf)-1, 1);
                pval = trim_var(buf, strlen(buf));

                if (strlen(pval) <= 0 ||
                    strcasecmp(pval, "0") == 0 ||
                    strcasecmp(pval, "false") == 0 ||
                    strcasecmp(pval, "no") == 0)
                    ret = 0;
                else ret = 1;

                if (condnum > 0) {
                } else {
                }
            }

            if (reverse) ret = ret > 0 ? 0 : 1;

            if (condcmp == 1) condval = condval && ret;
            else if (condcmp == 2) condval = condval || ret;
            else condval = ret;

            pbgn = poct;
            condcmp = 0;
            reverse = 0;
            condnum++;
        }

        pbgn = skipOver(pbgn, pend-pbgn, " \t\r\n\f\v", 6);
        if (pbgn >= pend) break;

        if (pend - pbgn >= 2) {
            if (pbgn[0] == '&' && pbgn[1] == '&') {
                condcmp = 1;  // AND operation
                pbgn += 2;
            } else if (pbgn[0] == '|' && pbgn[1] == '|') {
                condcmp = 2;  // OR operation
                pbgn += 2;
            } else if (adf_tolower(pbgn[0]) == 'o' && adf_tolower(pbgn[1]) == 'r') {
                condcmp = 2;  // OR operation
                pbgn += 2;
            }
        }
        if (pend - pbgn >= 3) {
            if (adf_tolower(pbgn[0]) == 'a' && adf_tolower(pbgn[1]) == 'n' && adf_tolower(pbgn[2]) == 'd') {
                condcmp = 1;  // AND operation
                pbgn += 3;
            }
        }

        if (condcmp == 0) break;
    }

    return condval;
}

char * script_if_parse (void * vhsc, char * p, int slen)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pval = NULL;
    char       * pexpend = NULL;
    int          condval = 0;
    uint8        ifbody_exec = 0;

    if (!hsc) return p;

    if (!p) return NULL;
    if (slen < 0) slen = strlen(p);
    if (slen <= 2) return p;

    if (str_ncmp(p, "if", 2) != 0) return p;

    /* if (cond) {...} */
    pbgn = p + 2;
    pend = p + slen;

    while (pbgn < pend) {
        condval = 0;

        /* skip 'if' and following space, to condition */
        poct = skipOver(pbgn, pend-pbgn, " \t\r\n\f\v", 6);
        if (poct >= pend || *poct != '(') {
            /* condition invalid in 'if (cond)' expression, find the end of the expression */
            pbgn = skipTo(poct, pend-poct, ";", 1);
            return pbgn;
        }

        pexpend = skipTo(poct, pend-poct, ";", 1);
        pval = skipToPeer(poct, pexpend-poct, '(', ')');
        if (*pval != ')') {
            return pexpend;
        }

        if (!ifbody_exec) {
            condval = script_if_condition_parse(hsc, poct + 1, pval - poct - 1, NULL);
        }

        /* skip the condition block, stop to the if body */
        pbgn = skipOver(pval+1, pend-pval-1, " \t\r\n\f\v", 6);
        if (pbgn >= pend) return pbgn;

        if (*pbgn == '{') {
            /* if (cond) {  ... }  find { and assign to pbgn */
            pval = skipToPeer(pbgn, pend-pbgn, '{', '}');
            if (!ifbody_exec && condval) {
                http_script_parse_exec(hsc, pbgn + 1, pval - pbgn - 1);
                ifbody_exec = 1;
            }

            if (*pval == '}') pval++;

        } else if (pend - pbgn >= 2 && str_ncmp(pbgn, "if", 2) == 0) {
            /* if (cond) if (cond2) {... } */
            pval = script_if_parse(hsc, pbgn, pend-pbgn);

        } else {
            /* if (cond) ...; find expression end flag ; */
            pval = skipTo(pbgn, pend-pbgn, ";", 1);
            if (!ifbody_exec && condval) {
                http_script_parse_exec(hsc, pbgn, pval - pbgn);
                ifbody_exec = 1;
            }
    
            if (*pval == ';') pval++;
        }

        if (hsc->exitflag)
            return pval;

        /* now skip all 'else if' and 'else', look for the end of 'if' expression */

        /* if (cond) { ... } else { ... }
           if (cond) { ... } else if { ... }
           if (cond) { ... } ...   */
        pbgn = skipOver(pval, pend-pval, "; \t\r\n\f\v", 7);
        if (pbgn >= pend) return pbgn;
 
        /* else if (cond) { ... }  or else { ... } */
        if (pend - pbgn >= 4 && str_ncmp(pbgn, "else", 4) == 0) {
            poct = skipOver(pbgn+4, pend-pbgn-4, " \t\r\n\f\v", 6);
            if (poct >= pend) return poct;
 
            if (pend - poct > 2 && str_ncmp(poct, "if", 2) == 0) {
                /* else if (...) */
                pbgn = poct + 2;
                continue;
 
            } else if (pend - poct > 1 && *poct == '{') {
                /* else { ... }  */
                pval = skipToPeer(poct, pend-poct, '{', '}');
                if (!ifbody_exec && condval == 0) {
                    http_script_parse_exec(hsc, poct + 1, pval - poct - 1);
                    ifbody_exec = 1;
                }
                if (*pval == '}') pval++;
 
                return pval;
 
            } else {
                /* else ... */
                pval = skipTo(poct, pend-poct, ";", 1);
                if (!ifbody_exec && condval == 0) {
                    http_script_parse_exec(hsc, poct, pval - poct);
                    ifbody_exec = 1;
                }
                if (*pval == ';') pval++;
 
                return pval;
            }
 
        } else {
            /* no else existing, if expression end! */
            return pbgn;
        }
    } 

    return pbgn;
}

char * script_assignment_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    char         varname[512];
    char         value[4096];

    if (!hsc) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;

    /* $forward_addr = $remote_addr;
       $forward_addr = "114.247.194.188";  */

    pbgn = p;
    pend = p + len;

    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;

    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (*pbgn != '$') return pexpend;

    poct = goto_symbol_end(pbgn, pexpend - pbgn);

    get_var_name(pbgn, poct-pbgn, varname, sizeof(varname)-1);

    pbgn = skipOver(poct, pend-poct, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;

    /*  =  */
    for (poct = pbgn; poct < pexpend; poct++) {
        if (ISSPACE(*poct)) break;
        if (is_exp_char(*poct)) break;
    }

    if (*pbgn != '=' || poct - pbgn > 1) {
        return pexpend;
    }

    pbgn = skipOver(poct, pend-poct, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;

    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, value, sizeof(value)-1, 1);

    http_msg_var_set(hsc->msg, varname, value, strlen(value));

    return pexpend;
}

char * script_set_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    char         varname[512];
    char         value[4096];
 
    if (!hsc) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;
 
    /* set $forward_addr $remote_addr;
       set $forward_addr  "114.247.194.188";  */
 
    pbgn = p;
    pend = p + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;
 
    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 3) return pexpend;

    if (strncasecmp(pbgn, "set", 3) != 0) return pexpend;
    pbgn += 3;

    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting variable name */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_name(pbgn, poct-pbgn, varname, sizeof(varname)-1);
 
    pbgn = skipOver(poct, pend-poct, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting variable value */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, value, sizeof(value)-1, 1);
 
    http_msg_var_set(hsc->msg, varname, value, strlen(value));
 
    return pexpend;
}

char * script_return_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    int          ret = 0;
 
    if (!hsc) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;
 
    /* return $forward_addr;
       return "114.247.194.188";  */
 
    pbgn = p;
    pend = p + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;
 
    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 6) return pexpend;
 
    if (strncasecmp(pbgn, "return", 6) != 0) return pexpend;
    pbgn += 6;

    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting variable value */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    if (poct > pbgn) {
        /* get rid of ' or " on the leading or tail side */
        poct = rskipOver(poct-1, poct-pbgn, " \t\r\n\f\v", 6);
        if (poct >= pbgn) {
            if ((*pbgn == '"' || *pbgn == '\'') && *poct == *pbgn) {
                pbgn++;
            } else poct++;
        }
    }

    ret = http_var_copy(hsc->msg, pbgn, poct-pbgn, NULL,
                        0, NULL, 0, hsc->vname, hsc->vtype);
    if (ret > 0) {
        hsc->retval = kalloc(ret + 1);
        hsc->retvallen = ret;

        http_var_copy(hsc->msg, pbgn, poct-pbgn, hsc->retval, ret,
                      NULL, 0, hsc->vname, hsc->vtype);
    }
 
    hsc->exitflag = 1;

    return pexpend;
}

char * script_reply_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pval = NULL;
    char       * pexpend = NULL;
    int          status = 0;
    int          ret = 0;
    int          vallen = 0;
 
    if (!hsc) return p;
 
    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;
 
    /* reply status_code [ URL or MsgBody ] */
 
    pbgn = p;
    pend = p + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;
 
    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 5) return pexpend;
 
    if (strncasecmp(pbgn, "reply", 5) != 0) return pexpend;
    pbgn += 5;
 
    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting variable value */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);

    /* check if all octets are digits */
    for (pval = pbgn; pval < poct; pval++) {
        if (!isdigit(*pval)) return pexpend;
    }

    status = str_to_int(pbgn, poct-pbgn, 10, NULL);

    /* extracting redirect URL or MSG body */
    pval = NULL;
    pbgn = skipOver(poct, pexpend-poct, " \t\r\n\f\v", 6);
    poct = goto_symbol_end(pbgn, pexpend - pbgn);

    if (poct > pbgn) {
        /* get rid of ' or " on the leading or tail side */
        poct = rskipOver(poct-1, poct-pbgn, " \t\r\n\f\v", 6);
        if (poct >= pbgn) {
            if ((*pbgn == '"' || *pbgn == '\'') && *poct == *pbgn) {
                pbgn++;
            } else poct++;
        }
    }

    if (pbgn < pexpend && poct > pbgn) {
        ret = http_var_copy(hsc->msg, pbgn, poct-pbgn, NULL, 0,
                            NULL, 0, hsc->vname, hsc->vtype);
        if (ret > 0) {
            pval = kalloc(ret + 1);
            vallen = ret;
 
            vallen = http_var_copy(hsc->msg, pbgn, poct-pbgn, pval, ret,
                                   NULL, 0, hsc->vname, hsc->vtype);
            if (vallen >= 2 && (pval[0] == '"' || pval[0] == '\'')) {
                if (pval[vallen-1] == pval[0]) {
                    pval++;
                    vallen -= 2;
                }
            }
        }
    }

    if (status >= 300 && status < 400) {
        if (pval && vallen > 0) {
            msg->RedirectReply(msg, status, pval);
        } else {
            return pexpend;
        }

    } else {
        if (pval && vallen > 0) {
            msg->AddResContent(msg, pval, vallen);
        }
        msg->SetStatus(msg, status, NULL);
        msg->Reply(msg);
    }

    if (pval) kfree(pval);

    hsc->exitflag = 1;
    hsc->replied = 1;

    return pexpend;
}

char * script_rewrite_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pval = NULL;
    char       * pexpend = NULL;
    char         regstr[512];
    char         replace[2048];
    char         flag[64];
    char         dsturi[2048];
    int          ret, dstlen;
    ckstr_t      pmatstr[32];
    int          i, matnum = 0;
#ifdef UNIX
    char         uri[2048];
    regex_t      regobj = {0};
    regmatch_t   pmat[32];
#endif
#if defined(_WIN32) || defined(_WIN64)
    pcre       * regobj = NULL;
    char       * errstr = NULL;
    int          erroff = 0;
    int          ovec[36];
#endif

    if (!hsc) return p;
 
    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;
 
    /* rewrite regex replacement [flag] */
 
    pbgn = p;
    pend = p + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;
 
    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 7) return pexpend;
 
    if (strncasecmp(pbgn, "rewrite", 7) != 0) return pexpend;
    pbgn += 7;
 
    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting regex string */
    regstr[0] = '\0';
    pval = poct = skipQuoteTo(pbgn, pexpend - pbgn, " \t\r\n\f\v", 6);

    /* get rid of ' or " on the leading or tail side */
    if (poct > pbgn) {
        poct = rskipOver(poct-1, poct-pbgn, " \t\r\n\f\v", 6);
        if (poct >= pbgn) {
            if ((*pbgn == '"' || *pbgn == '\'') && *poct == *pbgn) {
                pbgn++;
            } else poct++;
        }
    }

    if (poct > pbgn) {
        str_secpy(regstr, sizeof(regstr)-1, pbgn, poct-pbgn);
    }

    /* extracting replacement string */
    pbgn = skipOver(pval, pexpend-pval, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;

    replace[0] = '\0';
    pval = poct = skipQuoteTo(pbgn, pexpend - pbgn, " \t\r\n\f\v", 6);

    /* get rid of ' or " on the leading or tail side */
    if (poct > pbgn) {
        poct = rskipOver(poct-1, poct-pbgn, " \t\r\n\f\v", 6);
        if (poct >= pbgn) {
            if ((*pbgn == '"' || *pbgn == '\'') && *poct == *pbgn) {
                pbgn++;
            } else poct++;
        }
    }

    if (poct > pbgn) {
        str_secpy(replace, sizeof(replace)-1, pbgn, poct-pbgn);
    }

    flag[0] = '\0';

    /* extracting flag string */
    pbgn = skipOver(pval, pexpend-pval, " \t\r\n\f\v", 6);
    if (pbgn < pexpend) {
        pval = poct = skipQuoteTo(pbgn, pexpend - pbgn, " \t\r\n\f\v", 6);
         
        /* get rid of ' or " on the leading or tail side */ 
        if (poct > pbgn) {
            poct = rskipOver(poct-1, poct-pbgn, " \t\r\n\f\v", 6);
            if (poct >= pbgn) {
                if ((*pbgn == '"' || *pbgn == '\'') && *poct == *pbgn) {
                    pbgn++;
                } else poct++;
            }
        }
     
        if (poct > pbgn) {
            str_secpy(flag, sizeof(flag)-1, pbgn, poct-pbgn);
        }
    }

#ifdef UNIX
    if (regcomp(&regobj, regstr, REG_EXTENDED | REG_ICASE) != 0) {
        regfree(&regobj);
        return pexpend;
    }

    str_secpy(uri, sizeof(uri)-1, msg->req_path, msg->req_pathlen);

    ret = regexec(&regobj, uri, 32, pmat, 0);
    if (ret == 0) {
        for (i = 0, matnum = 0; i < 32; i++) {
            if (pmat[i].rm_so >= 0) {
                pmatstr[matnum].p = uri + pmat[i].rm_so;
                pmatstr[matnum].len = pmat[i].rm_eo - pmat[i].rm_so;
                matnum++;
                continue;
            }
            break;
        }
        regfree(&regobj);
    } else {
        regfree(&regobj);
        return pexpend;
    }
#endif
#if defined(_WIN32) || defined(_WIN64)
    regobj = pcre_compile(regstr, PCRE_CASELESS, &errstr, &erroff, NULL);
    if (!regobj) return pexpend;

    ret = pcre_exec(regobj, NULL, msg->req_path, msg->req_pathlen, 0, 0, ovec, 36);
    if (ret <= 0) {
        pcre_free(regobj);
        return pexpend;
    }

    for (i = 0, matnum = 0; i < ret; i++) {
        pmatstr[matnum].p = msg->req_path + ovec[2 * i];
        pmatstr[matnum].len = ovec[2 * i + 1] - ovec[2 * i];
        matnum++;
    }

    pcre_free(regobj);
#endif

    dsturi[0] = '\0';
    http_var_copy(msg, replace, strlen(replace), dsturi, sizeof(dsturi)-1,
                  pmatstr, matnum, hsc->vname, hsc->vtype);
    if ((dstlen = strlen(dsturi)) <= 0) return pexpend;

    if (dsturi[dstlen - 1] != '?') {
        if (memchr(dsturi, '?', dstlen) == NULL) 
            strcat(dsturi, "?");
        else
            strcat(dsturi, "&");
        dstlen += 1;
        str_secpy(dsturi + dstlen, sizeof(dsturi)-1-dstlen,
                  msg->req_query, msg->req_querylen);
        dstlen = strlen(dsturi);

    } else{
        dsturi[dstlen - 1] = '\0';
        dstlen--;
    }

    if (strcasecmp(flag, "redirect") == 0) {
        msg->RedirectReply(msg, 302, dsturi);
        hsc->exitflag = 1;
        hsc->replied = 1;
        return pexpend;

    } else if (strcasecmp(flag, "permanent") == 0) {
        msg->RedirectReply(msg, 301, dsturi);
        hsc->exitflag = 1;
        hsc->replied = 1;
        return pexpend;

    } 

    if (strcasecmp(flag, "last") == 0) {
        msg->SetDocURL(msg, dsturi, dstlen, 0, 0);
        hsc->exitflag = 1;

    } else if (strcasecmp(flag, "forward") == 0 || strcasecmp(flag, "proxy") == 0) {
        /* dsturi must be an absolute URL, do not re-instantizte location */
        if (msg->SetDocURL(msg, dsturi, dstlen, 0, 1) > 0)
            msg->req_url_type = 1;
        msg->proxied = 1;

    } else if (strcasecmp(flag, "break") == 0) {
        /* do not re-instantiate location after setting DocURI, go on executing next line */
        msg->SetDocURL(msg, dsturi, dstlen, 0, 1);

    } else { //no flag
        /* do not re-intantiate location after setting DocURI.
           when all scripts executed, re-intantizte location at last */
        msg->SetDocURL(msg, dsturi, dstlen, 0, 1);
        hsc->reloc = 1;
    }
 
    return pexpend;
}

char * script_add_req_header_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    char         name[512];
    char         value[4096];
 
    if (!hsc) return p;
 
    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;
 
    /* addReqHeader x-forward-ip $remote_addr;
       addReqHeader x-Real-IP  "114.247.194.188";  */
 
    pbgn = p;
    pend = p + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;
 
    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 12) return pexpend;
 
    if (strncasecmp(pbgn, "addReqHeader", 12) != 0) return pexpend;
    pbgn += 12;
 
    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting header name */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, name, sizeof(name)-1, 0);
 
    pbgn = skipOver(poct, pend-poct, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting header value */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, value, sizeof(value)-1, 1);

    msg->AddReqHdr(msg, name, strlen(name), value, strlen(value));

    return pexpend;
}

char * script_add_res_header_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    char         name[512];
    char         value[4096];
 
    if (!hsc) return p;
 
    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;
 
    /* addResHeader x-forward-ip $remote_addr;
       addResHeader x-Real-IP  "114.247.194.188";  */
 
    pbgn = p;
    pend = p + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;
 
    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 12) return pexpend;
 
    if (strncasecmp(pbgn, "addResHeader", 12) != 0) return pexpend;
    pbgn += 12;
 
    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting header name */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, name, sizeof(name)-1, 0);
 
    pbgn = skipOver(poct, pend-poct, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting header value */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, value, sizeof(value)-1, 1);
 
    msg->AddResHdr(msg, name, strlen(name), value, strlen(value));
 
    return pexpend;
}

char * script_del_req_header_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    char         name[512];
 
    if (!hsc) return p;
 
    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;
 
    /* delReqHeader x-forward-ip;
       delReqHeader x-Real-IP;  */
 
    pbgn = p;
    pend = p + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;
 
    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 12) return pexpend;
 
    if (strncasecmp(pbgn, "delReqHeader", 12) != 0) return pexpend;
    pbgn += 12;
 
    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting header name */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, name, sizeof(name)-1, 0);

    msg->DelReqHdr(msg, name, strlen(name));

    return pexpend;
}
 
char * script_del_res_header_parse (void * vhsc, char * p, int len)
{ 
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    char         name[512];
 
    if (!hsc) return p;
 
    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;
 
    /* delResHeader x-forward-ip;
       delResHeader x-Real-IP;  */ 
     
    pbgn = p;   
    pend = p + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;
 
    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 12) return pexpend;
 
    if (strncasecmp(pbgn, "delResHeader", 12) != 0) return pexpend;
    pbgn += 12;
 
    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting header name */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, name, sizeof(name)-1, 0);
 
    msg->DelResHdr(msg, name, strlen(name));
 
    return pexpend;
}

char * script_add_res_body_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    HeaderUnit * punit = NULL;
    int64        val64 = 0;
    int64        addlen = 0;

    if (!hsc) return p;

    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;

    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;

    /* addResBody "added body content";
       insert the content to the head of response body */

    pbgn = p;
    pend = p + len;

    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;

    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 12) return pexpend;

    if (strncasecmp(pbgn, "addResBody", 10) != 0) return pexpend;
    pbgn += 10;

    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;

    /* extracting body value */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);

    poct = rskipOver(poct-1, poct-pbgn, " \t\r\n\f\v", 6);
    if (poct < pbgn) return pexpend;

    if ((*pbgn == '"' || *pbgn == '\'') && *poct == *pbgn) {
        pbgn++; poct--;
    }

    if (poct >= pbgn) {
        addlen = poct - pbgn + 1;
        addlen = chunk_prepend_strip_buffer(msg->res_body_chunk, pbgn, addlen, "\r\n\t\b\f\v'\"\\/", 10, 0);
        if (addlen < 0) addlen = 0;

        if (msg->res_body_flag == BC_CONTENT_LENGTH) {
            punit = http_header_get(msg, 1, "Content-Length", 14);
            if (punit) {
                val64 = strtoll(punit->value, NULL, 10);
                val64 += addlen;

                http_header_del(msg, 1, "Content-Length", 14);
            } else {
                val64 = addlen;
            }
            http_header_append_int64(msg, 1, "Content-Length", 14, val64);

        } else if (msg->res_body_flag == BC_TE) {
            if (http_header_get(msg, 1, "Transfer-Encoding", -1) == NULL) {
                http_header_append(msg, 1, "Transfer-Encoding", 17, "chunked", 7);
            }
        }
    }

    return pexpend;
}

char * script_append_res_body_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    HeaderUnit * punit = NULL;
    int64        val64 = 0;
    int64        addlen = 0;

    if (!hsc) return p;

    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;

    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;

    /* appendResBody "appended body content";
       insert the content to the tail of response body */

    pbgn = p;
    pend = p + len;

    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;

    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 12) return pexpend;

    if (strncasecmp(pbgn, "appendResBody", 13) != 0) return pexpend;
    pbgn += 13;

    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;

    /* extracting body value */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);

    poct = rskipOver(poct-1, poct-pbgn, " \t\r\n\f\v", 6);
    if (poct < pbgn) return pexpend;

    if ((*pbgn == '"' || *pbgn == '\'') && *poct == *pbgn) {
        pbgn++; poct--;
    }

    if (poct >= pbgn) {
        addlen = poct - pbgn + 1;
        addlen = chunk_append_strip_buffer(msg->res_body_chunk, pbgn, addlen, "\r\n\t\b\f\v'\"\\/", 10);
        if (addlen < 0) addlen = 0;

        if (msg->res_body_flag == BC_CONTENT_LENGTH) {
            punit = http_header_get(msg, 1, "Content-Length", 14);
            if (punit) {
                val64 = strtoll(punit->value, NULL, 10);
                val64 += addlen;

                http_header_del(msg, 1, "Content-Length", 14);
            } else {
                val64 = addlen;
            }
            http_header_append_int64(msg, 1, "Content-Length", 14, val64);

        } else if (msg->res_body_flag == BC_TE) {
            if (http_header_get(msg, 1, "Transfer-Encoding", -1) == NULL) {
                http_header_append(msg, 1, "Transfer-Encoding", 17, "chunked", 7);
            }
        }

        if (poct) kfree(poct);
    }

    return pexpend;
}

char * script_add_file_to_res_body_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    char         fpath[2048];
    char         value[1024];
    HeaderUnit * punit = NULL;
    int64        fsize = 0;
    int64        val64 = 0;

    if (!hsc) return p;

    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;

    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;

    /* addFile2ResBody /abc/def.js;
       addFile2ResBody $file_path */

    pbgn = p;
    pend = p + len;

    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;

    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 12) return pexpend;

    if (strncasecmp(pbgn, "addFile2ResBody", 15) != 0) return pexpend;
    pbgn += 15;

    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;

    /* extracting file path to be appended to body */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, value, sizeof(value)-1, 1);

    poct = str_trim(value);
    if (!poct || strlen(poct) <= 0)
        return pexpend;

    if (poct[0] == '/') {
        sprintf(fpath, "%s", msg->GetRootPath(msg));
        sprintf(fpath + strlen(fpath), "%s", poct);
    } else {
        fpath[0] = '\0';
        msg->GetRealPath(msg, fpath, sizeof(fpath)-1);
        sprintf(fpath + strlen(fpath), "%s", poct);
    }

    if (msg->res_body_flag == BC_TE) val64 = 2 * 1024 * 1024;
    else val64 = 0;

    fsize = chunk_prepend_file(msg->res_body_chunk, fpath, val64);
    if (fsize > 0) {
        if (msg->res_body_flag == BC_CONTENT_LENGTH) {
            punit = http_header_get(msg, 1, "Content-Length", 14);
            if (punit) {
                val64 = strtoll(punit->value, NULL, 10);
                val64 += fsize;

                http_header_del(msg, 1, "Content-Length", 14);
            } else {
                val64 = fsize;
            }
            http_header_append_int64(msg, 1, "Content-Length", 14, val64);

        } else if (msg->res_body_flag == BC_TE) {
            if (http_header_get(msg, 1, "Transfer-Encoding", -1) == NULL) {
                http_header_append(msg, 1, "Transfer-Encoding", 17, "chunked", 7);
            }
        }
    }

    return pexpend;
}

char * script_append_file_to_res_body_parse (void * vhsc, char * p, int len)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    char         fpath[2048];
    char         value[1024];
    HeaderUnit * punit = NULL;
    int64        fsize = 0;
    int64        val64 = 0;
 
    if (!hsc) return p;
 
    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;
 
    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;
 
    /* appendFile2ResBody /abc/def.js;
       appendFile2ResBody $file_path */
 
    pbgn = p;
    pend = p + len;
 
    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;
 
    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 12) return pexpend;
 
    if (strncasecmp(pbgn, "appendFile2ResBody", 18) != 0) return pexpend;
    pbgn += 18;
 
    pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
    if (pbgn >= pexpend) return pexpend;
 
    /* extracting file path to be appended to body */
    poct = goto_symbol_end(pbgn, pexpend - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, value, sizeof(value)-1, 1);

    poct = str_trim(value);
    if (!poct || strlen(poct) <= 0)
        return pexpend;

    if (poct[0] == '/') {
        sprintf(fpath, "%s", msg->GetRootPath(msg));
        sprintf(fpath + strlen(fpath), "%s", poct);
    } else {
        fpath[0] = '\0';
        msg->GetRealPath(msg, fpath, sizeof(fpath)-1);
        sprintf(fpath + strlen(fpath), "%s", poct);
    }

    if (msg->res_body_flag == BC_TE) val64 = 2 * 1024 * 1024;
    else val64 = 0;

    fsize = chunk_append_file(msg->res_body_chunk, fpath, val64);
    if (fsize > 0) {
        if (msg->res_body_flag == BC_CONTENT_LENGTH) {
            punit = http_header_get(msg, 1, "Content-Length", 14);
            if (punit) {
                val64 = strtoll(punit->value, NULL, 10);
                val64 += fsize;

                http_header_del(msg, 1, "Content-Length", 14);
            } else {
                val64 = fsize;
            }
            http_header_append_int64(msg, 1, "Content-Length", 14, val64);

        } else if (msg->res_body_flag == BC_TE) {
            if (http_header_get(msg, 1, "Transfer-Encoding", -1) == NULL) {
                http_header_append(msg, 1, "Transfer-Encoding", 17, "chunked", 7);
            }
        }
    }

    return pexpend;
}

char * script_try_files_parse (void * vhsc, char * p, int len)
{ 
    HTTPScript * hsc = (HTTPScript *)vhsc;
    HTTPMsg    * msg = NULL;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    char         name[2048];
    int          namelen = 0;
    char         path[4092];
    uint8        lastitem = 0;
    int          status = 0;
    HTTPHost   * phost = NULL;
    HTTPLoc    * ploc = NULL;

    if (!hsc) return p;

    msg = (HTTPMsg *)hsc->msg;
    if (!msg) return p;

    if (!p) return NULL;
    if (len < 0) len = strlen(p);
    if (len <= 2) return p;

    /* try_files file1 file2 ... uri;;
       or try_files file1 file2 ... =code;  */ 

    pbgn = p;   
    pend = p + len;

    pbgn = skipOver(pbgn, len, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return pbgn;

    pexpend = skipQuoteTo(pbgn, pend-pbgn, ";", 1);
    if (pexpend - pbgn < 12) return pexpend;

    if (strncasecmp(pbgn, "try_files", 9) != 0) return pexpend;
    pbgn += 9;

    while (pbgn < pend) {
        pbgn = skipOver(pbgn, pexpend-pbgn, " \t\r\n\f\v", 6);
        if (pbgn >= pexpend) return pexpend;

        /* extracting file from list to check if existing or not */
        poct = goto_symbol_end(pbgn, pexpend - pbgn);

        name[0] = '\0';
        get_var_value(hsc, pbgn, poct-pbgn, name, sizeof(name)-1, 1);
        namelen = strlen(name); 

        pbgn = skipOver(poct, pexpend-poct, " \t\r\n\f\v", 6);
        if (pbgn >= pexpend) {
            lastitem = 1;
        }

        if (namelen <= 0) continue;

        if (name[0] == '=') {
            status = str_to_int(name+1, namelen-1, 10, NULL);

            msg->SetStatus(msg, status, NULL);
            msg->Reply(msg);

            hsc->exitflag = 1;
            hsc->replied = 1;
            break;

        } else if (name[0] == '@') {
            /* consequently, internally redirect to another location within same host */
            phost = (HTTPHost *)msg->phost;
            if (!phost) continue;

            ploc = ht_get(phost->exact_loc_table, name);
            if (ploc) {
                msg->ploc = ploc;

                msg->matchnum = 1;
                msg->matchstr[0].p = msg->docuri->path;
                msg->matchstr[0].len = msg->docuri->pathlen;
            }

        } else {
            if (lastitem) {
                msg->SetDocURL(msg, name, namelen, 0, 0);
                break;
            } 

            if (msg->GetLocFile(msg, name, namelen, NULL, 0, path, sizeof(path)-1) > 0) {
                msg->SetDocURL(msg, path, strlen(path), 0, 0);
                break;
            }
        }
    }

    return pexpend;
}

int http_script_parse_exec (void * vhsc, char * sc, int sclen)
{
    HTTPScript   * hsc = (HTTPScript *)vhsc;
    char         * pbgn = NULL;
    char         * pend = NULL;
    char         * poct = NULL;
    int            len = 0;
    ScriptParser * parser = NULL;

    if (!hsc) return -1;

    if (!sc) {
        sc = hsc->script;
        sclen = hsc->scriptlen;
    }

    if (!sc) return -2;
    if (sclen < 0) sclen = strlen(sc);
    if (sclen <= 0) return -3;

    pbgn = sc;
    pend = sc + sclen;

    while (pbgn < pend && !hsc->exitflag && !hsc->replied) {

        pbgn = skipOver(pbgn, pend-pbgn, "; \t\r\n\f\v", 7);
        if (pbgn >= pend) break;

        /* skip the Comment lines (prefix #) or blocks */
        if (*pbgn == '#') {
            pbgn = skipTo(pbgn, pend-pbgn, "\r\n", 2);
            continue;
        } else if (pbgn[0] == '/' && pbgn[1] == '*') {
            pbgn += 2;

            //find the comment end * and  /
            for (poct = pbgn; poct < pend; ) {
                poct = skipTo(poct, pend-poct, "*", 1);
                if (poct < pend - 1 && poct[1] != '/') {
                    poct++;
                    continue;
                } else break;
            }

            if (poct >= pend - 1) {
                pbgn = poct;
            } else if (poct[0] == '*' && poct[1] == '/') {
                pbgn = poct + 2;
            }
            continue;
        }

        if (*pbgn == '$') { //var $tmp = 1;
            poct = script_assignment_parse(hsc, pbgn, pend-poct);
            if (!poct) return -100;

            pbgn = poct;
            continue;
        }

        for (poct = pbgn, len = 0; poct < pend; poct++, len++) {
            if (len == 0 && !is_var_char(*poct)) break;
            if (len > 0 && !is_var_char(*poct) && !isdigit(*poct)) break;
        }

        len = poct - pbgn;

        parser = script_parser_get(pbgn, len);
        if (parser) {
            poct = (*parser)(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;

            pbgn = poct;
            continue;
        }

        /* unknown token, find the end flag of the expression */
        pbgn = skipTo(poct, pend-poct, ";", 1);
        continue;
    }

    return 0;
}

int http_script_segment_exec (void * vmsg, char * psc, int sclen, 
                              char ** pval, int * vallen, char * vname, int vtype)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPScript   hsc = {0};
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    int          ret = 0;

    if (pval) *pval = NULL;
    if (vallen) *vallen = 0;

    if (!msg) return -1;

    pbgn = psc;
    pend = psc + sclen;

    poct = sun_find_string(pbgn, pend-pbgn, "<script>", 8, NULL);
    if (poct) {
        pbgn = poct + 8;
        poct = sun_find_string(pbgn, pend-pbgn, "</script>", 9, NULL);
        if (poct) pend = poct;
    }

    http_script_init(&hsc, msg, pbgn, pend-pbgn, 0, vname, vtype);

    ret = http_script_parse_exec(&hsc, pbgn, pend-pbgn);
    if (ret >= 0 && pval) {
        *pval = hsc.retval;
        hsc.retval = NULL;
    }
    if (vallen) *vallen = hsc.retvallen;

    http_script_free(&hsc);

    return 0;
}


int http_script_exec (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPScript   hsc;
    HTTPListen * hl = NULL;
    HTTPHost   * host = NULL;
    HTTPLoc    * ploc = NULL;
    int          i, num;
    ckstr_t    * psc = NULL;
    uint8        reloc = 0;
    uint8        replied = 0;

    if (!msg) return -1;

    memset(&hsc, 0, sizeof(hsc));

    hl = (HTTPListen *)msg->hl;
    if (hl) {
        num = arr_num(hl->script_list);
 
        for (i = 0; i < num; i++) {
            psc = arr_value(hl->script_list, i);
            if (!psc || !psc->p || psc->len <= 0)
                continue;
 
            http_script_init(&hsc, msg, psc->p, psc->len, 1, NULL, 0);
 
            http_script_parse_exec(&hsc, psc->p, psc->len);
            reloc = hsc.reloc;
            replied = hsc.replied;
 
            http_script_free(&hsc);
 
            if (replied) return 0;
 
            if (reloc) {
                http_loc_instance(msg);
                return 0;
            }
        }
    }

    host = (HTTPHost *)msg->phost;
    if (host) {
        num = arr_num(host->script_list);

        for (i = 0; i < num; i++) {
            psc = arr_value(host->script_list, i);
            if (!psc || !psc->p || psc->len <= 0)
                continue;

            http_script_init(&hsc, msg, psc->p, psc->len, 2, NULL, 0);

            http_script_parse_exec(&hsc, psc->p, psc->len);
            reloc = hsc.reloc;
            replied = hsc.replied;

            http_script_free(&hsc);

            if (replied) return 0;

            if (reloc) {
                http_loc_instance(msg);
                return 0;
            }
        }
    }

    ploc = (HTTPLoc *)msg->ploc;
    if (ploc) {
        num = arr_num(ploc->script_list);
 
        for (i = 0; i < num; i++) {
            psc = arr_value(ploc->script_list, i);
            if (!psc || !psc->p || psc->len <= 0)
                continue;
 
            http_script_init(&hsc, msg, psc->p, psc->len, 3, NULL, 0);

            http_script_parse_exec(&hsc, psc->p, psc->len);
            reloc = hsc.reloc;
            replied = hsc.replied;

            http_script_free(&hsc);

            if (replied) return 0;

            if (reloc) {
                http_loc_instance(msg);
                return 0;
            }
        }
    }

    return 1;
}

int http_reply_script_exec (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPScript   hsc;
    HTTPListen * hl = NULL;
    HTTPHost   * host = NULL;
    HTTPLoc    * ploc = NULL;
    int          i, num;
    ckstr_t    * psc = NULL;

    if (!msg) return -1;

    memset(&hsc, 0, sizeof(hsc));

    hl = (HTTPListen *)msg->hl;
    if (hl) {
        num = arr_num(hl->reply_script_list);

        for (i = 0; i < num; i++) {
            psc = arr_value(hl->reply_script_list, i);
            if (!psc || !psc->p || psc->len <= 0)
                continue;

            http_script_init(&hsc, msg, psc->p, psc->len, 1, NULL, 0);

            http_script_parse_exec(&hsc, psc->p, psc->len);

            http_script_free(&hsc);
        }
    }

    host = (HTTPHost *)msg->phost;
    if (host) {
        num = arr_num(host->reply_script_list);

        for (i = 0; i < num; i++) {
            psc = arr_value(host->reply_script_list, i);
            if (!psc || !psc->p || psc->len <= 0)
                continue;

            http_script_init(&hsc, msg, psc->p, psc->len, 2, NULL, 0);

            http_script_parse_exec(&hsc, psc->p, psc->len);

            http_script_free(&hsc);
        }
    }

    ploc = (HTTPLoc *)msg->ploc;
    if (ploc) {
        num = arr_num(ploc->reply_script_list);

        for (i = 0; i < num; i++) {
            psc = arr_value(ploc->reply_script_list, i);
            if (!psc || !psc->p || psc->len <= 0)
                continue;

            http_script_init(&hsc, msg, psc->p, psc->len, 3, NULL, 0);

            http_script_parse_exec(&hsc, psc->p, psc->len);

            http_script_free(&hsc);
        }
    }

    return 1;
}

void script_parser_init ()
{
    int i, num;
    ckstr_t key;

    static scmd_t scmd_tab [] = {
        { "if",                 2,  script_if_parse },
        { "set",                3,  script_set_parse },
        { "reply",              5,  script_reply_parse },
        { "return",             6,  script_return_parse },
        { "rewrite",            7,  script_rewrite_parse },
        { "addReqHeader",       12, script_add_req_header_parse },
        { "addResHeader",       12, script_add_res_header_parse },
        { "delReqHeader",       12, script_del_req_header_parse },
        { "delResHeader",       12, script_del_res_header_parse },
        { "addResBody",         10, script_add_res_body_parse },
        { "appendResBody",      13, script_append_res_body_parse },
        { "addFile2ResBody",    15, script_add_file_to_res_body_parse },
        { "appendFile2ResBody", 18, script_append_file_to_res_body_parse },
        { "try_files",          9,  script_try_files_parse }
    };

    if (script_parser_table) return;

    script_parser_table = ht_only_new(200, ckstr_cmp);
    if (!script_parser_table) return;

    ht_set_hash_func(script_parser_table, ckstr_string_hash);

    num = sizeof(scmd_tab) / sizeof(scmd_tab[0]);
    for (i = 0; i < num; i++) {
        key.p = scmd_tab[i].cmd;
        key.len = scmd_tab[i].len;
        ht_set(script_parser_table, &key, &scmd_tab[i]);
    }
}

void script_parser_clean ()
{
    if (!script_parser_table) return;

    ht_free(script_parser_table);

    script_parser_table = NULL;
}

void * script_parser_get (char * cmd, int len)
{
    ckstr_t  key = ckstr_init(cmd, len);
    scmd_t * scmd;

    scmd = ht_get(script_parser_table, &key);
    if (scmd) return scmd->parser;

    return NULL;
}

