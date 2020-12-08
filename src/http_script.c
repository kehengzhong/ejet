/*
 * Copyright (c) 2003-2020 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"
#include <regex.h>

#include "http_listen.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_variable.h"
#include "http_script.h"

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

    if ((*pbgn == '"' || *pbgn == '\'') && *poct == *pbgn) {
        pbgn++; 
        poct--;
        pend--;
        if (pbgn >= pend) return 0;
    }

    if (getvar)
        return http_var_copy(hsc->msg, pbgn, pend-pbgn, value, vallen, NULL, 0, hsc->vname, hsc->vtype);

    return str_secpy(value, vallen, pbgn, pend-pbgn);
}

int script_if_conditiion_parse (void * vhsc, char * cond, int condlen)
{
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char         bufa[4096];
    char         bufb[4096];
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    char       * pexpend = NULL;
    struct stat  fs;
    int          reverse = 0;
    char         cmpsym[8];

    regex_t      regobj;
    int          ret = 0;
    regmatch_t   pmat[4];

    if (!hsc) return 0;

    if (!cond) return 0;
    if (condlen < 0) condlen = strlen(cond);
    if (condlen <= 0) return 0;

    pbgn = cond;
    pend = cond + condlen;

    pbgn = skipOver(pbgn, condlen, " \t\r\n\f\v", 6);
    if (pbgn >= pend) return 0;

    pexpend = rskipOver(pend-1, pend-pbgn, " \t\r\n\f\v", 6);

    if (pend - pbgn > 2 && pbgn[0] == '-' &&
        (pbgn[1] == 'f' || pbgn[1] == 'd' || pbgn[1] == 'e' || pbgn[1] == 'x'))
    {
        poct = skipOver(pbgn+2, pend-pbgn-2, " \t\r\n\f\v", 6);
        if (poct >= pend) return 0;

        get_var_value(hsc, poct, pexpend+1-poct, bufa, sizeof(bufa)-1, 1);
        poct = trim_var(bufa, strlen(bufa));

        if (pbgn[1] == 'f') {
            if (file_is_regular(poct)) return 1;

        } else if (pbgn[1] == 'd') {
            if (file_is_dir(poct)) return 1;

        } else if (pbgn[1] == 'e') {
            if (file_exist(poct)) return 1;

        } else if (pbgn[1] == 'x') {
            if (file_stat(poct, &fs) < 0) return 0;
            if (fs.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
                return 1;
        }

        return 0;
    } 

    if (pend - pbgn > 3 && pbgn[0] == '!' && pbgn[1] == '-' &&
        (pbgn[2] == 'f' || pbgn[2] == 'd' || pbgn[2] == 'e' || pbgn[2] == 'x'))
    {
        poct = skipOver(pbgn+3, pend-pbgn-3, " \t\r\n\f\v", 6);
        if (poct >= pend) return 0;

        get_var_value(hsc, poct, pexpend-poct+1, bufa, sizeof(bufa)-1, 1);
        poct = trim_var(bufa, strlen(bufa));

        if (pbgn[2] == 'f') {
            if (!file_is_regular(poct)) return 1;

        } else if (pbgn[2] == 'd') {
            if (!file_is_dir(poct)) return 1;

        } else if (pbgn[2] == 'e') {
            if (!file_exist(poct)) return 1;

        } else if (pbgn[2] == 'x') {
            if (file_stat(poct, &fs) < 0) return 1;
            if (!(fs.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
                return 1;
        }

        return 0;
    }

    if (*pbgn == '!') { pbgn++; reverse = 1; }

    poct = goto_symbol_end(pbgn, pexpend + 1 - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, bufa, sizeof(bufa)-1, 1);

    pbgn = skipOver(poct, pexpend + 1 - poct, " \t\r\n\f\v", 6);
    if (pbgn > pexpend) {
        goto onevar;
    }

    /* all kinds of comparing symbol: ==  !=  ~  ^~  ~*  */
    for (poct = pbgn; poct < pexpend + 1; poct++) {
        if (is_exp_char(*poct)) break;
        if (ISSPACE(*poct)) break;
    }
    if (poct > pbgn) {
        str_secpy(cmpsym, sizeof(cmpsym)-1, pbgn, poct-pbgn);
    } else cmpsym[0] = '\0';

    pbgn = skipOver(poct, pexpend + 1 - poct, " \t\r\n\f\v", 6);
    if (pbgn > pexpend) {
        goto onevar;
    }

    /* extracting the second variable */
    poct = goto_symbol_end(pbgn, pexpend + 1 - pbgn);
    get_var_value(hsc, pbgn, poct-pbgn, bufb, sizeof(bufb)-1, 1);

    pbgn = bufa;
    poct = bufb;

    /* do comparing or matching calculation */
    if (strcasecmp(cmpsym, "==") == 0) {
        return (strcasecmp(pbgn, poct) == 0) ? 1 : 0;

    } else if (strcasecmp(cmpsym, "!=") == 0) {
        return (strcasecmp(pbgn, poct) == 0) ? 0 : 1;

    } else if (strcasecmp(cmpsym, "^~") == 0) {
        return (strncasecmp(pbgn, poct, strlen(poct)) == 0) ? 1 : 0;

    } else if (strcasecmp(cmpsym, "~") == 0) {
        memset(&regobj, 0, sizeof(regobj));
        regcomp(&regobj, bufb, REG_EXTENDED);
        ret = regexec(&regobj, bufa, 4, pmat, 0);
        regfree(&regobj);

        if (ret == 0) return 1;
        if (ret == REG_NOMATCH) return 0;

    } else if (strcasecmp(cmpsym, "~*") == 0) {
        memset(&regobj, 0, sizeof(regobj));
        regcomp(&regobj, bufb, REG_EXTENDED | REG_ICASE);

        ret = regexec(&regobj, bufa, 4, pmat, 0);
        regfree(&regobj);

        if (ret == 0) return 1;
        if (ret == REG_NOMATCH) return 0;
    }

onevar:
    poct = trim_var(bufa, strlen(bufa));
    if (strlen(poct) <= 0) return reverse; 

    if (strcasecmp(poct, "0") == 0 ||  
        strcasecmp(poct, "false") == 0 ||  
        strcasecmp(poct, "no") == 0)
        return reverse;

    return !reverse;
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
            condval = script_if_conditiion_parse(hsc, poct + 1, pval - poct - 1);
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
    char         uri[2048];
    char         dsturi[2048];
    regex_t      regobj = {0};
    regmatch_t   pmat[32];
    int          ret, dstlen;
    ckstr_t      pmatstr[32];
    int          i, matnum = 0;
 
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
    HTTPScript * hsc = (HTTPScript *)vhsc;
    char       * pbgn = NULL;
    char       * pend = NULL;
    char       * poct = NULL;
    int          len = 0;

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

        for (poct = pbgn; is_var_char(*poct) && poct < pend; poct++);

        len = poct - pbgn;
        if (len == 2 && str_ncmp(pbgn, "if", 2) == 0) {
            /* if (conditioin) { ... }  */
            poct = script_if_parse(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;

            pbgn = poct;
            continue;
        }

        else if (len == 3 && str_ncmp(pbgn, "set", 3) == 0) {
            poct = script_set_parse(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;
            pbgn = poct;
            continue;
        }

        else if (len == 5 && str_ncmp(pbgn, "reply", 5) == 0) {
            poct = script_reply_parse(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;
            pbgn = poct;
            continue;
        }

        else if (len == 6 && str_ncmp(pbgn, "return", 6) == 0) {
            poct = script_return_parse(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;
            pbgn = poct;
            continue;
        }

        else if (len == 7 && str_ncmp(pbgn, "rewrite", 7) == 0) {
            poct = script_rewrite_parse(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;
            pbgn = poct;
            continue;
        }

        else if (len == 12 && str_ncmp(pbgn, "addReqHeader", 12) == 0) {
            poct = script_add_req_header_parse(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;
            pbgn = poct;
            continue;
        }

        else if (len == 12 && str_ncmp(pbgn, "addResHeader", 12) == 0) {
            poct = script_add_res_header_parse(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;
            pbgn = poct;
            continue;
        }

        else if (len == 12 && str_ncmp(pbgn, "delReqHeader", 12) == 0) {
            poct = script_del_req_header_parse(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;
            pbgn = poct;
            continue;
        }

        else if (len == 12 && str_ncmp(pbgn, "delResHeader", 12) == 0) {
            poct = script_del_res_header_parse(hsc, pbgn, pend-pbgn);
            if (!poct) return -101;
            pbgn = poct;
            continue;
        }

        else if (len == 9 && str_ncmp(pbgn, "try_files", 9) == 0) {
            poct = script_try_files_parse(hsc, pbgn, pend-pbgn);
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

