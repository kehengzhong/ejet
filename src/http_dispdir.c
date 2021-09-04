/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_header.h"
#include "http_listen.h"
#include "http_cgi.h"
 
#ifdef UNIX
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#endif

 
int url_path_contain_dot_dot (char * path, int len)
{
    char * pbgn = NULL;
    char * pend = NULL;
    char * poct = NULL;
 
    if (!path) return 0;
    if (len <0 ) len = str_len(path);
    if (len <= 0) return 0;
 
    pbgn = path; pend = pbgn + len;
    poct = skipTo(pbgn, pend-pbgn, ".", 1);
    if (poct >= pbgn) return 0;
 
    if (*(poct-1) == '/' || *(poct-1) == '\\') {
        if (*(poct+1) == '.') {
            if (poct+2 >= pend) return 1;
            else if (*(poct+2) == '/' || *(poct+2) == '\\') return 1;
        }
    }
    return 0;
}

#ifdef UNIX

typedef struct diritem_ {
    char     isdir;
    char     mode[11];
    char     user[48];
    char     group[48];
    time_t   filetm;
    char     sizestr[16];
    char     name[280];
} DirItem;

static int read_dir_list (char * path, char * curpath, frame_p frame)
{
    struct dirent  * pent = NULL;
    int              i, dirnum, len;
    int              filetotal=0, dirtotal=0;
    struct dirent ** ppent = NULL;
    char             tmpstr[1024];
    char             realfile[512];
    struct stat      filest;
    struct passwd  * pwd = NULL;
    struct group   * grp = NULL;
 
    arr_t          * itemlist = NULL;
    DirItem        * item = NULL;
    int              modelen = 0;
    int              userlen = 0;
    int              grouplen = 0;
    int              sizestr_len = 0;
    int              namelen = 0;
 
    if (!path) return -1;
    if (!curpath) return -2;
    if (!frame) return -3;
 
    itemlist = arr_new(4);
 
    dirnum = scandir(path, &ppent, 0, alphasort);
    for (i = 0; i < dirnum; i++) {
        pent = ppent[i];
 
        if (strcmp(pent->d_name, ".") == 0 ||
            strcmp(pent->d_name, "..") == 0)
            goto nextfile;
        //if (pent->d_name[0] == '.') goto nextfile;
 
        sprintf(tmpstr, "%s%s", path, pent->d_name);
        memset(&filest, 0, sizeof(filest));
        if (lstat(tmpstr, &filest) < 0) goto nextfile;
 
        item = kzalloc(sizeof(*item));
 
        modelen = 10;
        strcpy(item->mode, "----------");
        if (S_ISDIR(filest.st_mode)) item->mode[0] = 'd';
        else if (S_ISLNK(filest.st_mode)) {
            item->mode[0] = 'l';
        }
        if (filest.st_mode & S_IRUSR) item->mode[1] = 'r';
        if (filest.st_mode & S_IWUSR) item->mode[2] = 'w';
        if (filest.st_mode & S_IXUSR) item->mode[3] = 'x';
        if (filest.st_mode & S_IRGRP) item->mode[4] = 'r';
        if (filest.st_mode & S_IWGRP) item->mode[5] = 'w';
        if (filest.st_mode & S_IXGRP) item->mode[6] = 'x';
        if (filest.st_mode & S_IROTH) item->mode[7] = 'r';
        if (filest.st_mode & S_IWOTH) item->mode[8] = 'w';
        if (filest.st_mode & S_IXOTH) item->mode[9] = 'x';
 
        pwd = getpwuid(filest.st_uid);
        if (pwd) {
            len = str_len(pwd->pw_name);
            if (userlen < len) userlen = len;
            strcpy(item->user, pwd->pw_name);
        }
 
        grp = getgrgid(filest.st_gid);
        if (grp) {
            len = str_len(grp->gr_name);
            if (grouplen < len) grouplen = len;
            strcpy(item->group, grp->gr_name);
        }
 
        item->filetm = filest.st_mtime;
 
        if (S_ISREG(filest.st_mode)) {
            sprintf(item->sizestr, "%ld", filest.st_size);
            len = str_len((char *)item->sizestr);
            if (sizestr_len < len) sizestr_len = len;
 
            filetotal++;

        } else if (S_ISDIR(filest.st_mode)) {
            item->isdir = 1;
            if (sizestr_len < 5) sizestr_len = 5;
            dirtotal++;

        } else if (S_ISLNK(filest.st_mode)) {
            realpath(tmpstr, realfile);
            if (lstat(realfile, &filest) >= 0) {
                if (S_ISREG(filest.st_mode)) {
                    sprintf(item->sizestr, "%ld", filest.st_size);
                    len = str_len((char *)item->sizestr);
                    if (sizestr_len < len) sizestr_len = len;
 
                    filetotal++;
                } else if (S_ISDIR(filest.st_mode)) {
                    item->isdir = 1;
                    if (sizestr_len < 5) sizestr_len = 5;
                    dirtotal++;
                }
            }
        }

        strncpy(item->name, pent->d_name, sizeof(item->name)-1);
        len = str_len((char *)item->name);
        if (namelen < len) namelen = len;
 
        arr_push(itemlist, item);
 
nextfile:
        free(ppent[i]);
    }
    free(ppent);
 
    for (i = 0; i < arr_num(itemlist); i++) {
        item = arr_value(itemlist, i);
        if (!item) continue;
 
        len = str_len(item->mode);
        frame_appendf(frame, " %s", item->mode);
        if (modelen - len > 0) frame_append_nbytes(frame, ' ', modelen - len);
        frame_append(frame, "  ");
 
        len = str_len(item->user);
        frame_appendf(frame, "%s", item->user);
        if (userlen - len > 0) frame_append_nbytes(frame, ' ', userlen - len);
        frame_append(frame, " ");
 
        len = str_len(item->group);
        frame_appendf(frame, "%s", item->group);
        if (grouplen - len > 0) frame_append_nbytes(frame, ' ', grouplen - len);
        frame_append(frame, "  ");
 
        str_datetime(NULL, tmpstr, sizeof(tmpstr), 0);
        frame_append(frame, tmpstr);
        frame_append(frame, "   ");
 
        if (item->isdir) {
            if (sizestr_len - 5 > 0) frame_append_nbytes(frame, ' ', sizestr_len - 5);
            frame_appendf(frame, "&lt;DIR&gt;");
            frame_append(frame, "  ");
 
            frame_appendf(frame, "<A HREF=\"");
            sprintf(tmpstr, "%s/", item->name);
            frame_uri_encode(frame, tmpstr, str_len(tmpstr), NULL);
            frame_appendf(frame, "\">%s</A><br>", item->name);

        } else {
            len = str_len(item->sizestr);
            if (sizestr_len - len > 0) frame_append_nbytes(frame, ' ', sizestr_len - len);
            frame_appendf(frame, "%s", item->sizestr);
            frame_append(frame, "  ");
 
            frame_appendf(frame, "<A HREF=\"");
            sprintf(tmpstr, "%s", item->name);
            frame_uri_encode(frame, tmpstr, str_len(tmpstr), NULL);
            frame_appendf(frame, "\">%s</A><br>", item->name);
        }
    }
    frame_appendf(frame, " 目录总数: %d &nbsp;&nbsp;文件总数: %d<br>", dirtotal, filetotal);
 
    arr_pop_kfree(itemlist);
    return 0;
}
#endif
 
#if defined(_WIN32) || defined(_WIN64)
static int read_dir_list (char * path, char * curpath, frame_p frame)
{
    WIN32_FIND_DATA   filest;
    HANDLE            hFind;
    char              szdir[512];
    char              tmpstr[128];
    char              svAttribs[8];
    FILETIME          filetm;
    SYSTEMTIME        systm;
    int               len = 0;
    int               filetotal=0, dirtotal=0;
 
    if (!path) return -1;
    if (!curpath) return -2;
    if (!frame) return -3;
 
    len = str_len(path);
    if (path[len - 1] != '/' && path[len - 1] != '\\')
        sprintf(szdir, "%s/*", path);
    else
        sprintf(szdir, "%s*", path);
    UnixPath2WinPath(szdir, -1);
 
    hFind = FindFirstFile(szdir, &filest);
    if (hFind == INVALID_HANDLE_VALUE) return -100;
 
    do {
        if (filest.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(filest.cFileName, ".") == 0 ||
                strcmp(filest.cFileName, "..") == 0)
                continue;
        }

        lstrcpy(svAttribs,"-------");
        if(filest.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)  svAttribs[0] = 'D';
        if(filest.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)    svAttribs[1] = 'A';
        if(filest.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)     svAttribs[2] = 'H';
        if(filest.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED) svAttribs[3] = 'C';
        if(filest.dwFileAttributes & FILE_ATTRIBUTE_READONLY)   svAttribs[4] = 'R';
        if(filest.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)     svAttribs[5] = 'S';
        if(filest.dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY)  svAttribs[6] = 'T';
 
        FileTimeToLocalFileTime(&filest.ftLastWriteTime, &filetm);
        FileTimeToSystemTime(&filetm, &systm);
 
        frame_appendf(frame, "%s  %4.4d-%2.2d-%2.2d %2.2d:%2.2d  ", svAttribs,
                           (int)systm.wYear, (int)systm.wMonth, (int)systm.wDay,
                           (int)systm.wHour%24, (int)systm.wMinute%60);
 
        if (filest.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            frame_append_nbytes(frame, ' ', 12-5);
            frame_appendf(frame, "&lt;DIR&gt;  ");
 
            frame_appendf(frame, "<A HREF=\"");
            sprintf(tmpstr, "%s%s/", curpath, filest.cFileName);
            frame_uri_encode(frame, tmpstr, str_len(tmpstr), NULL);
            frame_appendf(frame, "\">%s</A><br>", filest.cFileName);
            dirtotal++;
        } else {
            sprintf(tmpstr, "%ld", filest.nFileSizeLow);
            len = str_len(tmpstr);
            frame_append_nbytes(frame, ' ', 12-len);
            frame_appendf(frame, "%s  ", tmpstr);
 
            frame_appendf(frame, "<A HREF=\"");
            sprintf(tmpstr, "%s%s", curpath, filest.cFileName);
            frame_uri_encode(frame, tmpstr, str_len(tmpstr), NULL);
            frame_appendf(frame, "\">%s</A><br>", filest.cFileName);
            filetotal++;
        }
 
    } while(FindNextFile(hFind, &filest));
 
    FindClose(hFind);
    frame_appendf(frame, " 目录总数: %d &nbsp;&nbsp;文件总数: %d<br>", dirtotal, filetotal);
    return 0;
}
#endif
 
 
int DisplayDirectory (void * vmsg)
{
    HTTPMsg        * msg = (HTTPMsg *)vmsg;
    HTTPLoc        * ploc = NULL;
    HTTPMgmt       * mgmt = NULL;
    char           * root_path = NULL;
    int              len = 0;
    char             path[512];
    char             curpath[512];
    char             realpath[512];
    frame_p          frame = NULL;
    char           * pbgn, * pend, * poct;
    int              dotdot = 0;
    int              i, ret;
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    ploc = (HTTPLoc *)msg->ploc;
    if (!ploc) return -3;

    root_path = GetRootPath(msg);
    if (!root_path) return -4;

    len = GetRealFile(msg, path, sizeof(path));
    if (file_is_dir(path)) {
 
        ret = str_len(path);
        if (path[ret-1] != '/') strcat(path, "/");
        ret = str_len(path);
 
        for (i = 0; i < (int)ploc->indexnum; i++) {
             sprintf(path + ret, "%s", ploc->index[i]);
             if (file_is_regular(path)) {

                 strncpy(curpath, msg->GetURL(msg), sizeof(curpath)-1);
                 len = str_len(curpath);

                 if (curpath[len-1] != '/') {
                     strcat(curpath, "/");
                     return msg->RedirectReply(msg, 302, curpath);
                 }

                 msg->SetStatus(msg, 200, NULL);
                 msg->AddResFile(msg, path, 0, -1);
                 return msg->Reply(msg);
             }
        }

        path[ret] = '\0';
 
        memset(realpath, 0, sizeof(realpath));
        memset(curpath, 0, sizeof(curpath));
#ifdef UNIX
        getcwd(curpath, sizeof(curpath)-1);
        chdir(path);
        getcwd(realpath, sizeof(realpath)-1);
        chdir(curpath);
#elif defined(_WIN32) || defined(_WIN64)
        GetCurrentDirectory(sizeof(curpath)-1, curpath);
        SetCurrentDirectory(path);
        GetCurrentDirectory(sizeof(realpath)-1, realpath);
        SetCurrentDirectory(curpath);
#endif
 
        len = GetReqPath(msg, curpath, sizeof(curpath));
        if (curpath[len-1] != '/') strcat(curpath, "/");
    } else {
        GetRealPath(msg, path, sizeof(path));
        memset(realpath, 0, sizeof(realpath));
        memset(curpath, 0, sizeof(curpath));
#ifdef UNIX
        getcwd(curpath, sizeof(curpath)-1);
        chdir(path);
        getcwd(realpath, sizeof(realpath)-1);
        chdir(curpath);
#elif defined(_WIN32) || defined(_WIN64)
        GetCurrentDirectory(sizeof(curpath)-1, curpath);
        SetCurrentDirectory(path);
        GetCurrentDirectory(sizeof(realpath)-1, realpath);
        SetCurrentDirectory(curpath);
#endif
 
        len = GetPathOnly(msg, curpath, sizeof(curpath));
    }
 
    dotdot = url_path_contain_dot_dot(curpath, -1);
    if (dotdot && strncasecmp(realpath, root_path, str_len(root_path)) != 0) {
        //indicate the Browser has requested a parent path upon root.
        return -200;
    }
 
    frame = GetFrame(msg);
 
    frame_append(frame, "<html>");
    frame_append(frame, "<head>\n");
    frame_append(frame, "<title>");
    frame_put_nlast(frame, msg->req_host, msg->req_hostlen);
    frame_appendf(frame, " - %s</title>\n", curpath);
 
    frame_append(frame, "</head>\n<body><H1>");
    frame_put_nlast(frame, msg->req_host, msg->req_hostlen);
    //frame_appendf(frame, " - %s</H1><br>\n", realpath);
    frame_appendf(frame, " - %s</H1><br>\n", curpath);
 
    frame_append(frame, "<hr>\n");
    frame_append(frame, "\n");
    frame_append(frame, "<pre>\n");
 
    if (len == 1 && curpath[0] == '/') {
        frame_append(frame, "[Root Directory]<br><br>\n");
    } else {
        pbgn = &curpath[0];
        pend = &curpath[len-1];
        pend = rskipOver(pend, pend-pbgn+1, "/", 1);
        poct = rskipTo(pend, pend-pbgn+1, "/", 1);
 
        frame_append(frame, "<A HREF=\"");
        if (poct >= pbgn) {
            //frame_put_nlast(frame, pbgn, poct-pbgn+1);
            frame_uri_encode(frame, pbgn, poct-pbgn+1, NULL);
        }
        frame_append(frame, "\">[To Parent Directory]</A><br><br>\n");
    }
 
    read_dir_list(path, curpath, frame);
 
    frame_append(frame, "</pre><hr></body>\n");
    frame_append(frame, "</html>");
 
    AddResContent(msg, frameP(frame), frameL(frame));
    SetStatus(msg, 200, NULL);
    SetResContentType (msg, "text/html", 9);
    Reply(msg);
 
    if (frame) RecycleFrame(msg, frame);
    return 0;
}

