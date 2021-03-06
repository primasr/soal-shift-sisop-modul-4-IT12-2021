#define FUSE_USE_VERSION 28
#define _XOPEN_SOURCE 700
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <pthread.h>

static const char *dirpath = "/home/primasr/Downloads";

// Fungsi untuk membuat log
void createlog(const char process[100], const char fpath[1000]) {
    char text[2000];
    FILE *fp = fopen("/home/primasr/SinSeiFS.log","a");
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    
    if (strcmp(process, "unlink") == 0) {
        sprintf(text, "WARNING::%02d%02d%04d-%02d:%02d:%02d::UNLINK::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    else if (strcmp(process, "mkdir") == 0) {
        sprintf(text, "INFO::%02d%02d%04d-%02d:%02d:%02d::MKDIR::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    else if (strcmp(process, "rmdir") == 0) {
        sprintf(text, "WARNING::%02d%02d%04d-%02d:%02d:%02d::RMDIR::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    for (int i = 0; text[i] != '\0'; i++) {
            fputc(text[i], fp);
    }
    fclose (fp);
}

// Fungsi untuk membuat log khusus proses rename
void createlogrename(const char from[1000], const char to[1000]) {
    FILE *fp = fopen("/home/primasr/SinSeiFS.log", "a");
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char text[2000];

    sprintf(text, "INFO::%02d%02d%04d-%02d:%02d:%02d::RENAME::%s::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, from, to);
    for (int i = 0; text[i] != '\0'; i++) {
            fputc(text[i], fp);
    }
    fclose(fp);
}

void atbash(char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    char *dot = strrchr(name, '.');
    char *atoz = strstr(name, "AtoZ_");
    int i;
    for (i = atoz - name; i < strlen(name); ++i) {
        if (name[i] == '/') {
            break;
        }
    }

    if (atoz == NULL) {
        i = 0;
    }

    int last = dot ? dot - name: strlen(name);
    for (; i < last; ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 155 - name[i];
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 219 - name[i];
        }
    }
}

void rot13(char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int name_len = strlen(name);
    for (int i = 0; i < name_len; ++i) {
        if ('A' <= name[i] && name[i] <= 'M') {
            name[i] = 13 + name[i];
        } else if ('N' <= name[i] && name[i] <= 'Z') {
            name[i] = -13 + name[i];
        } else if ('a' <= name[i] && name[i] <= 'm') {
            name[i] = 13 + name[i];
        } else if ('n' <= name[i] && name[i] <= 'z') {
            name[i] = -13 + name[i];
        }
    }

    char *dot = strrchr(name, '.');
    for (int i = (int)(dot - name); i < name_len; ++i) {
        if ('A' <= name[i] && name[i] <= 'M') {
            name[i] = 13 + name[i];
        } else if ('N' <= name[i] && name[i] <= 'Z') {
            name[i] = -13 + name[i];
        } else if ('a' <= name[i] && name[i] <= 'm') {
            name[i] = 13 + name[i];
        } else if ('n' <= name[i] && name[i] <= 'z') {
            name[i] = -13 + name[i];
        }
    }
}

void vigenere_enc(char *name) {
    char *key = "SISOP";

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int n = 0;

    char *dot = strrchr(name, '.');
    for (int i = 0; i < (int)(dot - name); ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 65 + (name[i] + key[n] - 130) % 26;
            n = (n + 1) % 5;
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 97 + (name[i] + key[n] - 162) % 26;
            n = (n + 1) % 5;
        }
    }
}

void vigenere_dec(char *name) {
    char *key = "SISOP";

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int n = 0;

    char *dot = strrchr(name, '.');
    for (int i = 0; i < (int)(dot - name); ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 65 + (name[i] - key[n] + 26) % 26;
            n = (n + 1) % 5;
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 97 + (name[i] - key[n] - 6) % 26;
            n = (n + 1) % 5;
        }
    }

}

void check_encryption(char *path, const char *fpath) {
    printf("check %s %s\n", path, fpath);
    if (strstr(fpath, "/AtoZ_") != NULL) {
        atbash(path);
    } else if (strstr(fpath, "/RX_") != NULL) {
        atbash(path);
        rot13(path);
    }
    printf("enc %s\n", path);
}


static int xmp_getattr(const char *path, struct stat *st) {
    char fpath[2000], name[1000], temp[1000];
    sprintf(temp, "%s", path);

    int name_len = strlen(path);
    for (int i = 0; i < name_len; i++) {
        name[i] = path[i + 1];
    }
    printf("getattr %s\n", name);
    
    // vigenere_dec(name);
    // atbash(name);
    // rot13(name);
    check_encryption(temp, path);
    sprintf(fpath, "%s/%s", dirpath, temp);
    
    int res = lstat(fpath, st);
    if (res != 0){
        return -ENOENT;
    }

    return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    int res;
    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;
    char fpath[2000];
    char name[1000];

    if (strcmp(path, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } 
    else {
        sprintf(name, "%s", path);
        // vigenere_dec(name);
        // atbash(name);
        // rot13(name);
        check_encryption(name, path);
        sprintf(fpath, "%s/%s", dirpath, name);
    }

    printf("readdir: %s\n", fpath);

    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        char fullpathname[2257];
        sprintf(fullpathname, "%s/%s", fpath, de->d_name);
        
        char temp[1000];
        strcpy(temp, de->d_name);
        // vigenere_enc(temp);
        // atbash(name);
        // rot13(name);
        check_encryption(temp, fpath);

        res = (filler(buf, temp, &st, 0));
        if (res != 0) break;
    }

    closedir(dp);

    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char fpath[2000];
    char name[1000];

    if (strcmp(path, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } else {
        sprintf(name, "%s", path);
        // vigenere_dec(name);
        // atbash(name);
        // rot13(name);

        check_encryption(name, path);
        sprintf(fpath, "%s/%s", dirpath, name);
    }

    printf("read %s\n", fpath);
    
    int res = 0;
    int fd = 0 ;

    (void) fi;
    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int xmp_rename(const char *old, const char *new) {
    char fpath[2000];
    char name[1000];
    char new_name[1000];
    createlogrename(old, new);
    if (strcmp(old, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } else {
        sprintf(name, "%s", old);
        // vigenere_dec(name);
        // atbash(name);
        // rot13(name);
        check_encryption(name, fpath);

        memset(fpath, 0, sizeof(fpath));
        memset(new_name, 0, sizeof(new_name));

        sprintf(fpath, "%s/%s", dirpath, name);
        sprintf(new_name, "%s/%s", dirpath, new);
    }

    printf("rename %s %s\n", fpath, new_name);

    int res = rename(fpath, new_name);
    if (res == -1) 
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode) {
    printf("mkdir %s\n", path);
    createlog("mkdir", path);
    char fpath[2000];
    
    sprintf(fpath, "%s/%s", dirpath, path);
    mkdir(fpath, mode);

    return 0;
}

static int xmp_rmdir(const char *path) {
    printf("rmdir %s\n", path);
    createlog("rmdir", path);
    char fpath[2000];

    sprintf(fpath, "%s/%s", dirpath, path);
    int res = rmdir(fpath);
    if (res != 0) return -errno;

    return 0;
}

static struct fuse_operations xmp_oper = {
    .getattr    = xmp_getattr,
    .readdir    = xmp_readdir,
    .read       = xmp_read,
    .rename     = xmp_rename,
    .mkdir      = xmp_mkdir,
    .rmdir      = xmp_rmdir,
};

int main(int argc, char *argv[]) {
    umask(0);
    return fuse_main(argc, argv, &xmp_oper, NULL);
}
