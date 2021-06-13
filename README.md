# soal-shift-sisop-modul-4-IT12-2021

Repository Sebagai Laporan Resmi Soal Shift Modul 4 Praktikum Sistem Operasi 2021 Disusun oleh :

- Prima Secondary Ramadhan (05311940000001)
- Shavica Ihya Qurata Ayun L . (05311940000013)
- Sri Puspita Dewi (05311940000045)

## Soal 1

Di suatu jurusan, terdapat admin lab baru yang super duper gabut, ia bernama Sin. Sin baru menjadi admin di lab tersebut selama 1 bulan. Selama sebulan tersebut ia bertemu orang-orang hebat di lab tersebut, salah satunya yaitu Sei. Sei dan Sin akhirnya berteman baik. Karena belakangan ini sedang ramai tentang kasus keamanan data, mereka berniat membuat filesystem dengan metode encode yang mutakhir. Berikut adalah filesystem rancangan Sin dan Sei :

```
NOTE : 
Semua file yang berada pada direktori harus ter-encode menggunakan Atbash cipher(mirror).
Misalkan terdapat file bernama kucinglucu123.jpg pada direktori DATA_PENTING
“AtoZ_folder/DATA_PENTING/kucinglucu123.jpg” → “AtoZ_folder/WZGZ_KVMGRMT/pfxrmtofxf123.jpg”
Note : filesystem berfungsi normal layaknya linux pada umumnya, Mount source (root) filesystem adalah directory /home/[USER]/Downloads, dalam penamaan file ‘/’ diabaikan, dan ekstensi tidak perlu di-encode.
Referensi : https://www.dcode.fr/atbash-cipher
```

a) Jika sebuah direktori dibuat dengan awalan “AtoZ_”, maka direktori tersebut akan menjadi direktori ter-encode.

b) Jika sebuah direktori di-rename dengan awalan “AtoZ_”, maka direktori tersebut akan menjadi direktori ter-encode.

c) Apabila direktori yang terenkripsi di-rename menjadi tidak ter-encode, maka isi direktori tersebut akan terdecode.

d) Setiap pembuatan direktori ter-encode (mkdir atau rename) akan tercatat ke sebuah log. **Format : /home/[USER]/Downloads/[Nama Direktori] → /home/[USER]/Downloads/AtoZ_[Nama Direktori]**

e) Metode encode pada suatu direktori juga berlaku terhadap direktori yang ada di dalamnya.(rekursif)

## penyelesaian 
## code :
```sh
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
```

## Soal 2

Selain itu Sei mengusulkan untuk membuat metode enkripsi tambahan agar data pada komputer mereka semakin aman. Berikut rancangan metode enkripsi tambahan yang dirancang oleh Sei

a) Jika sebuah direktori dibuat dengan awalan “RX_[Nama]”, maka direktori tersebut akan menjadi direktori terencode beserta isinya dengan perubahan nama isi sesuai kasus nomor 1 dengan algoritma tambahan ROT13 (Atbash + ROT13).

b) Jika sebuah direktori di-rename dengan awalan “RX_[Nama]”, maka direktori tersebut akan menjadi direktori terencode beserta isinya dengan perubahan nama isi sesuai dengan kasus nomor 1 dengan algoritma tambahan Vigenere Cipher dengan key “SISOP” (Case-sensitive, Atbash + Vigenere).

c) Apabila direktori yang terencode di-rename (Dihilangkan “RX_” nya), maka folder menjadi tidak terencode dan isi direktori tersebut akan terdecode berdasar nama aslinya.

d) Setiap pembuatan direktori terencode (mkdir atau rename) akan tercatat ke sebuah log file beserta methodnya (apakah itu mkdir atau rename).

e) Pada metode enkripsi ini, file-file pada direktori asli akan menjadi terpecah menjadi file-file kecil sebesar 1024 bytes, sementara jika diakses melalui filesystem rancangan Sin dan Sei akan menjadi normal. Sebagai contoh, Suatu_File.txt berukuran 3 kiloBytes pada directory asli akan menjadi 3 file kecil yakni:
```
Suatu_File.txt.0000
Suatu_File.txt.0001
Suatu_File.txt.0002
```
Ketika diakses melalui filesystem hanya akan muncul Suatu_File.txt

## Soal 3

Karena Sin masih super duper gabut akhirnya dia menambahkan sebuah fitur lagi pada filesystem mereka. 

a) Jika sebuah direktori dibuat dengan awalan “A_is_a_”, maka direktori tersebut akan menjadi sebuah direktori spesial.

b) Jika sebuah direktori di-rename dengan memberi awalan “A_is_a_”, maka direktori tersebut akan menjadi sebuah direktori spesial.

c) Apabila direktori yang terenkripsi di-rename dengan menghapus “A_is_a_” pada bagian awal nama folder maka direktori tersebut menjadi direktori normal.

d) Direktori spesial adalah direktori yang mengembalikan enkripsi/encoding pada direktori “AtoZ_” maupun “RX_” namun masing-masing aturan mereka tetap berjalan pada direktori di dalamnya (sifat recursive  “AtoZ_” dan “RX_” tetap berjalan pada subdirektori).

e) Pada direktori spesial semua nama file (tidak termasuk ekstensi) pada fuse akan berubah menjadi lowercase **insensitive** dan diberi ekstensi baru berupa nilai desimal dari binner perbedaan namanya.

Contohnya jika pada direktori asli nama filenya adalah “FiLe_CoNtoH.txt” maka pada fuse akan menjadi “file_contoh.txt.1321”. 1321 berasal dari biner 10100101001.

## Soal 4

Untuk memudahkan dalam memonitor kegiatan pada filesystem mereka Sin dan Sei membuat sebuah log system dengan spesifikasi sebagai berikut.

a) Log system yang akan terbentuk bernama “SinSeiFS.log” pada direktori home pengguna (/home/[user]/SinSeiFS.log). Log system ini akan menyimpan daftar perintah system call yang telah dijalankan pada filesystem.

b) Karena Sin dan Sei suka kerapian maka log yang dibuat akan dibagi menjadi dua level, yaitu INFO dan WARNING.

c) Untuk log level WARNING, digunakan untuk mencatat syscall rmdir dan unlink.

d) Sisanya, akan dicatat pada level INFO.

e) Format untuk logging yaitu:


[Level]::[dd][mm][yyyy]-[HH]:[MM]:[SS]:[CMD]::[DESC :: DESC]

Level : Level logging, dd : 2 digit tanggal, mm : 2 digit bulan, yyyy : 4 digit tahun, HH : 2 digit jam (format 24 Jam),MM : 2 digit menit, SS : 2 digit detik, CMD : System Call yang terpanggil, DESC : informasi dan parameter tambahan

INFO::28052021-10:00:00:CREATE::/test.txt
INFO::28052021-10:01:00:RENAME::/test.txt::/rename.txt

## Dokumentasi

Compfile file FUSE kita menggunakan command dibawah

![compile](https://user-images.githubusercontent.com/73151849/121808986-34979c80-cc85-11eb-85ac-cb15ccec482d.png)

Tampilan setelah kita melakukan mount FUSE

![mount](https://user-images.githubusercontent.com/73151849/121808995-3c574100-cc85-11eb-8386-f57743e2c2e5.png)

Kita coba membuat sebuah folder

![mkdir_atoz](https://user-images.githubusercontent.com/73151849/121809003-3feac800-cc85-11eb-966b-21340c812e52.png)

Kita coba me-rename sebuah folder

![rename_atoz](https://user-images.githubusercontent.com/73151849/121809000-3f523180-cc85-11eb-8422-92a439acd24d.png)

Setelah selesai semua, kita bisa melakukan unmount dengan command dibawah

![unmonut](https://user-images.githubusercontent.com/73151849/121808999-3f523180-cc85-11eb-8f39-6c435c5b1a5e.png)

Tampilan logfile

![logfile](https://user-images.githubusercontent.com/73151849/121808998-3e210480-cc85-11eb-953c-b5ffa84fd17b.png)
