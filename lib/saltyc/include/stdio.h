/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __STDIO_H__
#define __STDIO_H__

#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct FILE FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

#define EOF     (-1)
#define BUFSIZ  1024
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define _IOFBF  0
#define _IOLBF  1
#define _IONBF  2

#define FILENAME_MAX 4096
#define FOPEN_MAX    16
#define TMP_MAX      10000
#define L_tmpnam     20
#define P_tmpdir     "/tmp"

extern FILE *fopen(const char *path, const char *mode);
extern FILE *fdopen(int fd, const char *mode);
extern FILE *freopen(const char *path, const char *mode, FILE *stream);
extern int   fclose(FILE *stream);
extern int   fflush(FILE *stream);

extern int   fgetc(FILE *stream);
extern int   getc(FILE *stream);
extern int   getchar(void);
extern int   ungetc(int c, FILE *stream);

extern int   fputc(int c, FILE *stream);
extern int   putc(int c, FILE *stream);
extern int   putchar(int c);

extern char *fgets(char *s, int size, FILE *stream);
extern int   fputs(const char *s, FILE *stream);
extern int   puts(const char *s);

extern size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
extern size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

extern int   fseek(FILE *stream, long offset, int whence);
extern long  ftell(FILE *stream);
extern void  rewind(FILE *stream);

extern int   feof(FILE *stream);
extern int   ferror(FILE *stream);
extern void  clearerr(FILE *stream);
extern int   fileno(FILE *stream);

extern int   setvbuf(FILE *stream, char *buf, int mode, size_t size);
extern void  setbuf(FILE *stream, char *buf);
extern void  setlinebuf(FILE *stream);

extern int   printf(const char *format, ...);
extern int   fprintf(FILE *stream, const char *format, ...);
extern int   sprintf(char *str, const char *format, ...);
extern int   snprintf(char *str, size_t size, const char *format, ...);
extern int   dprintf(int fd, const char *format, ...);
extern int   asprintf(char **strp, const char *format, ...);

extern int   vprintf(const char *format, va_list ap);
extern int   vfprintf(FILE *stream, const char *format, va_list ap);
extern int   vsprintf(char *str, const char *format, va_list ap);
extern int   vsnprintf(char *str, size_t size, const char *format, va_list ap);
extern int   vasprintf(char **strp, const char *format, va_list ap);

extern int   sscanf(const char *str, const char *format, ...);
extern int   vsscanf(const char *str, const char *format, va_list ap);

extern void  perror(const char *s);
extern int   remove(const char *pathname);
extern int   rename(const char *oldpath, const char *newpath);

extern FILE *tmpfile(void);
extern int   mkstemp(char *tmpl);

extern FILE *open_memstream(char **ptr, size_t *sizeloc);

extern ssize_t getline(char **lineptr, size_t *n, FILE *stream);
extern ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);

extern FILE *popen(const char *command, const char *type);
extern int   pclose(FILE *stream);

#endif /* __STDIO_H__ */
