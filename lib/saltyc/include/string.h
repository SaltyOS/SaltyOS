/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __STRING_H__
#define __STRING_H__

#include <stddef.h>

extern void *memcpy(void *dest, const void *src, size_t n);
extern void *memmove(void *dest, const void *src, size_t n);
extern void *memset(void *s, int c, size_t n);
extern int   memcmp(const void *s1, const void *s2, size_t n);
extern void *memchr(const void *s, int c, size_t n);
extern void *memrchr(const void *s, int c, size_t n);
extern void *mempcpy(void *dest, const void *src, size_t n);

extern size_t strlen(const char *s);
extern size_t strnlen(const char *s, size_t maxlen);

extern char *strcpy(char *dest, const char *src);
extern char *strncpy(char *dest, const char *src, size_t n);
extern char *stpcpy(char *dest, const char *src);
extern char *stpncpy(char *dest, const char *src, size_t n);

extern char *strcat(char *dest, const char *src);
extern char *strncat(char *dest, const char *src, size_t n);

extern int   strcmp(const char *s1, const char *s2);
extern int   strncmp(const char *s1, const char *s2, size_t n);
extern int   strcasecmp(const char *s1, const char *s2);
extern int   strncasecmp(const char *s1, const char *s2, size_t n);
extern int   strcoll(const char *s1, const char *s2);
extern size_t strxfrm(char *dest, const char *src, size_t n);

extern char *strchr(const char *s, int c);
extern char *strrchr(const char *s, int c);
extern char *strchrnul(const char *s, int c);
extern char *strstr(const char *haystack, const char *needle);
extern char *strcasestr(const char *haystack, const char *needle);
extern char *strpbrk(const char *s, const char *accept);

extern size_t strspn(const char *s, const char *accept);
extern size_t strcspn(const char *s, const char *reject);

extern char *strtok(char *str, const char *delim);
extern char *strtok_r(char *str, const char *delim, char **saveptr);

extern char *strdup(const char *s);
extern char *strndup(const char *s, size_t n);

extern char *strerror(int errnum);
extern int   strerror_r(int errnum, char *buf, size_t buflen);
extern char *strsignal(int sig);

extern void  bzero(void *s, size_t n);
extern void  bcopy(const void *src, void *dest, size_t n);
extern void  explicit_bzero(void *s, size_t n);

/* BSD extensions */
extern size_t strlcpy(char *dst, const char *src, size_t dstsize);
extern size_t strlcat(char *dst, const char *src, size_t dstsize);
extern int    strverscmp(const char *s1, const char *s2);

#endif /* __STRING_H__ */
