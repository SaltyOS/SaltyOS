/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MD5_H__
#define __MD5_H__

#define MD5_DIGEST_LENGTH   16
#define MD5_DIGEST_STRING_LENGTH (MD5_DIGEST_LENGTH * 2 + 1)

typedef struct MD5Context {
    unsigned int state[4];
    unsigned int count[2];
    unsigned char buffer[64];
} MD5_CTX;

void  MD5Init(MD5_CTX *ctx);
void  MD5Update(MD5_CTX *ctx, const void *data, unsigned int len);
void  MD5Final(unsigned char digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx);
char *MD5End(MD5_CTX *ctx, char *buf);

#endif /* __MD5_H__ */
