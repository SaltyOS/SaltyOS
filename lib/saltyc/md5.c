/* FreeBSD compat — MD5 implementation for ported FreeBSD utilities (sort -R) */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * md5.c — RFC 1321 MD5 message-digest algorithm for SaltyOS
 *
 * Implements MD5Init(), MD5Update(), MD5Final() with standard MD5_CTX.
 * Used by sort(1) for -R (random sort key generation).
 */

#include <md5.h>
#include <string.h>

/* MD5 constants: T[i] = floor(2^32 * abs(sin(i+1))), i = 0..63 */
static const unsigned int T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

/* Per-round shift amounts */
static const unsigned int S[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
};

#define ROTL(x, n)  (((x) << (n)) | ((x) >> (32 - (n))))

static void
md5_encode(unsigned char *output, const unsigned int *input, unsigned int len)
{
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j]     = (unsigned char)(input[i]        & 0xff);
        output[j + 1] = (unsigned char)((input[i] >> 8)  & 0xff);
        output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}

static void
md5_decode(unsigned int *output, const unsigned char *input, unsigned int len)
{
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((unsigned int)input[j])
                   | ((unsigned int)input[j + 1] << 8)
                   | ((unsigned int)input[j + 2] << 16)
                   | ((unsigned int)input[j + 3] << 24);
    }
}

static void
md5_transform(unsigned int state[4], const unsigned char block[64])
{
    unsigned int a = state[0], b = state[1], c = state[2], d = state[3];
    unsigned int M[16];
    unsigned int f, g;
    int i;

    md5_decode(M, block, 64);

    for (i = 0; i < 64; i++) {
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        f = f + a + T[i] + M[g];
        a = d;
        d = c;
        c = b;
        b = b + ROTL(f, S[i]);
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void
MD5Init(MD5_CTX *ctx)
{
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

void
MD5Update(MD5_CTX *ctx, const void *input, unsigned int inputLen)
{
    const unsigned char *data = (const unsigned char *)input;
    unsigned int idx, partLen, i;

    /* Compute number of bytes mod 64 */
    idx = (unsigned int)((ctx->count[0] >> 3) & 0x3F);

    /* Update bit count */
    ctx->count[0] += ((unsigned int)inputLen << 3);
    if (ctx->count[0] < ((unsigned int)inputLen << 3))
        ctx->count[1]++;
    ctx->count[1] += ((unsigned int)inputLen >> 29);

    partLen = 64 - idx;

    /* Transform as many times as possible */
    if (inputLen >= partLen) {
        memcpy(&ctx->buffer[idx], data, partLen);
        md5_transform(ctx->state, ctx->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64)
            md5_transform(ctx->state, &data[i]);

        idx = 0;
    } else {
        i = 0;
    }

    /* Buffer remaining input */
    memcpy(&ctx->buffer[idx], &data[i], inputLen - i);
}

void
MD5Final(unsigned char digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx)
{
    static const unsigned char padding[64] = { 0x80 };
    unsigned char bits[8];
    unsigned int idx, padLen;

    /* Save number of bits */
    md5_encode(bits, ctx->count, 8);

    /* Pad to 56 mod 64 */
    idx = (unsigned int)((ctx->count[0] >> 3) & 0x3f);
    padLen = (idx < 56) ? (56 - idx) : (120 - idx);
    MD5Update(ctx, padding, padLen);

    /* Append length (before padding) */
    MD5Update(ctx, bits, 8);

    /* Store state in digest */
    md5_encode(digest, ctx->state, 16);

    /* Zero sensitive information */
    memset(ctx, 0, sizeof(*ctx));
}

char *
MD5End(MD5_CTX *ctx, char *buf)
{
    unsigned char digest[MD5_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";
    int i;

    if (buf == NULL)
        return NULL;

    MD5Final(digest, ctx);

    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        buf[i * 2]     = hex[digest[i] >> 4];
        buf[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    buf[MD5_DIGEST_LENGTH * 2] = '\0';

    return buf;
}
