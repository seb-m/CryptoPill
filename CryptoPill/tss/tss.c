//
//  tss.c
//  CryptoPill
//
//  Created by Sébastien Martini.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//
#include "tss.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <CommonCrypto/CommonDigest.h>

#include "utils.h"  //libsodium

#include "rand.h"
#include "sysendian.h"
#include "verify.h"


static const uint8_t header_size = 21;


// GF(256) arithmetic

static const uint8_t EXP[256] = {
  0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
  0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
  0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
  0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
  0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
  0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
  0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
  0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
  0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
  0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
  0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
  0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
  0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
  0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
  0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
  0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
  0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
  0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
  0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
  0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
  0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
  0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
  0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
  0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
  0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
  0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
  0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
  0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
  0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
  0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
  0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
  0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x00
};

static const uint8_t LOG[256] = {
    0,    0,   25,    1,   50,    2,   26,  198,
   75,  199,   27,  104,   51,  238,  223,    3,
  100,    4,  224,   14,   52,  141,  129,  239,
   76,  113,    8,  200,  248,  105,   28,  193,
  125,  194,   29,  181,  249,  185,   39,  106,
   77,  228,  166,  114,  154,  201,    9,  120,
  101,   47,  138,    5,   33,   15,  225,   36,
   18,  240,  130,   69,   53,  147,  218,  142,
  150,  143,  219,  189,   54,  208,  206,  148,
   19,   92,  210,  241,   64,   70,  131,   56,
  102,  221,  253,   48,  191,    6,  139,   98,
  179,   37,  226,  152,   34,  136,  145,   16,
  126,  110,   72,  195,  163,  182,   30,   66,
   58,  107,   40,   84,  250,  133,   61,  186,
   43,  121,   10,   21,  155,  159,   94,  202,
   78,  212,  172,  229,  243,  115,  167,   87,
  175,   88,  168,   80,  244,  234,  214,  116,
   79,  174,  233,  213,  231,  230,  173,  232,
   44,  215,  117,  122,  235,   22,   11,  245,
   89,  203,   95,  176,  156,  169,   81,  160,
  127,   12,  246,  111,   23,  196,   73,  236,
  216,   67,   31,   45,  164,  118,  123,  183,
  204,  187,   62,   90,  251,   96,  177,  134,
   59,   82,  161,  108,  170,   85,   41,  157,
  151,  178,  135,  144,   97,  190,  220,  252,
  188,  149,  207,  205,   55,   63,   91,  209,
   83,   57,  132,   60,   65,  162,  109,   71,
   20,   42,  158,   93,   86,  242,  211,  171,
   68,   17,  146,  217,   35,   32,   46,  137,
  180,  124,  184,   38,  119,  153,  227,  165,
  103,   74,  237,  222,  197,   49,  254,   24,
   13,   99,  140,  128,  192,  247,  112,    7
};

static uint8_t gf256_add(uint8_t a, uint8_t b) {
  return a ^ b;
}

static uint8_t gf256_sub(uint8_t a, uint8_t b) {
  return gf256_add(a, b);
}

static uint8_t gf256_mul(uint8_t a, uint8_t b) {
  if (a == 0 || b == 0)
    return 0;
  return EXP[(LOG[a] + LOG[b]) % 255];
}

static uint8_t gf256_div(uint8_t a, uint8_t b) {
  // Invalid division
  assert(b);
  if (a == 0)
    return 0;
  return EXP[(255 + LOG[a] - LOG[b]) % 255];
}

static uint8_t f(const tss_ctx *ctx, int secret_index, uint8_t share_index) {
  uint8_t y = 0;
  uint8_t x_i = 1;
  uint8_t c;
  int i;

  assert(share_index > 0);

  for (i = 0; i < ctx->threshold; ++i) {
    if (i == 0)
      c = ctx->secret[secret_index];
    else
      c = ctx->coefs_poly[i];

    y = gf256_add(y, gf256_mul(c, x_i));
    x_i = gf256_mul(x_i, share_index);
  }
  return y;
}

static uint8_t basis_poly(const tss_ctx *ctx, const uint8_t *indexes,
                          uint8_t i) {
  uint8_t prod = 1;
  int j;

  for (j = 0; j < ctx->threshold; ++j) {
    if (i == j)
      continue;
    prod = gf256_mul(prod, gf256_div(indexes[j], gf256_add(indexes[j],
                                                           indexes[i])));
  }
  return prod;
}

static uint8_t lagrange_interpolation(const tss_ctx *ctx,
                                      const uint8_t *indexes,
                                      const uint8_t *v) {
  uint8_t sum = 0;
  int i;

  for (i = 0; i < ctx->threshold; ++i)
    sum = gf256_add(sum, gf256_mul(basis_poly(ctx, indexes, i), v[i]));
  return sum;
}


// Header encoding / decoding

static void header_enc(const tss_ctx *ctx, uint8_t index, uint8_t *header) {
  memcpy(header, ctx->identifier, TSS_IDENTIFIER_SIZE);
  header[TSS_IDENTIFIER_SIZE] = ctx->hash;
  header[17] = ctx->threshold;
  be16enc(header + 18, ctx->secret_len);
  header[20] = index;
}

static int header_dec(tss_ctx *ctx, const uint8_t *header) {
  uint8_t t8;
  uint16_t t16;

  memcpy(ctx->identifier, header, TSS_IDENTIFIER_SIZE);

  t8 = header[TSS_IDENTIFIER_SIZE];
  if (t8 >= TSS_END)
    return -1;
  ctx->hash = t8;

  t8 = header[17];
  if (t8 == 0 || t8 == 255)
    return -1;
  ctx->threshold = t8;

  t16 = be16dec(header + 18);
  if (t16 == 0 || t16 > 65534)
    return -1;
  ctx->secret_len = t16;

  return 0;
}

static int check_header(const tss_ctx *ctx, const uint8_t *share) {
  if (memcmp(ctx->identifier, share, TSS_IDENTIFIER_SIZE))
    return 0;
  if (ctx->hash != share[TSS_IDENTIFIER_SIZE] || ctx->threshold != share[17] ||
      share[20] == 0)
    return 0;
  if (be16dec(share + 18) != ctx->secret_len)
    return 0;
  return 1;
}


// Hash functions

static CC_LONG hash_size(tss_hash hash) {
  CC_LONG size;

  switch (hash) {
    case TSS_NONE:
      size = 0;
      break;
    case TSS_SHA1:
      size = 20;
      break;
    case TSS_SHA256:
      size = 32;
      break;
    default:
      assert(0);
  }
  return size;
}

static void hash(tss_hash hash, const uint8_t *data, CC_LONG data_len,
                 uint8_t *dst) {
  switch (hash) {
    case TSS_NONE:
      break;
    case TSS_SHA1:
      CC_SHA1((void *)data, data_len, (void *)dst);
      break;
    case TSS_SHA256:
      CC_SHA256((void *)data, data_len, (void *)dst);
      break;
    default:
      assert(0);
  }
}


// Util

static int has_recover_share(const tss_ctx *ctx) {
  int i;

  for (i = 1; i < 256; ++i)
    if (ctx->shares[i] != NULL)
      return 1;
  return 0;
}


// Public functions

int tss_share_init(tss_ctx *ctx, const uint8_t identifier[TSS_IDENTIFIER_SIZE],
                   uint8_t threshold, tss_hash hash_algorithm,
                   const uint8_t *secret, uint16_t secret_len) {
  uint16_t full_secret_len;
  int i;

  if (ctx == NULL || secret == NULL)
    return -1;

  memcpy(ctx->identifier, identifier, TSS_IDENTIFIER_SIZE);

  if (hash_algorithm >= TSS_END)
    return -1;
  ctx->hash = hash_algorithm;

  if (threshold == 0 || threshold == 255)
    return -1;
  ctx->threshold = threshold;

  // Generate random polynomial coefficients.
  memset(ctx->coefs_poly, 0, 256);
  if (crand(ctx->coefs_poly + 1, threshold - 1) == -1)
    return -1;

  full_secret_len = secret_len + hash_size(hash_algorithm);
  if (full_secret_len > 65534)
    return -1;

  ctx->secret = malloc(full_secret_len);
  if (ctx->secret == NULL)
    return -1;
  memcpy(ctx->secret, secret, secret_len);
  if (hash_algorithm != TSS_NONE)
    hash(ctx->hash, ctx->secret, secret_len, ctx->secret + secret_len);
  ctx->secret_len = full_secret_len;

  ctx->index = 1;

  for (i = 0; i < 256; ++i)
    ctx->shares[i] = NULL;

  return 0;
}

uint32_t tss_share_size(const tss_ctx *ctx) {
  if (ctx == NULL)
    return 0;
  return header_size + ctx->secret_len;
}

int tss_share(tss_ctx *ctx, uint8_t index, uint8_t *share) {
  int i;

  if (ctx == NULL || share == NULL || index == 0 || index == 255)
    return -1;

  if (ctx->secret == NULL || ctx->hash >= TSS_END || ctx->threshold == 0 ||
      ctx->threshold == 255)
    return -1;

  for (i = 0; i < ctx->secret_len; ++i)
    share[header_size + i] = f(ctx, i, index);

  header_enc(ctx, index, share);
  return 0;
}

int tss_share_next(tss_ctx *ctx, uint8_t *share) {
  int ret;

  if (ctx == NULL || ctx->index == 0)
    return -1;

  if (ctx->index == 255)
    return -2;

  ret = tss_share(ctx, ctx->index, share);
  if (ret != 0)
    return ret;

  ctx->index += 1;
  return 0;
}

int tss_recover_init(tss_ctx *ctx) {
  int i;

  if (ctx == NULL)
    return -1;

  // That way it impossible to generate new shares unitentionally i.e.
  // without explictly assigning a new index value.
  ctx->index = 0;

  ctx->secret = NULL;
  ctx->secret_len = 0;

  for (i = 0; i < 256; ++i)
    ctx->shares[i] = NULL;

  return 0;
}

int tss_recover_add(tss_ctx *ctx, const uint8_t *share) {
  uint8_t x;

  if (ctx == NULL || share == NULL)
    return -1;

  // Share's original index
  x = share[20];
  if (x == 0 || x == 255)
    return -3;

  if (ctx->shares[x] != NULL)
    return -2;

  if (!has_recover_share(ctx) && header_dec(ctx, share))
    return -1;

  if (!check_header(ctx, share))
    return -3;

  ctx->shares[x] = malloc(ctx->secret_len);
  if (ctx->shares[x] == NULL)
    return -1;
  memcpy(ctx->shares[x], share + header_size, ctx->secret_len);

  return x;
}

uint16_t tss_recover_secret_size(const tss_ctx *ctx) {
  if (ctx == NULL)
    return 0;
  return ctx->secret_len - hash_size(ctx->hash);
}

uint8_t tss_recover_threshold(const tss_ctx *ctx) {
  if (ctx == NULL)
    return 0;
  return ctx->threshold;
}

uint8_t tss_recover_num_shares(const tss_ctx *ctx) {
  int count;
  int i;

  if (ctx == NULL)
    return 0;

  count = 0;
  for (i = 1; i < 256; ++i)
    if (ctx->shares[i] != NULL)
      count++;
  return count;
}

int tss_recover(tss_ctx *ctx, uint8_t *secret) {
  if (ctx == NULL)
    return -1;

  uint8_t indexes[ctx->threshold];
  uint8_t secret_byte[ctx->threshold];
  int count;
  int i;
  int j;

  if (secret == NULL || ctx->secret_len == 0)
    return -1;

  count = 0;
  for (i = 1; i < 256; ++i) {
    if (ctx->shares[i] != NULL) {
      indexes[count++] = i;
      if (count >= ctx->threshold)
        break;
    }
  }
  if (count < ctx->threshold)
    return -2;

  if (ctx->secret == NULL) {
    ctx->secret = malloc(ctx->secret_len);
    if (ctx->secret == NULL)
      return -1;
  }

  for (i = 0; i < ctx->secret_len; ++i) {
    for (j = 0; j < ctx->threshold; ++j)
      secret_byte[j] = ctx->shares[indexes[j]][i];
    ctx->secret[i] = lagrange_interpolation(ctx, indexes, secret_byte);
  }

  if (ctx->hash != TSS_NONE) {
    CC_LONG hsize = hash_size(ctx->hash);
    uint8_t hash_buffer[hsize];
    hash(ctx->hash, ctx->secret, ctx->secret_len - hsize, hash_buffer);
    if (verify_32(ctx->secret + (ctx->secret_len - hsize), hash_buffer))
      return -3;
  }
  memcpy(secret, ctx->secret, tss_recover_secret_size(ctx));

  return 0;
}

// Adapted from: "Commons Math: The Apache Commons Mathematics Library"
// http://people.apache.org/~olamy/commons-content/proper/commons-math/
//   apidocs/src-html/org/apache/commons/math3/analysis/polynomials/
//   PolynomialFunctionLagrangeForm.html#line.253
int tss_recover_coefficients(tss_ctx *ctx) {
  if (ctx == NULL)
    return -1;

  uint8_t x[ctx->threshold];
  uint8_t y[ctx->threshold];
  uint8_t c[ctx->threshold + 1];
  uint8_t tc[ctx->threshold];
  uint8_t d;
  uint8_t t;
  uint8_t n;
  int count;
  int i;
  int j;

  if (ctx->secret_len == 0)
    return -1;

  n = ctx->threshold;

  count = 0;
  for (i = 1; i < 256; ++i) {
    if (ctx->shares[i] != NULL) {
      x[count] = i;
      y[count++] = ctx->shares[i][0];
      if (count >= n)
        break;
    }
  }
  if (count < n)
    return -2;

  memset(ctx->coefs_poly, 0, 256);

  // Represents what would be the 'full' numerator in Lagrange's polynomial
  // c[] are the coefficients of P(x) = (x-x[0])(x-x[1])...(x-x[n-1])
  c[0] = 1;
  for (i = 0; i < n; ++i) {
    for (j = i; j > 0; --j)
      c[j] = gf256_sub(c[j - 1], gf256_mul(c[j], x[i]));
    c[0] = gf256_sub(0, gf256_mul(c[0], x[i]));
    c[i + 1] = 1;
  }

  for (i = 0; i < n; ++i) {
    // Represents the denominator in Lagrange's polynomial
    // d = (x[i]-x[0])...(x[i]-x[i-1])(x[i]-x[i+1])...(x[i]-x[n-1])
    d = 1;
    for (j = 0; j < n; ++j) {
      if (i != j)
        d = gf256_mul(d, gf256_sub(x[i], x[j]));
    }
    t = gf256_div(y[i], d);

    // Lagrange polynomial is the sum of n terms, each of which is a
    // polynomial of degree n-1. tc[] are the coefficients of the i-th
    // numerator Pi(x) = (x-x[0])...(x-x[i-1])(x-x[i+1])...(x-x[n-1]).
    tc[n - 1] = c[n];  // actually c[n] = 1
    ctx->coefs_poly[n - 1] = gf256_add(ctx->coefs_poly[n - 1],
                                       gf256_mul(t, tc[n - 1]));
    for (j = n - 2; j >= 0; --j) {
      tc[j] = gf256_add(c[j + 1], gf256_mul(tc[j + 1], x[i]));
      ctx->coefs_poly[j] = gf256_add(ctx->coefs_poly[j],
                                     gf256_mul(t, tc[j]));
    }
  }

  ctx->coefs_poly[0] = 0;
  memset(y, 0, n);
  memset(c, 0, n + 1);
  memset(tc, 0, n);
  d = t = 0;

  return 0;
}

void tss_free(tss_ctx *ctx) {
  int i;

  if (ctx == NULL)
    return;

  memset(ctx->identifier, 0, TSS_IDENTIFIER_SIZE);
  memset(ctx->coefs_poly, 0, 256);

  if (ctx->secret != NULL) {
    sodium_memzero(ctx->secret, ctx->secret_len);
    free(ctx->secret);
    ctx->secret = NULL;
    ctx->secret_len = 0;
  }

  for (i = 0; i < 256; ++i) {
    if (ctx->shares[i] != NULL) {
      sodium_memzero(ctx->shares[i], ctx->secret_len);
      free(ctx->shares[i]);
      ctx->shares[i] = NULL;
    }
  }
}
