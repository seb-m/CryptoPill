// Code adapted to use CommonCrypto framework.

/*-
 * Copyright 2005,2007,2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "pbkdf2.h"

#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#include <CommonCrypto/CommonHMAC.h>

#include "sysendian.h"


/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt, size_t saltlen,
                   uint64_t c, uint8_t * buf, size_t dkLen) {
  CCHmacContext PShctx, hctx;
  size_t i;
  uint8_t ivec[4];
  uint8_t U[32];
  uint8_t T[32];
  uint64_t j;
  int k;
  size_t clen;

  /* Compute HMAC state after processing P and S. */
  CCHmacInit(&PShctx, kCCHmacAlgSHA256, passwd, passwdlen);
  CCHmacUpdate(&PShctx, salt, saltlen);

  /* Iterate through the blocks. */
  for (i = 0; i * 32 < dkLen; i++) {
    /* Generate INT(i + 1). */
    be32enc(ivec, (uint32_t)(i + 1));

    /* Compute U_1 = PRF(P, S || INT(i)). */
    memcpy(&hctx, &PShctx, sizeof(CCHmacContext));
    CCHmacUpdate(&hctx, ivec, 4);
    CCHmacFinal(&hctx, U);

    /* T_i = U_1 ... */
    memcpy(T, U, 32);

    for (j = 2; j <= c; j++) {
      /* Compute U_j. */
      CCHmacInit(&hctx, kCCHmacAlgSHA256, passwd, passwdlen);
      CCHmacUpdate(&hctx, U, 32);
      CCHmacFinal(&hctx, U);

      /* ... xor U_j ... */
      for (k = 0; k < 32; k++)
        T[k] ^= U[k];
    }

    /* Copy as many bytes as necessary into buf. */
    clen = dkLen - i * 32;
    if (clen > 32)
      clen = 32;
    memcpy(&buf[i * 32], T, clen);
  }

  /* Clean PShctx, since we never called _Final on it. */
  memset(&PShctx, 0, sizeof(CCHmacContext));
}
