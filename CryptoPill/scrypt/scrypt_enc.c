//
//  scrypt_enc.c
//  CryptoPill
//
//  Created by Sébastien Martini.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#include "scrypt.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sysendian.h"

#include "rand.h"


int scrypt_enc(const uint8_t *passwd, size_t passwd_len,
               uint64_t N, uint32_t r, uint32_t p,
               uint8_t header[SCRYPT_HEADER_SIZE],
               uint8_t *buf, size_t buf_len) {
  if (SCRYPT_SALT_SIZE != 32 || SCRYPT_SALT_SIZE > 255)
    return -1;

  le64enc(header, N);
  le32enc(header + 8, r);
  le32enc(header + 12, p);
  header[16] = SCRYPT_SALT_SIZE;
  if (crand(header + 17, SCRYPT_SALT_SIZE) == -1)
    return -1;

  return scrypt(passwd, passwd_len,
                header + 17, SCRYPT_SALT_SIZE,
                N, r, p, buf, buf_len);
}

int scrypt_dec(const uint8_t *passwd, size_t passwd_len,
               const uint8_t *header,
               uint8_t *buf, size_t buflen) {
  uint64_t N;
  uint32_t r;
  uint32_t p;
  size_t salt_len;

  salt_len = header[16];
  N = le64dec(header);
  r = le32dec(header + 8);
  p = le32dec(header + 12);

  return scrypt(passwd, passwd_len,
                header + 17, salt_len,
                N, r, p, buf, buflen);
}
