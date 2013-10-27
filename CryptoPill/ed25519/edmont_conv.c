//
//  edmont_conv.c
//  CryptoPill
//
//  Created by Sébastien Martini on 21/06/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#include "edmont_conv.h"

#include "fe25519.h"


int edmont_conv(unsigned char r[crypto_scalarmult_curve25519_BYTES],
                const unsigned char p[ED25519_PUBLICKEYBYTES]) {
  fe25519 u, y, num, den, inv, one;

  fe25519_unpack(&y, p);

  // u = (1 + y) / (1 -y)

  fe25519_setone(&one);
  fe25519_add(&num, &one, &y);

  fe25519_sub(&den, &one, &y);
  fe25519_invert(&inv, &den);

  fe25519_mul(&u, &num, &inv);

  fe25519_pack(r, &u);
  return 0;
}
