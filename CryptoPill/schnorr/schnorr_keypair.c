//
//  schnorr_keypair.c
//  CryptoPill
//
//  Created by Sébastien Martini.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#include "schnorr_keypair.h"

#include "rand.h"

#include "ge25519.h"
#include "sc25519.h"


int schnorr_secretkey(uint8_t sk[SCHNORR_SECRETKEYBYTES]) {
  if (crand(sk, SCHNORR_SECRETKEYBYTES) == -1)
    return -1;
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;
  return 0;
}

int schnorr_publickey(uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                      const uint8_t sk[SCHNORR_SECRETKEYBYTES]) {
  sc25519 sc_sk;
  ge25519 ge_pk;

  sc25519_from32bytes(&sc_sk, sk);

  ge25519_scalarmult_base(&ge_pk, &sc_sk);
  ge25519_pack(pk, &ge_pk);
  return 0;
}

int schnorr_keypair(uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                    uint8_t sk[SCHNORR_SECRETKEYBYTES]) {
  int ret;

  ret = schnorr_secretkey(sk);
  if (ret != 0)
    return ret;

  ret = schnorr_publickey(pk, sk);
  if (ret != 0)
    return ret;

  return 0;
}
