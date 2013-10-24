//
//  schnorr_id.c
//  CryptoPill
//
//  Created by Sébastien Martini.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#include "schnorr_id.h"

#include <assert.h>

#include "rand.h"
#include "verify.h"

#include "ge25519.h"
#include "sc25519.h"


static void sc25519_from_challenge_bytes(sc25519 *r,
                                         const uint8_t x[SCHNORR_ID_CHALLENGEBYTES]) {
  assert(SCHNORR_ID_CHALLENGEBYTES <= 32);
  int i;
  for (i = 0; i < SCHNORR_ID_CHALLENGEBYTES; ++i)
    r->v[i] = x[i];
  for (; i < 32; ++i)
    r->v[i] = 0;
}


// Step 1
// pk_r = sk_r.B  with B base point
int schnorr_id_commitment(uint8_t pk_r[SCHNORR_PUBLICKEYBYTES],
                          uint8_t sk_r[SCHNORR_SECRETKEYBYTES]) {
  return schnorr_keypair(pk_r, sk_r);
}

// Step 2
// c in [0, 2^80[
int schnorr_id_challenge(uint8_t challenge[SCHNORR_ID_CHALLENGEBYTES]) {
  return crand(challenge, SCHNORR_ID_CHALLENGEBYTES);
}

// Step 3
// y = (sk_r + c * sk) mod #(B)  with sk secret
int schnorr_id_response(uint8_t response[SCHNORR_ID_RESPONSEBYTES],
                        const uint8_t sk[SCHNORR_SECRETKEYBYTES],
                        const uint8_t sk_r[SCHNORR_SECRETKEYBYTES],
                        const uint8_t challenge[SCHNORR_ID_CHALLENGEBYTES]) {
  sc25519 sc_sk;
  sc25519 sc_sk_r;
  sc25519 sc_challenge;

  sc25519_from32bytes(&sc_sk, sk);
  sc25519_from32bytes(&sc_sk_r, sk_r);
  sc25519_from_challenge_bytes(&sc_challenge, challenge);

  sc25519_mul(&sc_sk, &sc_sk, &sc_challenge);
  sc25519_add(&sc_sk, &sc_sk, &sc_sk_r);

  sc25519_to32bytes(response, &sc_sk);
  return 0;
}

// Step 3 bis
// verify pk_r = y.B - c.pk  with pk = sk.B
int schnorr_id_verify(const uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                      const uint8_t pk_r[SCHNORR_PUBLICKEYBYTES],
                      const uint8_t challenge[SCHNORR_ID_CHALLENGEBYTES],
                      const uint8_t response[SCHNORR_ID_RESPONSEBYTES]) {
  ge25519 ge_pk_neg;
  sc25519 sc_challenge;
  sc25519 sc_response;
  ge25519 ge_pk_r_verifier;
  uint8_t pk_r_verifier[SCHNORR_PUBLICKEYBYTES];


  if (ge25519_unpackneg_vartime(&ge_pk_neg, pk))
    return -1;

  sc25519_from_challenge_bytes(&sc_challenge, challenge);
  sc25519_from32bytes(&sc_response, response);

  ge25519_double_scalarmult_vartime(&ge_pk_r_verifier,
                                    &ge_pk_neg, &sc_challenge,
                                    &ge25519_base, &sc_response);
  ge25519_pack(pk_r_verifier, &ge_pk_r_verifier);
  return verify_32(pk_r, pk_r_verifier);
}
