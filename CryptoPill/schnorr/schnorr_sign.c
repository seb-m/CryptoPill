//
//  schnorr_sign.c
//  CryptoPill
//
//  Created by Sébastien Martini.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#include "schnorr_sign.h"

#include <CommonCrypto/CommonDigest.h>

#include "verify.h"

#include "ge25519.h"
#include "sc25519.h"


static int schnorr_sign_challenge_sha512(uint8_t digest[CC_SHA512_DIGEST_LENGTH],
                                         const uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                                         const uint8_t pk_r[SCHNORR_PUBLICKEYBYTES],
                                         const uint8_t *message, size_t message_len) {
  CC_SHA512_CTX ctx;

  CC_SHA512_Init(&ctx);
  CC_SHA512_Update(&ctx, pk, SCHNORR_PUBLICKEYBYTES);
  CC_SHA512_Update(&ctx, pk_r, SCHNORR_PUBLICKEYBYTES);
  if (message != NULL)
    CC_SHA512_Update(&ctx, message, (CC_LONG)message_len);
  CC_SHA512_Final(digest, &ctx);
  return 0;
}


// Return the signature (R, s)
int schnorr_sign(uint8_t signature[SCHNORR_SIGN_SIGNATUREBYTES],
                 const uint8_t sk[SCHNORR_SECRETKEYBYTES],
                 const uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                 const uint8_t *message, size_t message_len) {
  uint8_t sk_r[SCHNORR_SECRETKEYBYTES];
  sc25519 sc_sk_r;
  ge25519 ge_pk_r;
  uint8_t digest[CC_SHA512_DIGEST_LENGTH];
  sc25519 sc_digest;
  sc25519 sc_sk;
  sc25519 sc_s;
  int result;

  // R = r.B with B base point
  result = schnorr_secretkey(sk_r);
  if (result)
    return -1;

  sc25519_from32bytes(&sc_sk_r, sk_r);
  ge25519_scalarmult_base(&ge_pk_r, &sc_sk_r);
  ge25519_pack(signature, &ge_pk_r);

  // h = sha512(pk, R, message)
  result = schnorr_sign_challenge_sha512(digest, pk, signature,
                                         message, message_len);
  if (result)
    return -1;

  sc25519_from64bytes(&sc_digest, digest);
  sc25519_from32bytes(&sc_sk, sk);

  // s = (r + h * sk) mod #(B)
  sc25519_mul(&sc_s, &sc_digest, &sc_sk);
  sc25519_add(&sc_s, &sc_s, &sc_sk_r);

  sc25519_to32bytes(signature + 32, &sc_s);
  return 0;
}

int schnorr_sign_verify(const uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                        const uint8_t signature[SCHNORR_SIGN_SIGNATUREBYTES],
                        const uint8_t *message, size_t message_len) {
  ge25519 ge_pk_neg;
  uint8_t digest[CC_SHA512_DIGEST_LENGTH];
  sc25519 sc_digest;
  sc25519 sc_s;
  ge25519 ge_pk_r_verifier;
  uint8_t pk_r_verifier[SCHNORR_PUBLICKEYBYTES];
  int result;

  result = ge25519_unpackneg_vartime(&ge_pk_neg, pk);
  if (result)
    return -1;

  // h = sha512(pk, R, message)
  result = schnorr_sign_challenge_sha512(digest, pk, signature,
                                         message, message_len);
  if (result)
    return -1;

  sc25519_from64bytes(&sc_digest, digest);
  sc25519_from32bytes(&sc_s, signature + 32);

  // s.B - h.pk ?= R
  ge25519_double_scalarmult_vartime(&ge_pk_r_verifier,
                                    &ge_pk_neg, &sc_digest,
                                    &ge25519_base, &sc_s);

  ge25519_pack(pk_r_verifier, &ge_pk_r_verifier);
  return verify_32(signature, pk_r_verifier);
}
