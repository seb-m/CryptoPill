#ifndef CRYPTO_SCHNORR_ID_H_
#define CRYPTO_SCHNORR_ID_H_

#include <stdint.h>

#include "schnorr_keypair.h"


#define SCHNORR_ID_CHALLENGEBYTES 10
#define SCHNORR_ID_RESPONSEBYTES 32


// Schnorr identification scheme
// All these functions return 0 if they succeed or -1 if they fail.

int schnorr_id_commitment(uint8_t pk_r[SCHNORR_PUBLICKEYBYTES],
                          uint8_t sk_r[SCHNORR_SECRETKEYBYTES]);

int schnorr_id_challenge(uint8_t challenge[SCHNORR_ID_CHALLENGEBYTES]);

int schnorr_id_response(uint8_t response[SCHNORR_ID_RESPONSEBYTES],
                        const uint8_t sk[SCHNORR_SECRETKEYBYTES],
                        const uint8_t sk_r[SCHNORR_SECRETKEYBYTES],
                        const uint8_t challenge[SCHNORR_ID_CHALLENGEBYTES]);

int schnorr_id_verify(const uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                      const uint8_t pk_r[SCHNORR_PUBLICKEYBYTES],
                      const uint8_t challenge[SCHNORR_ID_CHALLENGEBYTES],
                      const uint8_t response[SCHNORR_ID_RESPONSEBYTES]);


#endif  // CRYPTO_SCHNORR_ID_H_
