#ifndef CRYPTO_SCHNORR_SIGN_H_
#define CRYPTO_SCHNORR_SIGN_H_

#include <stdint.h>
#include <stdlib.h>

#include "schnorr_keypair.h"


#define SCHNORR_SIGN_SIGNATUREBYTES 64


// Schnorr signature scheme
// All these functions return 0 if they succeed or -1 if they fail.

// pk = sk.B, message can be NULL (in that case message_len is ignored).
int schnorr_sign(uint8_t signature[SCHNORR_SIGN_SIGNATUREBYTES],
                 const uint8_t sk[SCHNORR_SECRETKEYBYTES],
                 const uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                 const uint8_t *message, size_t message_len);

// Return 0 if the signature is valid; -1 otherwise.
int schnorr_sign_verify(const uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                        const uint8_t signature[SCHNORR_SIGN_SIGNATUREBYTES],
                        const uint8_t *message, size_t message_len);


#endif  // CRYPTO_SCHNORR_SIGN_H_
