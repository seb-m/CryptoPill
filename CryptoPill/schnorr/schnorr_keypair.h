#ifndef CRYPTO_SCHNORR_KEYPAIR_H_
#define CRYPTO_SCHNORR_KEYPAIR_H_

#include <stdint.h>


#define SCHNORR_PUBLICKEYBYTES 32
#define SCHNORR_SECRETKEYBYTES 32


// Schnorr keys operations
// All these functions return 0 if they succeed or -1 if they fail.

int schnorr_secretkey(uint8_t sk[SCHNORR_SECRETKEYBYTES]);

int schnorr_publickey(uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                      const uint8_t sk[SCHNORR_SECRETKEYBYTES]);

int schnorr_keypair(uint8_t pk[SCHNORR_PUBLICKEYBYTES],
                    uint8_t sk[SCHNORR_SECRETKEYBYTES]);

#endif  // CRYPTO_SCHNORR_KEYPAIR_H_
