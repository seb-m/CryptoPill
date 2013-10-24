#ifndef CRYPTO_VERIFY_H_
#define CRYPTO_VERIFY_H_

#include <stdint.h>


// Return values for all functions:
//   0: success (equality comparison succeeded)
//  -1: verification failed (bytes mismatchs)

// 8 bytes compatisons
int verify_8(const uint8_t *x, const uint8_t *y);

// 16 bytes compatisons
int verify_16(const uint8_t *x, const uint8_t *y);

// 32 bytes compatisons
int verify_32(const uint8_t *x, const uint8_t *y);

#endif  // CRYPTO_VERIFY_H_
