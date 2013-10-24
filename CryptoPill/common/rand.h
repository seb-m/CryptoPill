#ifndef CRYPTO_CRAND_H_
#define CRYPTO_CRAND_H_

#include <stdint.h>
#include <stdlib.h>


// Return 0 on success; -1 on error.
int crand(uint8_t *buffer, size_t len);

#endif  // CRYPTO_CRAND_H_
