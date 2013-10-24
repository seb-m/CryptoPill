// Adapted from public domain library NaCL written by D. J. Bernstein.

#include "verify.h"


// Return values:
//  0: success (comparison succeeded)
// -1: verification failed (bytes mismatchs)
int verify_8(const uint8_t *x, const uint8_t *y) {
  unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
  F(0)
  F(1)
  F(2)
  F(3)
  F(4)
  F(5)
  F(6)
  F(7)
  return (1 & ((differentbits - 1) >> 8)) - 1;
}

// Return values:
//  0: success (comparison succeeded)
// -1: verification failed (bytes mismatchs)
int verify_16(const uint8_t *x, const uint8_t *y) {
  unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
  F(0)
  F(1)
  F(2)
  F(3)
  F(4)
  F(5)
  F(6)
  F(7)
  F(8)
  F(9)
  F(10)
  F(11)
  F(12)
  F(13)
  F(14)
  F(15)
  return (1 & ((differentbits - 1) >> 8)) - 1;
}

// Return values:
//  0: success (comparison succeeded)
// -1: verification failed (bytes mismatchs)
int verify_32(const uint8_t *x, const uint8_t *y) {
  unsigned int differentbits = 0;
#define G(i) differentbits |= x[i] ^ y[i];
  G(0)
  G(1)
  G(2)
  G(3)
  G(4)
  G(5)
  G(6)
  G(7)
  G(8)
  G(9)
  G(10)
  G(11)
  G(12)
  G(13)
  G(14)
  G(15)
  G(16)
  G(17)
  G(18)
  G(19)
  G(20)
  G(21)
  G(22)
  G(23)
  G(24)
  G(25)
  G(26)
  G(27)
  G(28)
  G(29)
  G(30)
  G(31)
  return (1 & ((differentbits - 1) >> 8)) - 1;
}
