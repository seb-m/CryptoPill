//
//  rand.c
//  CryptoPill
//
//  Created by Sébastien Martini on 21/06/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#include "rand.h"

#include <Security/SecRandom.h>


// Get len random bytes from /dev/random.
int crand(uint8_t *buffer, size_t len) {
  if (buffer == NULL)
    return -1;

  return SecRandomCopyBytes(kSecRandomDefault, len, buffer);
}
