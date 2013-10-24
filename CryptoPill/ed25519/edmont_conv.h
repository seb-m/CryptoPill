//
//  edmont_conv.h
//  CryptoPill
//
//  Created by Sébastien Martini on 21/06/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#ifndef CRYPTO_EDMONT_CONV_H_
#define CRYPTO_EDMONT_CONV_H_

#include "crypto_scalarmult_curve25519.h"


#define ED25519_PUBLICKEYBYTES 32


// Convert a packed edwards point (y with x's sign) to montgomery x coordinate.
// Typically p is the result of ge25519_pack.
int edmont_conv(unsigned char r[crypto_scalarmult_curve25519_BYTES],
                const unsigned char p[ED25519_PUBLICKEYBYTES]);

#endif  // CRYPTO_EDMONT_CONV_H_
