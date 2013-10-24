//
//  CryptoImplementations.m
//  CryptoPill
//
//  Created by Sébastien Martini on 06/08/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "CryptoImplementations.h"

#include "crypto_onetimeauth.h"
#include "crypto_onetimeauth_poly1305_53.h"
#include "crypto_onetimeauth_poly1305_donna.h"


@implementation CryptoImplementations

+ (BOOL)selectCryptoImplementations {
  // Before was using crypto_onetimeauth_poly1305_53_implementation but this
  // more optimized new implementation works fine since this issue has been
  // fixed https://github.com/jedisct1/libsodium/issues/64
  //int result = crypto_onetimeauth_poly1305_set_implementation(&crypto_onetimeauth_poly1305_donna_implementation);

  // Use a more conservative implementation for now.
  int result = crypto_onetimeauth_poly1305_set_implementation(&crypto_onetimeauth_poly1305_53_implementation);

  NSLog(@"Poly1305 implementation used: %s",
        crypto_onetimeauth_poly1305_implementation_name());

  return result == 0;
}

@end
