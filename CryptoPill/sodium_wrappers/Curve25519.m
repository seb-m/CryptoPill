//
//  Curve25519.m
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "Curve25519.h"

#include "crypto_scalarmult_curve25519.h"

#include "edmont_conv.h"

#import "Random.h"
#import "SecureData.h"


const NSUInteger kCurve25519ScalarSize = crypto_scalarmult_curve25519_SCALARBYTES;
const NSUInteger kCurve25519PublicKeySize = crypto_scalarmult_curve25519_BYTES;


@implementation Curve25519

+ (SecureData *)scalarmultCurve25519GenerateScalar {
  SecureData *scalar = [Random randomSecureData:kCurve25519ScalarSize];
  if (!scalar)
    return nil;
  ((uint8_t *)[scalar mutableBytes])[0] &= 248;
  ((uint8_t *)[scalar mutableBytes])[31] &= 127;
  ((uint8_t *)[scalar mutableBytes])[31] |= 64;
  return scalar;
}

+ (NSData *)scalarmultCurve25519BaseWithScalar:(SecureData *)scalar {
  if (!scalar || [scalar length] != kCurve25519ScalarSize)
    return nil;

  NSMutableData *product = [NSMutableData dataWithLength:kCurve25519PublicKeySize];

  int ret = crypto_scalarmult_curve25519_base([product mutableBytes], [scalar bytes]);
  if (ret != 0)
    return nil;

  return product;
}

+ (SecureData *)scalarmultCurve25519WithScalar:(SecureData *)scalar publicKey:(NSData *)publicKey {
  if (!scalar || [scalar length] != kCurve25519ScalarSize ||
      !publicKey || [publicKey length] != kCurve25519PublicKeySize)
    return nil;

  SecureData *product = [SecureData secureDataWithLength:kCurve25519PublicKeySize];

  int ret = crypto_scalarmult_curve25519([product mutableBytes], [scalar bytes],
                                         [publicKey bytes]);
  if (ret != 0)
    return nil;

  return product;
}

+ (NSData *)publicKeyFromEd25519PublicKey:(NSData *)ed25519PublicKey {
  if (!ed25519PublicKey || [ed25519PublicKey length] != ED25519_PUBLICKEYBYTES)
    return nil;

  NSMutableData *curve25519PublicKey = [NSMutableData dataWithLength:kCurve25519PublicKeySize];
  int ret = edmont_conv([curve25519PublicKey mutableBytes],
                        [ed25519PublicKey bytes]);
  if (ret)
    return nil;
  return curve25519PublicKey;
}

@end
