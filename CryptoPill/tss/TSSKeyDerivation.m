//
//  TSSKeyDerivation.m
//  CryptoPill
//
//  Created by Sébastien Martini on 07/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "TSSKeyDerivation.h"

#include "tss.h"
#include "verify.h"

#import "NSArray+Concat.h"
#import "Curve25519.h"
#import "SchnorrKeypair.h"
#import "SecureData.h"
#import "SecureData+HKDF.h"
#import "TSSShare.h"


@implementation TSSKeyDerivation

+ (SecureData *)secretKeyForShare:(SecureData *)share {
  if (!share)
    return nil;

  int ret;

  tss_ctx tssCtx;
  ret = tss_recover_init(&tssCtx);
  if (ret != 0)
    return nil;

  ret = tss_recover_add(&tssCtx, [share bytes]);
  if (ret < 0) {
    tss_free(&tssCtx);
    return nil;
  }

  NSInteger index = ret;
  NSData *identifier = [NSData dataWithBytes:tssCtx.identifier length:kTSSIdentifierSize];
  SecureData *shareSecret = [SecureData secureDataWithBytes:tssCtx.shares[index]
                                                     length:tssCtx.secret_len];
  NSAssert([shareSecret length] >= kCurve25519ScalarSize,
           @"insufficient secret data size");
  tss_free(&tssCtx);
  if (!identifier || !shareSecret)
    return nil;

  NSArray *infos = @[@"share_public_key", identifier, @(index)];
  NSData *concatanatedInfos = [infos concatToData];
  SecureData *derivedKey = [SecureData hkdfForKey:shareSecret
                                             info:concatanatedInfos
                                 derivedKeyLength:kCurve25519ScalarSize];
  if (!derivedKey)
    return nil;

  // Format Curve25519 scalar value
  ((uint8_t *)[derivedKey mutableBytes])[0] &= 248;
  ((uint8_t *)[derivedKey mutableBytes])[31] &= 127;
  ((uint8_t *)[derivedKey mutableBytes])[31] |= 64;
  return derivedKey;
}

+ (NSData *)publicKeyForShare:(SecureData *)share {
  SecureData *secretKey = [self secretKeyForShare:share];
  if (!secretKey)
    return nil;
  // Use this method because Schnorr will need a point on Edward curve.
  return [SchnorrKeypair publicKeyFromSecretKey:secretKey];
}

+ (BOOL)checkShare:(SecureData *)share withPublicKey:(NSData *)publicKey {
  NSAssert(kCurve25519PublicKeySize == kSchnorrPublicKeySize, nil);

  if (!publicKey || [publicKey length] != kSchnorrPublicKeySize)
    return NO;

  NSData *recoveredPublicKey = [self publicKeyForShare:share];
  if (!recoveredPublicKey || [recoveredPublicKey length] != kSchnorrPublicKeySize)
    return NO;

  if (verify_32([publicKey bytes], [recoveredPublicKey bytes]) != 0)
    return NO;
  return YES;
}

@end
