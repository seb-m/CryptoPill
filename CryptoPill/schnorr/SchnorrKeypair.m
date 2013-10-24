//
//  SchnorrKeypair.m
//  CryptoPill
//
//  Created by Sébastien Martini on 12/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SchnorrKeypair.h"

#include "schnorr_keypair.h"

#import "SecureData.h"


const NSUInteger kSchnorrSecretKeySize = SCHNORR_SECRETKEYBYTES;
const NSUInteger kSchnorrPublicKeySize = SCHNORR_PUBLICKEYBYTES;


@implementation SchnorrKeypair

+ (SecureData *)generateSecretKey {
  SecureData *secretKey = [SecureData secureDataWithLength:SCHNORR_SECRETKEYBYTES];
  int ret = schnorr_secretkey([secretKey mutableBytes]);
  if (ret != 0)
    return nil;
  return secretKey;
}

+ (NSData *)publicKeyFromSecretKey:(SecureData *)secretKey {
  NSMutableData *publicKey = [NSMutableData dataWithLength:SCHNORR_PUBLICKEYBYTES];
  int ret = schnorr_publickey([publicKey mutableBytes], [secretKey bytes]);
  if (ret != 0)
    return nil;
  return publicKey;
}

@end
