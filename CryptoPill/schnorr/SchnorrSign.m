//
//  SchnorrSign.m
//  CryptoPill
//
//  Created by Sébastien Martini on 04/10/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SchnorrSign.h"

#include "schnorr_sign.h"

#import "SecureData.h"


const NSUInteger kSchnorrSignatureKeySize = SCHNORR_SIGN_SIGNATUREBYTES;


@implementation SchnorrSign

+ (NSData *)signData:(NSData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey {
  int ret;

  if (!publicKey || !secretKey)
    return nil;

  NSMutableData *signature = [NSMutableData dataWithLength:SCHNORR_SIGN_SIGNATUREBYTES];

  ret = schnorr_sign([signature mutableBytes], [secretKey bytes],
                     [publicKey bytes], [data bytes], [data length]);
  if (ret)
    return nil;
  return signature;
}

+ (BOOL)verifySignature:(NSData *)signature forData:(NSData *)data publicKey:(NSData *)publicKey {
  int ret;

  if (!signature || !publicKey)
    return NO;

  ret = schnorr_sign_verify([publicKey bytes], [signature bytes],
                            [data bytes], [data length]);
  return ret == 0;
}

@end
