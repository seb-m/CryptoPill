//
//  Box.m
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "Box.h"

#include "crypto_box.h"

#import "Random.h"
#import "SecureData.h"


@implementation Box

+ (NSData *)boxData:(NSData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey nonce:(NSData *)nonce {
  int ret;

  if (!data ||
      !publicKey || [publicKey length] != crypto_box_publickeybytes() ||
      !secretKey || [secretKey length] != crypto_box_secretkeybytes() ||
      !nonce || [nonce length] != crypto_box_noncebytes())
    return nil;

  NSMutableData *encryptedData = [NSMutableData dataWithData:nonce];
  [encryptedData setLength:crypto_box_noncebytes() + crypto_box_zerobytes() + [data length]];

  // Extend the input data to allocate enough space for the authenticator
  NSMutableData *extendedData = [NSMutableData dataWithLength:crypto_box_zerobytes()];
  [extendedData appendData:data];

  ret = crypto_box([encryptedData mutableBytes] + crypto_box_noncebytes(),
                   [extendedData bytes], [extendedData length],
                   [nonce bytes],
                   [publicKey bytes], [secretKey bytes]);
  if (ret != 0)
    return nil;

  return encryptedData;
}

+ (NSData *)boxSecureData:(SecureData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey nonce:(NSData *)nonce {
  int ret;

  if (!data ||
      !publicKey || [publicKey length] != crypto_box_publickeybytes() ||
      !secretKey || [secretKey length] != crypto_box_secretkeybytes() ||
      !nonce || [nonce length] != crypto_box_noncebytes())
    return nil;

  NSMutableData *encryptedData = [NSMutableData dataWithData:nonce];
  [encryptedData setLength:crypto_box_noncebytes() + crypto_box_zerobytes() + [data length]];

  // Extend the input data to allocate enough space for the authenticator
  SecureData *prefixedData = [SecureData secureDataWithLength:crypto_box_zerobytes() + [data length]];
  [prefixedData copySecureData:data atIndex:crypto_box_zerobytes()];

  ret = crypto_box([encryptedData mutableBytes] + crypto_box_noncebytes(),
                   [prefixedData bytes], [prefixedData length],
                   [nonce bytes],
                   [publicKey bytes], [secretKey bytes]);
  if (ret != 0)
    return nil;

  return encryptedData;
}

+ (NSData *)boxData:(NSData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey {
  // Generate full random nonce
  NSData *nonce = [Random randomData:crypto_box_noncebytes()];
  if (!nonce)
    return nil;

  return [self boxData:data publicKey:publicKey secretKey:secretKey nonce:nonce];
}

+ (NSData *)boxSecureData:(SecureData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey {
  // Generate full random nonce
  NSData *nonce = [Random randomData:crypto_box_noncebytes()];
  if (!nonce)
    return nil;

  return [self boxSecureData:data publicKey:publicKey secretKey:secretKey nonce:nonce];
}

+ (NSData *)boxDataOpen:(NSData *)encryptedData publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey {
  int ret;

  if (!encryptedData || [encryptedData length] < crypto_box_noncebytes() ||
      !publicKey || [publicKey length] != crypto_box_publickeybytes() ||
      !secretKey || [secretKey length] != crypto_box_secretkeybytes())
    return nil;

  NSMutableData *data = [NSMutableData dataWithLength:[encryptedData length] - crypto_box_noncebytes()];

  ret = crypto_box_open([data mutableBytes],
                        [encryptedData bytes] + crypto_box_noncebytes(),
                        [encryptedData length] - crypto_box_noncebytes(),
                        [encryptedData bytes],
                        [publicKey bytes], [secretKey bytes]);
  if (ret != 0)
    return nil;

  return [NSData dataWithBytes:[data bytes] + crypto_box_zerobytes()
                        length:[data length] - crypto_box_zerobytes()];
}

+ (SecureData *)boxSecureDataOpen:(NSData *)encryptedData publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey {
  int ret;

  if (!encryptedData || [encryptedData length] < crypto_box_noncebytes() ||
      !publicKey || [publicKey length] != crypto_box_publickeybytes() ||
      !secretKey || [secretKey length] != crypto_box_secretkeybytes())
    return nil;

  SecureData *data = [SecureData secureDataWithLength:[encryptedData length] - crypto_box_noncebytes()];

  ret = crypto_box_open([data mutableBytes],
                        [encryptedData bytes] + crypto_box_noncebytes(),
                        [encryptedData length] - crypto_box_noncebytes(),
                        [encryptedData bytes],
                        [publicKey bytes], [secretKey bytes]);
  if (ret != 0)
    return nil;

  return [SecureData secureDataWithBytes:[data bytes] + crypto_box_zerobytes()
                                  length:[data length] - crypto_box_zerobytes()];
}

@end
