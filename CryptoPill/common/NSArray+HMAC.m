//
//  NSArray+HMAC.m
//  CryptoPill
//
//  Created by Sébastien Martini on 18/07/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "NSArray+HMAC.h"

#include <CommonCrypto/CommonHMAC.h>

#import "SecureData.h"


@implementation NSArray (HMAC)

- (NSData *)hmacSha256WithKey:(SecureData *)key {
  if (!key)
    return nil;

  CCHmacContext ctx;
  CCHmacInit(&ctx, kCCHmacAlgSHA256, [key bytes], [key length]);

  for (id item in self) {
    NSAssert([item isKindOfClass:[NSData class]], @"Item must be an NSData");

    NSData *itemData = (NSData *)item;

    CCHmacUpdate(&ctx, [itemData bytes], [itemData length]);
  }

  NSMutableData *macOut = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
  CCHmacFinal(&ctx, [macOut mutableBytes]);
  return macOut;
}

@end
