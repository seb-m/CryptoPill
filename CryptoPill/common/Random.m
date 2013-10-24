//
//  Random.m
//  CryptoPill
//
//  Created by Sébastien Martini on 07/06/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "Random.h"

#include <Security/SecRandom.h>

#import "SecureData.h"


// Source code of SecRandomCopyBytes()
// http://opensource.apple.com/source/Security/Security-55179.11/sec/Security/SecFramework.c


@implementation Random

+ (NSData *)randomData:(size_t)len {
  NSMutableData *data = [NSMutableData dataWithLength:len];
  int ret = SecRandomCopyBytes(kSecRandomDefault, len, [data mutableBytes]);
  if (ret == -1)
    return nil;
  return data;
}

+ (SecureData *)randomSecureData:(size_t)len {
  SecureData *data = [SecureData secureDataWithLength:len];
  int ret = SecRandomCopyBytes(kSecRandomDefault, len, [data mutableBytes]);
  if (ret == -1)
    return nil;
  return data;
}

@end
