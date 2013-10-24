//
//  NSData+Digest.m
//  CryptoPill
//
//  Created by Sébastien Martini on 24/06/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "NSData+Digest.h"

#include <CommonCrypto/CommonDigest.h>

#import "NSData+Hex.h"


@implementation NSData (Digest)

- (NSData *)sha256 {
  NSMutableData *digestData = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
  CC_SHA256([self bytes], (CC_LONG)[self length], [digestData mutableBytes]);
  return digestData;
}

- (NSString *)stringSHA256 {
  return [[self sha256] hexadecimalEncodingCompact];
}

@end
