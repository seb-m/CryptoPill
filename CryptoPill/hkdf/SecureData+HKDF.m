//
//  SecureData+HKDF.m
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SecureData+HKDF.h"

#include <CommonCrypto/CommonHMAC.h>

#include "hkdf.h"

#import "SecureData.h"


@implementation SecureData (HKDF)

+ (SecureData *)hkdfForKey:(SecureData *)key info:(NSData *)info derivedKeyLength:(NSUInteger)derivedKeyLength {
  int ret;

  if (!key)
    return nil;

  const void *infoBytes;
  if (info)
    infoBytes = [info bytes];
  else
    infoBytes = NULL;

  SecureData *derivedKey = [SecureData secureDataWithLength:derivedKeyLength];

  ret = hkdf(kCCHmacAlgSHA256,
             NULL, 0,
             [key bytes], (int)[key length],
             infoBytes, (int)[info length],
             [derivedKey mutableBytes], (int)derivedKeyLength);
  if (ret != 0)
    return nil;

  return derivedKey;
}

@end
