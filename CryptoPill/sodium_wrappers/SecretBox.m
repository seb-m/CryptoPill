//
//  SecretBox.m
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SecretBox.h"

#include "crypto_secretbox.h"

#include "scrypt.h"

#import "Random.h"
#import "SecureData.h"


// Values proposed in 2009: N=2^20 (file encryption, <= 5s), also proposed 2^14
// (interactive logins, <= 100ms).
// http://www.tarsnap.com/scrypt.html
//
// Tests for N on iPod touch 5th gen with iOS 7.0 (with r=8 and p=1):
// 2^14: 6s
// 2^15: 12s
// 2^16: 24s

const uint64_t kScryptNDefault = 32768;
const uint64_t kScryptNAlternative1 = 65536;
const uint32_t kScryptrDefault = 8;
const uint32_t kScryptpDefault = 1;


static BOOL validScryptParameters(uint64_t N, uint32_t r, uint32_t p) {
  if (N < kScryptNDefault || r < kScryptrDefault || p < kScryptpDefault)
    return NO;
  return YES;
}


@implementation SecretBox

+ (SecureData *)secretBoxGenerateKey {
  return [Random randomSecureData:crypto_secretbox_keybytes()];
}

+ (NSData *)secretBoxData:(NSData *)data key:(SecureData *)key nonce:(NSData *)nonce {
  int ret;

  if (!data ||
      !key || [key length] != crypto_secretbox_keybytes() ||
      !nonce || [nonce length] != crypto_secretbox_noncebytes())
    return nil;

  NSMutableData *encryptedData = [NSMutableData dataWithData:nonce];
  [encryptedData setLength:crypto_secretbox_noncebytes() + crypto_secretbox_zerobytes() + [data length]];

  // Extend the input data to allocate enough space for the authenticator
  NSMutableData *extendedData = [NSMutableData dataWithLength:crypto_secretbox_zerobytes()];
  [extendedData appendData:data];

  ret = crypto_secretbox([encryptedData mutableBytes] + crypto_secretbox_noncebytes(),
                         [extendedData bytes], [extendedData length],
                         [nonce bytes],
                         [key bytes]);
  if (ret != 0)
    return nil;

  return encryptedData;
}

+ (NSData *)secretBoxSecureData:(SecureData *)data key:(SecureData *)key nonce:(NSData *)nonce {
  int ret;

  if (!data ||
      !key || [key length] != crypto_secretbox_keybytes() ||
      !nonce || [nonce length] != crypto_secretbox_noncebytes())
    return nil;

  NSMutableData *encryptedData = [NSMutableData dataWithData:nonce];
  [encryptedData setLength:crypto_secretbox_noncebytes() + crypto_secretbox_zerobytes() + [data length]];

  // Extend the input data to allocate enough space for the authenticator
  SecureData *prefixedData = [SecureData secureDataWithLength:crypto_secretbox_zerobytes() + [data length]];
  [prefixedData copySecureData:data atIndex:crypto_secretbox_zerobytes()];

  ret = crypto_secretbox([encryptedData mutableBytes] + crypto_secretbox_noncebytes(),
                         [prefixedData bytes], [prefixedData length],
                         [nonce bytes],
                         [key bytes]);
  if (ret != 0)
    return nil;

  return encryptedData;
}

+ (NSData *)secretBoxData:(NSData *)data key:(SecureData *)key {
  // Generate full random nonce
  NSData *nonce = [Random randomData:crypto_secretbox_noncebytes()];
  if (!nonce)
    return nil;

  return [self secretBoxData:data key:key nonce:nonce];
}

+ (NSData *)secretBoxSecureData:(SecureData *)data key:(SecureData *)key {
  // Generate full random nonce
  NSData *nonce = [Random randomData:crypto_secretbox_noncebytes()];
  if (!nonce)
    return nil;

  return [self secretBoxSecureData:data key:key nonce:nonce];
}

+ (NSData *)secretBoxData:(NSData *)data password:(SecureData *)password N:(uint64_t)N r:(uint32_t)r p:(uint32_t)p {
  int ret;

  if (!data || !password || !validScryptParameters(N, r, p))
    return nil;

  NSMutableData *encryptedData = [NSMutableData dataWithLength:SCRYPT_HEADER_SIZE];
  SecureData *secretKey = [SecureData secureDataWithLength:crypto_secretbox_keybytes()];

  ret = scrypt_enc([password bytes], [password length],
                   N, r, p,
                   [encryptedData mutableBytes],
                   [secretKey mutableBytes], crypto_secretbox_keybytes());
  if (ret != 0)
    return nil;

  NSData *boxedData = [self secretBoxData:data key:secretKey];
  if (!boxedData)
    return nil;

  [encryptedData appendData:boxedData];
  return encryptedData;
}

+ (NSData *)secretBoxSecureData:(SecureData *)data password:(SecureData *)password N:(uint64_t)N r:(uint32_t)r p:(uint32_t)p {
  int ret;

  if (!data || !password || !validScryptParameters(N, r, p))
    return nil;

  NSMutableData *encryptedData = [NSMutableData dataWithLength:SCRYPT_HEADER_SIZE];
  SecureData *secretKey = [SecureData secureDataWithLength:crypto_secretbox_keybytes()];

  ret = scrypt_enc([password bytes], [password length],
                   N, r, p,
                   [encryptedData mutableBytes],
                   [secretKey mutableBytes], crypto_secretbox_keybytes());
  if (ret != 0)
    return nil;

  NSData *boxedData = [self secretBoxSecureData:data key:secretKey];
  if (!boxedData)
    return nil;

  [encryptedData appendData:boxedData];
  return encryptedData;
}

+ (NSData *)secretBoxDataOpen:(NSData *)encryptedData key:(SecureData *)key {
  int ret;

  if (!encryptedData || [encryptedData length] < crypto_secretbox_noncebytes() ||
      !key || [key length] != crypto_secretbox_keybytes())
    return nil;

  NSMutableData *data = [NSMutableData dataWithLength:[encryptedData length] - crypto_secretbox_noncebytes()];

  ret = crypto_secretbox_open([data mutableBytes],
                              [encryptedData bytes] + crypto_secretbox_noncebytes(),
                              [encryptedData length] - crypto_secretbox_noncebytes(),
                              [encryptedData bytes],
                              [key bytes]);
  if (ret != 0)
    return nil;

  return [NSData dataWithBytes:[data bytes] + crypto_secretbox_zerobytes()
                        length:[data length] - crypto_secretbox_zerobytes()];
}

+ (SecureData *)secretBoxSecureDataOpen:(NSData *)encryptedData key:(SecureData *)key {
  int ret;

  if (!encryptedData || [encryptedData length] < crypto_secretbox_noncebytes() ||
      !key || [key length] != crypto_secretbox_keybytes())
    return nil;

  SecureData *data = [SecureData secureDataWithLength:[encryptedData length] - crypto_secretbox_noncebytes()];

  ret = crypto_secretbox_open([data mutableBytes],
                              [encryptedData bytes] + crypto_secretbox_noncebytes(),
                              [encryptedData length] - crypto_secretbox_noncebytes(),
                              [encryptedData bytes],
                              [key bytes]);
  if (ret != 0)
    return nil;

  return [SecureData secureDataWithBytes:[data bytes] + crypto_secretbox_zerobytes()
                                  length:[data length] - crypto_secretbox_zerobytes()];
}

+ (NSData *)secretBoxDataOpen:(NSData *)encryptedData password:(SecureData *)password {
  int ret;

  if (!password || !encryptedData || [encryptedData length] < SCRYPT_HEADER_SIZE)
    return nil;

  SecureData *secretKey = [SecureData secureDataWithLength:crypto_secretbox_keybytes()];

  ret = scrypt_dec([password bytes], [password length],
                   [encryptedData bytes],
                   [secretKey mutableBytes], crypto_secretbox_keybytes());
  if (ret != 0)
    return nil;

  NSRange range = {SCRYPT_HEADER_SIZE, [encryptedData length] - SCRYPT_HEADER_SIZE};
  return [self secretBoxDataOpen:[encryptedData subdataWithRange:range]
                             key:secretKey];
}

+ (SecureData *)secretBoxSecureDataOpen:(NSData *)encryptedData password:(SecureData *)password {
  int ret;

  if (!password || !encryptedData || [encryptedData length] < SCRYPT_HEADER_SIZE)
    return nil;

  SecureData *secretKey = [SecureData secureDataWithLength:crypto_secretbox_keybytes()];

  ret = scrypt_dec([password bytes], [password length],
                   [encryptedData bytes],
                   [secretKey mutableBytes], crypto_secretbox_keybytes());
  if (ret != 0)
    return nil;

  NSRange range = {SCRYPT_HEADER_SIZE, [encryptedData length] - SCRYPT_HEADER_SIZE};
  return [self secretBoxSecureDataOpen:[encryptedData subdataWithRange:range]
                                   key:secretKey];
}

+ (NSData *)secretBoxRemoveZeroBytes:(NSData *)encryptedData {
  if (!encryptedData || [encryptedData length] < crypto_secretbox_zerobytes())
    return nil;

  return [NSData dataWithBytes:([encryptedData bytes] + crypto_secretbox_zerobytes())
                        length:([encryptedData length] - crypto_secretbox_zerobytes())];
}

+ (NSData *)secretBoxInsertZeroBytes:(NSData *)encryptedData {
   if (!encryptedData)
     return nil;

  NSMutableData *encryptedDataWithZeroBytes = [NSMutableData dataWithLength:crypto_secretbox_zerobytes()];
  [encryptedDataWithZeroBytes appendData:encryptedData];
  return encryptedDataWithZeroBytes;
}

@end
