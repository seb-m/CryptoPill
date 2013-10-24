//
//  SecureData.m
//  CryptoPill
//
//  Created by Sébastien Martini on 11/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SecureData.h"

#include <stdlib.h>
#include <string.h>

#include "utils.h"  //libsodium

#include "verify.h"


@interface SecureData () {
  void *_data;
}

@end


@implementation SecureData

- (id)initWithBytes:(const void *)bytes length:(NSUInteger)length {
  self = [super init];
  if (self) {
    if (bytes == NULL)
      return nil;

    _data = calloc(length, 1);
    if (_data == NULL)
      return nil;

    memcpy(_data, bytes, length);
    _length = length;
  }
  return self;
}

- (id)initWithBytesNoCopy:(void *)bytes length:(NSUInteger)length {
  self = [super init];
  if (self) {
    if (bytes == NULL)
      return nil;

    _data = bytes;
    _length = length;
  }
  return self;
}

- (id)initWithLength:(NSUInteger)length {
  self = [super init];
  if (self) {
    _data = calloc(length, 1);
    if (_data == NULL)
      return nil;
    _length = length;
  }
  return self;
}

- (void)dealloc {
  if (_data != NULL) {
    sodium_memzero(_data, self.length);
    free(_data);
  }
}

+ (instancetype)secureDataWithBytes:(const void *)bytes length:(NSUInteger)length {
  return [[[self class] alloc] initWithBytes:bytes length:length];
}

+ (instancetype)secureDataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length {
  return [[[self class] alloc] initWithBytesNoCopy:bytes length:length];
}

+ (instancetype)secureDataWithLength:(NSUInteger)length {
  return [[[self class] alloc] initWithLength:length];
}

+ (instancetype)secureDataWithSecureData:(SecureData *)secureData {
  return [self secureDataWithBytes:[secureData bytes] length:[secureData length]];
}

- (void)copyBuffer:(const void *)buffer bufferLength:(NSUInteger)bufferLength atIndex:(NSUInteger)index {
  if (buffer == NULL || index >= self.length || bufferLength > self.length - index)
    return;

  memcpy(_data + index, buffer, bufferLength);
}


#pragma mark - NSCopying protocol method

- (id)copyWithZone:(NSZone *)zone {
  return [[self class] secureDataWithBytes:[self bytes] length:self.length];
}


#pragma mark - NSSecureCoding protocol methods

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (id)initWithCoder:(NSCoder *)coder {
  if (!coder)
    return nil;

  NSUInteger decodedBytesLength;
  const uint8_t *decodedBytes = [coder decodeBytesForKey:@"data"
                                          returnedLength:&decodedBytesLength];
  if (decodedBytes == NULL)
    return nil;

  return [self initWithBytes:decodedBytes length:decodedBytesLength];
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeBytes:_data length:self.length forKey:@"data"];
}


#pragma mark - Public methods

- (const void *)bytes {
  return _data;
}

- (void *)mutableBytes {
  return _data;
}

- (void)copySecureData:(SecureData *)data atIndex:(NSUInteger)index {
  if (!data)
    return;
  [self copyBuffer:[data bytes] bufferLength:[data length] atIndex:index];
}


- (BOOL)isEqualToSecureData:(SecureData *)data {
  if (!data || self.length != data.length)
    return NO;
  return memcmp(_data, [data bytes], self.length) == 0;
}


#pragma mark - Unsecure methods

+ (instancetype)secureDataWithUnprotectedData:(NSData *)data {
  if (!data)
    return nil;
  return [[[self class] alloc] initWithBytes:[data bytes] length:[data length]];
}

- (NSData *)unprotectedData {
  return [NSData dataWithBytes:_data length:self.length];
}

- (void)copyUnprotectedData:(NSData *)data atIndex:(NSUInteger)index {
  if (!data)
    return;
  [self copyBuffer:[data bytes] bufferLength:[data length] atIndex:index];
}

@end
