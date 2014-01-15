//
//  NSData+Hex.m
//  CryptoPill
//
//  Created by Sébastien Martini on 28/06/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "NSData+Hex.h"


@implementation NSData (Hex)

- (NSString *)hexadecimalEncodingFormatted {
  if ([self length] == 0)
    return nil;
  NSMutableString *hex = [NSMutableString stringWithCapacity:[self length] * 3];
  for (NSInteger i = 0; i < [self length]; ++i) {
    [hex appendFormat:@"%02X ", *((uint8_t *)[self bytes] + i)];
    if ((i % 8 == 7) && (i + 1 < [self length]))
      [hex appendString:@"\n"];
  }
  return [NSString stringWithString:hex];
}

- (NSString *)hexadecimalEncodingCompact {
  if ([self length] == 0)
    return nil;
  NSMutableString *hex = [NSMutableString stringWithCapacity:[self length] * 2];
  for (NSInteger i = 0; i < [self length]; ++i)
    [hex appendFormat:@"%02X", *((uint8_t *)[self bytes] + i)];
  return [NSString stringWithString:hex];
}

@end
