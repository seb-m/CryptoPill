//
//  NSArray+Concat.m
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "NSArray+Concat.h"


@implementation NSArray (Concat)

- (NSData *)concatToData {
  if ([self count] == 0)
    return nil;

  NSMutableData *data = [NSMutableData data];

  for (id item in self) {
    if ([item isKindOfClass:[NSString class]]) {
      [data appendData:[(NSString *)item dataUsingEncoding:NSUTF8StringEncoding]];
      continue;
    }

    if ([item isKindOfClass:[NSData class]]) {
      [data appendData:item];
      continue;
    }

    if ([item isKindOfClass:[NSNumber class]]) {
      [data appendData:[[(NSNumber *)item stringValue]
                        dataUsingEncoding:NSUTF8StringEncoding]];
      continue;
    }

    return nil;
  }

  return data;
}

@end
