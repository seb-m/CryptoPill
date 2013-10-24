//
//  TSSShare.m
//  CryptoPill
//
//  Created by Sébastien Martini on 05/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "TSSShare.h"

#include "tss.h"

#import "Random.h"
#import "SecureData.h"


const NSUInteger kTSSIdentifierSize = TSS_IDENTIFIER_SIZE;


@interface TSSShare () {
  tss_ctx _tssCtx;
}

@end


@implementation TSSShare

- (id)initWithSecret:(SecureData *)secret threshold:(NSUInteger)threshold identifier:(NSData *)identifier {
  if (threshold == 0 || threshold > 254 || !secret || !identifier ||
      [identifier length] != TSS_IDENTIFIER_SIZE)
    return nil;

  self = [super init];
  if (self) {
    _identifier = identifier;
    _threshold = threshold;
    int ret = tss_share_init(&_tssCtx, [_identifier bytes], threshold,
                             TSS_SHA256, [secret bytes], [secret length]);
    if (ret != 0)
      return nil;
  }
  return self;
}

- (id)initWithSecret:(SecureData *)secret threshold:(NSUInteger)threshold {
  NSData *identifier = [Random randomData:TSS_IDENTIFIER_SIZE];
  if (!identifier)
    return nil;
  return [self initWithSecret:secret threshold:threshold identifier:identifier];
}

- (void)dealloc {
  tss_free(&_tssCtx);
}


- (SecureData *)shareAtIndex:(NSUInteger)index {
  SecureData *share = [SecureData secureDataWithLength:tss_share_size(&_tssCtx)];
  int ret = tss_share(&_tssCtx, index, [share mutableBytes]);
  if (ret != 0)
    return nil;
  return share;
}

- (SecureData *)nextShare {
  if (![self hasNextShare])
    return nil;

  SecureData *share = [SecureData secureDataWithLength:tss_share_size(&_tssCtx)];
  int ret = tss_share_next(&_tssCtx, [share mutableBytes]);
  if (ret != 0)
    return nil;
  return share;
}

- (BOOL)hasNextShare {
  return tss_share_next(&_tssCtx, NULL) != -2;
}

@end
