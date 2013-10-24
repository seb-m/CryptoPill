//
//  TSSRecover.m
//  CryptoPill
//
//  Created by Sébastien Martini on 05/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "TSSRecover.h"

#include "tss.h"

#import "SecureData.h"


@interface TSSRecover () {
  tss_ctx _tssCtx;
}

@property (nonatomic, assign, getter=isHeaderDecoded) BOOL headerDecoded;

@end


@implementation TSSRecover

- (id)init {
  self = [super init];
  if (self) {
    int ret = tss_recover_init(&_tssCtx);
    if (ret != 0)
      return nil;
  }
  return self;
}

- (void)dealloc {
  tss_free(&_tssCtx);
}


- (NSInteger)addShare:(SecureData *)share {
  if (!share)
    return -1;

  int ret = tss_recover_add(&_tssCtx, [share bytes]);
  if (ret > 0) {
    if (!self.headerDecoded)
      self.headerDecoded = YES;
    return 0;
  }
  if (ret == -2)
    return -2;
  return -1;
}

- (NSData *)identifier {
  if (!self.isHeaderDecoded)
    return nil;
  return [NSData dataWithBytes:_tssCtx.identifier length:TSS_IDENTIFIER_SIZE];
}

- (NSUInteger)threshold {
  if (!self.isHeaderDecoded)
    return 0;
  return tss_recover_threshold(&_tssCtx);
}

- (BOOL)canRecover {
  NSUInteger threshold = [self threshold];
  if (threshold == 0)
    return NO;

  return tss_recover_num_shares(&_tssCtx) >= threshold;
}

- (NSUInteger)numberOfSharesNeededForRecovering {
  if ([self canRecover])
    return 0;
  return [self threshold] - tss_recover_num_shares(&_tssCtx);
}

- (SecureData *)recover {
  if (![self canRecover])
    return nil;

  SecureData *secret = [SecureData secureDataWithLength:tss_recover_secret_size(&_tssCtx)];
  int ret = tss_recover(&_tssCtx, [secret mutableBytes]);
  if (ret != 0)
    return nil;

  return secret;
}

@end
