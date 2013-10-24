//
//  FECEncoder.m
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "FECEncoder.h"

#include "fec.h"
#include "sysendian.h"


static const int kN = 254;
static const int kHeaderSize = 2;


@interface FECEncoder () {
  void *_fecCtx;
  void *_sourceDataIndex[kN];
}

@property (nonatomic, assign) NSInteger index;
@property (nonatomic, assign) int threshold;
@property (nonatomic, strong) NSMutableData *sourceData;

@end


@implementation FECEncoder

- (id)initWithData:(NSData *)data threshold:(NSInteger)threshold {
  if (!data || [data length] > UINT32_MAX || threshold <= 0 || threshold >= kN)
    return nil;

  self = [super init];
  if (self) {
    _threshold = (int)threshold;

    // Pad source data
    _sourceData = [NSMutableData dataWithLength:4];
    le32enc([_sourceData mutableBytes], (unsigned int)[data length]);

    [_sourceData appendData:data];
    NSUInteger contentSize = 4 + [data length];
    if (contentSize % _threshold)
      [_sourceData setLength:contentSize + _threshold - (contentSize % _threshold)];

    // Init context
    _fecCtx = fec_new(_threshold, kN);
    if (_fecCtx == NULL)
      return nil;

    // Index source data
    for (NSInteger i = 0; i < _threshold; ++i)
      _sourceDataIndex[i] = [_sourceData mutableBytes] + (i * ([_sourceData length] /
                                                               _threshold));
  }
  return self;
}

- (void)dealloc {
  if (_fecCtx != NULL)
    fec_free(_fecCtx);
}


- (NSData *)chunkAtIndex:(NSInteger)index {
  if (_fecCtx == NULL || !self.sourceData || index < 0 || index >= kN)
    return nil;

  NSUInteger chunkSize = [self.sourceData length] / self.threshold;
  if (chunkSize > INT_MAX)
    return nil;

  NSMutableData *encodedData = [NSMutableData dataWithLength:kHeaderSize + chunkSize];

  // Encode index
  *((uint8_t *)[encodedData mutableBytes]) = index;

  // Encode threshold
  *((uint8_t *)([encodedData mutableBytes] + 1)) = self.threshold;

  // Encode chunk
  fec_encode(_fecCtx, _sourceDataIndex, [encodedData mutableBytes] + kHeaderSize,
             (int)index, (int)chunkSize);

  return encodedData;
}

- (NSData *)nextChunk {
  if (![self hasNextChunk])
    return nil;
  return [self chunkAtIndex:self.index++];
}

- (BOOL)hasNextChunk {
  return self.index < kN;
}

@end
