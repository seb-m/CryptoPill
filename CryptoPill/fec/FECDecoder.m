//
//  FECDecoder.m
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "FECDecoder.h"

#include <stdlib.h>
#include <string.h>

#include "fec.h"
#include "sysendian.h"


static const int kN = 254;
static const int kHeaderSize = 2;


@interface FECDecoder () {
  void *_fecCtx;
  int _encodedChunksIndexes[kN];
  void *_shares[kN];
}

@property (nonatomic, assign) int threshold;
@property (nonatomic, strong) NSMutableData *chunks;
@property (nonatomic, assign) NSInteger count;
@property (nonatomic, assign) int encodedChunkSize;

@end


@implementation FECDecoder

- (id)init {
  self = [super init];
  if (self) {
    _chunks = [NSMutableData data];
    _fecCtx = NULL;
    for (NSInteger i = 0; i < kN; ++i)
      _shares[i] = NULL;
  }
  return self;
}

- (void)dealloc {
  if (_fecCtx != NULL)
    fec_free(_fecCtx);

  for (int i = 0; i < self.threshold; ++i)
    if (_shares[i] != NULL)
      free(_shares[i]);
}

- (NSInteger)addChunk:(NSData *)chunk {
  if ([self canDecode])
    return -3;

  if (!chunk || [chunk length] <= kHeaderSize)
    return -1;

  // Decode and validate index value
  int index = *((uint8_t *)[chunk bytes]);
  if (index >= kN)
    return -1;

  // Decode and validate threshold value
  int threshold = *((uint8_t *)([chunk bytes] + 1));
  if (threshold <= 0 || threshold >= kN)
    return -1;

  if (_fecCtx == NULL) {
    self.encodedChunkSize = [chunk length] - kHeaderSize;
    self.threshold = threshold;

    // Init context
    _fecCtx = fec_new(self.threshold, kN);
    if (_fecCtx == NULL)
      return -1;

    for (int i = 0; i < self.threshold; ++i) {
      _shares[i] = malloc(self.encodedChunkSize);
      if (_shares[i] == NULL)
        return -1;
    }
  } else {
    if ([chunk length] - kHeaderSize != self.encodedChunkSize ||
        self.threshold != threshold)
      return -1;
  }

  // Do not insert multiple times the same chunk.
  for (NSInteger i = 0; i < self.count; ++i)
    if (_encodedChunksIndexes[i] == index)
      return -2;

  memcpy(_shares[self.count], [chunk bytes] + kHeaderSize, self.encodedChunkSize);
  _encodedChunksIndexes[self.count++] = index;

  return 0;
}

- (BOOL)canDecode {
  return _fecCtx != NULL && self.count >= self.threshold;
}

- (NSData *)decode {
  if (![self canDecode])
    return nil;

  int ret = fec_decode(_fecCtx, _shares, _encodedChunksIndexes, self.encodedChunkSize);
  if (ret != 0)
    return nil;

  if (self.encodedChunkSize < 4)
    return nil;

  unsigned int contentSize = le32dec(_shares[0]);
  if (self.encodedChunkSize * self.threshold < 4 + contentSize)
    return nil;

  void *decodedBytes = malloc(contentSize);
  if (decodedBytes == NULL)
    return nil;

  int counter = 0;
  size_t sizeToCopy;
  size_t copiedBytes = 0;
  size_t offset;
  while (contentSize > 0) {
    if (counter == 0)
      offset = 4;
    else
      offset = 0;

    if (contentSize < self.encodedChunkSize - offset)
      sizeToCopy = contentSize;
    else
      sizeToCopy = self.encodedChunkSize - offset;

    memcpy(decodedBytes + copiedBytes, _shares[counter] + offset, sizeToCopy);

    contentSize -= sizeToCopy;
    copiedBytes += sizeToCopy;
    counter++;
    if (counter == self.threshold)
      break;
  }

  return [NSData dataWithBytesNoCopy:decodedBytes length:copiedBytes];
}

@end
