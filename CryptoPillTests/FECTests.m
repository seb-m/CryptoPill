//
//  FECTests.m
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "fec.h"
#include "rand.h"


@interface FECTests : SenTestCase

@end

@implementation FECTests

- (void)testBasic {
  uint8_t k = 32;
  uint8_t n = 254;
  int pkt_size = 1024;
  void *buf_src[k];
  void *shares[n]; // but will only hold k elements
  int indexes[n]; // but will only hold k elements
  void *fec_ctx;
  int count;
  int i;
  int ret;

  // init source buffer with random data
  for (i = 0; i < k; ++i) {
    buf_src[i] = malloc(pkt_size);
    STAssertFalse(buf_src[i] == NULL, @"error malloc");
    crand(buf_src[i], pkt_size);
  }

  // init dst buffer
  for (i = 0; i < n; ++i) {
    shares[i] = malloc(pkt_size);
    STAssertFalse(shares[i] == NULL, @"error malloc");
  }

  fec_ctx = fec_new(k, n);
  STAssertFalse(fec_ctx == NULL, @"fec_new failed");

  count = 0;
  for (i = k - 10; i < (2 * k) - 10; ++i) {
    // Copy k shares ranging from indexex [k, 2*k[
    // But remember this code is optimized for cases were losses are
    // minimized between [0, k[ indexes.
    fec_encode(fec_ctx, buf_src, shares[count], i, pkt_size);
    indexes[count++] = i;
  }

  ret = fec_decode(fec_ctx, shares, indexes, pkt_size);
  STAssertTrue(ret == 0, @"fec_decode failed");

  for (i = 0; i < k; ++i)
    STAssertTrue(memcmp(buf_src[i], shares[i], pkt_size) == 0,
                 @"recovered data don't match source buffer at index %d",
                 indexes[i]);

  fec_free(fec_ctx);
  for (i = 0; i < k; ++i)
    free(buf_src[i]);
  for (i = 0; i < n; ++i)
    free(shares[i]);
}

@end
