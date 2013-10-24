//
//  TSSTests.m
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#include <stdio.h>
#include <string.h>

#include "tss.h"


static void print_coefs(const tss_ctx *ctx) {
  printf("coefs poly: ");
  for (int i = 0; i < 256; ++i)
    printf("%2x ", ctx->coefs_poly[i]);
  printf("\n");
}


@interface TSSTests : SenTestCase

@end

@implementation TSSTests

- (void)testBasic1 {
  unsigned char secret[32] = "my little secret value is secret";
  size_t secret_len = 32;
  uint8_t identifier[TSS_IDENTIFIER_SIZE] = "identifier123456";
  tss_hash hash_algorithm = TSS_SHA256;
  uint8_t threshold = 254;
  uint8_t n = 254;
  uint8_t shares_buffer_ref[65536];
  uint8_t shares_buffer[65536];
  uint8_t recovered_secret[32];
  tss_ctx share_ctx;
  tss_ctx recover_ctx;
  uint32_t share_size;
  int ret;
  int i;

  memset(shares_buffer_ref, 0, 65536);
  memset(shares_buffer, 0, 65536);

  // Sharing

  ret = tss_share_init(&share_ctx, identifier, threshold, hash_algorithm,
                       secret, secret_len);
  STAssertFalse(ret < 0, @"tss_share_init failed (%d)", ret);

  share_size = tss_share_size(&share_ctx);
  for (i = 0; i < n; ++i) {
    ret = tss_share_next(&share_ctx, shares_buffer_ref + (i * share_size));
    STAssertFalse(ret < 0, @"tss_share failed (%d)", ret);
  }

  // Recovering

  ret = tss_recover_init(&recover_ctx);
  STAssertFalse(ret < 0, @"tss_recover_init failed (%d)", ret);

  for (i = 0; i < n; ++i) {
    ret = tss_recover_add(&recover_ctx, shares_buffer_ref + (i * share_size));
    STAssertFalse(ret < 0, @"tss_recover_add failed (%d)", ret);
  }

  STAssertTrue(tss_recover_secret_size(&recover_ctx) == 32,
                 @"bad secret size %d, expected 32", tss_recover_secret_size(&recover_ctx));

  ret = tss_recover(&recover_ctx, recovered_secret);
  STAssertFalse(ret < 0, @"tss_recover failed (%d)", ret);

  ret = tss_recover_coefficients(&recover_ctx);
  STAssertFalse(ret < 0, @"tss_recover_coefficients failed (%d)", ret);
  if (memcmp(share_ctx.coefs_poly, recover_ctx.coefs_poly, 256)) {
    print_coefs(&share_ctx);
    print_coefs(&recover_ctx);
  }
  STAssertTrue(memcmp(share_ctx.coefs_poly, recover_ctx.coefs_poly, 256) == 0,
               @"recovered coefficients don't match original coefficients");

  recover_ctx.index = 1;
  for (i = 0; i < n; ++i) {
    ret = tss_share_next(&recover_ctx, shares_buffer + (i * share_size));
    STAssertFalse(ret < 0, @"tss_share failed (%d)", ret);
  }
  STAssertTrue(memcmp(shares_buffer_ref, shares_buffer, 65536) == 0,
               @"shares generated from recovered coefs don't match original shares");

  tss_free(&share_ctx);
  tss_free(&recover_ctx);

  STAssertTrue(memcmp(secret, recovered_secret, 32) == 0,
               @"bad recovered secret value");
}

- (void)testBasic2 {
  unsigned char secret[32] = "test\0";
  size_t secret_len = 5;
  uint8_t identifier[TSS_IDENTIFIER_SIZE] = "identifier123456";
  tss_hash hash_algorithm = TSS_NONE;
  uint8_t threshold = 2;
  uint8_t n = 2;
  uint8_t shares_buffer[16384];
  uint8_t recovered_secret[32];
  tss_ctx share_ctx;
  tss_ctx recover_ctx;
  uint32_t share_size;
  int ret;
  int i;

  ret = tss_share_init(&share_ctx, identifier, threshold, hash_algorithm,
                       secret, secret_len);
  STAssertFalse(ret < 0, @"tss_share_init failed (%d)", ret);

  share_size = tss_share_size(&share_ctx);
  for (i = 0; i < n; ++i) {
    ret = tss_share_next(&share_ctx, shares_buffer + (i * share_size));
    STAssertFalse(ret < 0, @"tss_share failed (%d)", ret);
  }

  tss_free(&share_ctx);

  ret = tss_recover_init(&recover_ctx);
  STAssertFalse(ret < 0, @"tss_recover_init failed (%d)", ret);

  for (i = 0; i < n; ++i) {
    ret = tss_recover_add(&recover_ctx, shares_buffer + (i * share_size));
    STAssertFalse(ret < 0, @"tss_recover_add failed (%d)", ret);
  }

  STAssertTrue(tss_recover_secret_size(&recover_ctx) == 5,
                 @"bad secret size %d, expected 5",
                 tss_recover_secret_size(&recover_ctx));

  ret = tss_recover(&recover_ctx, recovered_secret);
  STAssertFalse(ret < 0, @"tss_recover failed (%d)", ret);

  tss_free(&recover_ctx);

  STAssertTrue(memcmp(secret, recovered_secret, 5) == 0,
               @"bad recovered secret value");
}

@end
