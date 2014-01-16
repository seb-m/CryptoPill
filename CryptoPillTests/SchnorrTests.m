//
//  SchnorrTests.m
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "schnorr_keypair.h"
#include "schnorr_id.h"
#include "schnorr_sign.h"


void print_1(uint8_t b[32]) {
  int i;
  for (i = 0; i < 32; ++i) {
    printf("%d, ", b[i]);
  }
  printf("\n");
}

void print_2(uint32_t b[32]) {
  int i;
  for (i = 0; i < 32; ++i) {
    printf("%d, ", b[i]);
  }
  printf("\n");
}

int test_schnorr_identification_basic(int simulate_failure) {
  uint8_t pk[SCHNORR_PUBLICKEYBYTES];
  uint8_t sk[SCHNORR_SECRETKEYBYTES];
  uint8_t pk_r[SCHNORR_PUBLICKEYBYTES];
  uint8_t sk_r[SCHNORR_SECRETKEYBYTES];
  uint8_t challenge[SCHNORR_ID_CHALLENGEBYTES];
  uint8_t response[SCHNORR_ID_RESPONSEBYTES];
  int ret;

  ret = schnorr_secretkey(sk);
  if (ret) {
    printf("error generate secret key %d\n", ret);
    return ret;
  }

  ret = schnorr_publickey(pk, sk);
  if (ret) {
    printf("error compute public key %d\n", ret);
    return ret;
  }

  ret = schnorr_id_commitment(pk_r, sk_r);
  if (ret) {
    printf("error commitment %d\n", ret);
    return ret;
  }

  ret = schnorr_id_challenge(challenge);
  if (ret) {
    printf("error challenge %d\n", ret);
    return ret;
  }

  ret = schnorr_id_response(response, sk, sk_r, challenge);
  if (ret) {
    printf("error response %d\n", ret);
    return ret;
  }

  if (simulate_failure) {
    response[20] = ~response[20];
    response[28] = ~response[28];
  }

  ret = schnorr_id_verify(pk, pk_r, challenge, response);
  if (ret && !simulate_failure) {
    printf("error invalid identification %d\n", ret);
  }
  return ret;
}

int test_schnorr_signature_basic(int simulate_failure) {
  uint8_t pk[SCHNORR_PUBLICKEYBYTES];
  uint8_t sk[SCHNORR_SECRETKEYBYTES];
  uint8_t signature[SCHNORR_SIGN_SIGNATUREBYTES];
  const unsigned char message[] = "A short message to sign.";
  int ret;

  ret = schnorr_secretkey(sk);
  if (ret) {
    printf("error generate secret key %d\n", ret);
    return ret;
  }

  ret = schnorr_publickey(pk, sk);
  if (ret) {
    printf("error compute public key %d\n", ret);
    return ret;
  }

  ret = schnorr_sign(signature, sk, pk, message, strlen((const char *)message));
  if (ret) {
    printf("error signature %d\n", ret);
    return ret;
  }

  if (simulate_failure) {
    signature[20] = ~signature[20];
    signature[42] = ~signature[42];
  }

  ret = schnorr_sign_verify(pk, signature, message, strlen((const char *)message));
  if (ret && !simulate_failure) {
    printf("error invalid signature %d\n", ret);
  }
  return ret;
}


@interface SchnorrTests : SenTestCase

@end

@implementation SchnorrTests

- (void)testSchnorrIdentificationBasic {
  int i;
  int loop_count;

  // Expected run
  loop_count = 256;
  for (i = 0; i < loop_count; ++i)
    STAssertTrue(test_schnorr_identification_basic(0) == 0,
                 [NSString stringWithFormat:@"test schnorr identication failed at iteration %d", i]);

  // Simulate failures
  loop_count = 64;
  for (i = 0; i < loop_count; ++i)
    STAssertFalse(test_schnorr_identification_basic(1) == 0,
                  @"test schnorr identification succeeded while it should have failed");
}

- (void)testSchnorrSignatureBasic {
  int i;
  int loop_count;

  // Expected run
  loop_count = 256;
  for (i = 0; i < loop_count; ++i)
    STAssertTrue(test_schnorr_signature_basic(0) == 0,
                 [NSString stringWithFormat:@"test schnorr signature failed at iteration %d", i]);

  // Simulate failures
  loop_count = 64;
  for (i = 0; i < loop_count; ++i)
    STAssertFalse(test_schnorr_signature_basic(1) == 0,
                  @"test schnorr signature succeeded while it should have failed");
}

@end
