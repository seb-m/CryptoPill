//
//  SchnorrProtocolTests.m
//  CryptoPill
//
//  Created by Sébastien Martini on 23/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>

#include <stdint.h>

#include "schnorr_keypair.h"
#include "schnorr_id.h"

#import "SchnorrProtocol.h"
#import "SecureData.h"


void modify_buffer(uint8_t buffer[SCHNORR_ID_RESPONSEBYTES]) {
  buffer[20] = ~buffer[20];
  buffer[28] = ~buffer[28];
}


@interface SchnorrProtocolTests : SenTestCase

@end

@implementation SchnorrProtocolTests

- (void)performTestWithFailure:(BOOL)mustFail {
  SecureData *sk = [SchnorrKeypair generateSecretKey];
  NSData *pk = [SchnorrKeypair publicKeyFromSecretKey:sk];
  STAssertTrue(sk != nil && pk != nil, @"key pair generation failed");

  SchnorrProver *prover = [[SchnorrProver alloc] initWithPublicKey:pk
                                                         secretKey:sk];
  [prover addState:[[SchnorrProverCommit alloc] initWithName:@"prover_commit"]];
  [prover addState:[[SchnorrProverResponse alloc] initWithName:@"prover_response"]];

  SchnorrVerifier *verifier = [[SchnorrVerifier alloc] initWithPublicKey:pk];
  [verifier addState:[[SchnorrVerifierChallenge alloc] initWithName:@"verifier_challenge"]];
  [verifier addState:[[SchnorrVerifierVerify alloc] initWithName:@"verifier_verify"]];

  NSData *message;
  BOOL status;
  NSError *error;

  // Prover commit
  status = [prover transition];
  STAssertTrue(status, @"prover commit transition failed");
  message = (NSData *)[[prover currentState] outputMessage];
  STAssertTrue(message != nil, @"prover commit output message failed");

  // Verifier challenge
  status = [verifier transitionWithMessage:message error:&error];
  STAssertTrue(status, @"verifier challenge transition failed");
  STAssertNil(error, @"Unexpected NSError object");
  message = (NSData *)[[verifier currentState] outputMessage];
  STAssertTrue(message != nil, @"verifier challenge output message failed");

  // Sanity check
  STAssertFalse([prover completedWithSuccess],
                @"prover completed with success not as expected");
  STAssertFalse([verifier completedWithSuccess],
                @"verifier completed with success not as expected");

  // Prover response
  status = [prover transitionWithMessage:message error:&error];
  STAssertTrue(status, @"verifier response transition failed");
  STAssertNil(error, @"Unexpected NSError object");
  message = (NSData *)[[prover currentState] outputMessage];
  STAssertTrue(message != nil, @"verifier response output message failed");

  // Modify the response to make it fail.
  if (mustFail) {
    NSMutableData *modifiedMsg = [NSMutableData dataWithData:message];
    modify_buffer([modifiedMsg mutableBytes]);
    message = modifiedMsg;
  }

  // Verifier verification
  status = [verifier transitionWithMessage:message error:&error];
  if (mustFail) {
    STAssertFalse(status, @"verifier verify transition succeeded");
    STAssertTrue(error != nil, @"Unexpected NSError object");
    NSLog(@"%@", [error localizedDescription]);
  } else {
    STAssertTrue(status, @"verifier verify transition failed");
    STAssertNil(error, @"Unexpected NSError object");
  }
  message = (NSData *)[[verifier currentState] outputMessage];
  STAssertTrue(message == nil, @"verifier verify output message failed");

  STAssertTrue([prover completedWithSuccess],
               @"prover does not completed with success as expected");
  STAssertTrue([prover checkCurrentStateName:@"prover_response"],
               @"wrong state name");
  if (mustFail)
    STAssertFalse([verifier completedWithSuccess],
                 @"verifier completed with success not as expected");
  else
    STAssertTrue([verifier completedWithSuccess],
                 @"verifier does not completed with success as expected");
  STAssertTrue([verifier checkCurrentStateName:@"verifier_verify"],
               @"wrong state name");
}

- (void)testBasicValid {
  [self performTestWithFailure:NO];
}

- (void)testBasicInvalid {
  [self performTestWithFailure:YES];
}

- (void)testCoding {
  SecureData *sk = [SchnorrKeypair generateSecretKey];
  NSData *pk = [SchnorrKeypair publicKeyFromSecretKey:sk];
  STAssertTrue(sk != nil && pk != nil, @"key pair generation failed");

  // Prover: instanciation, encoding, decoding
  SchnorrProver *prover = [[SchnorrProver alloc] initWithPublicKey:pk
                                                         secretKey:sk];
  [prover addState:[[SchnorrProverCommit alloc] initWithName:@"prover_commit"]];
  [prover addState:[[SchnorrProverResponse alloc] initWithName:@"prover_response"]];
  NSData *proverData = [NSKeyedArchiver archivedDataWithRootObject:prover];
  prover = [NSKeyedUnarchiver unarchiveObjectWithData:proverData];

  // Verifier: instanciation, encoding, decoding
  SchnorrVerifier *verifier = [[SchnorrVerifier alloc] initWithPublicKey:pk];
  [verifier addState:[[SchnorrVerifierChallenge alloc] initWithName:@"verifier_challenge"]];
  [verifier addState:[[SchnorrVerifierVerify alloc] initWithName:@"verifier_verify"]];

  NSData *verifierData = [NSKeyedArchiver archivedDataWithRootObject:verifier];
  verifier = [NSKeyedUnarchiver unarchiveObjectWithData:verifierData];

  //NSLog(@"%@", prover);
  //NSLog(@"%@", verifier);

  // Normal protocol flow
  NSData *message;
  BOOL status;

  // Prover commit
  status = [prover transition];
  STAssertTrue(status, @"prover commit transition failed");
  message = (NSData *)[[prover currentState] outputMessage];
  STAssertTrue(message != nil, @"prover commit output message failed");

  // Verifier challenge
  status = [verifier transitionWithMessage:message error:nil];
  STAssertTrue(status, @"verifier challenge transition failed");
  message = (NSData *)[[verifier currentState] outputMessage];
  STAssertTrue(message != nil, @"verifier challenge output message failed");

  // Prover response
  status = [prover transitionWithMessage:message error:nil];
  STAssertTrue(status, @"verifier response transition failed");
  message = (NSData *)[[prover currentState] outputMessage];
  STAssertTrue(message != nil, @"verifier response output message failed");

  // Verifier verification
  status = [verifier transitionWithMessage:message error:nil];
  STAssertTrue(status, @"verifier verify transition failed");
  message = (NSData *)[[verifier currentState] outputMessage];
  STAssertTrue(message == nil, @"verifier verify output message failed");

  STAssertTrue([prover completedWithSuccess],
               @"prover does not completed with success as expected");
  STAssertTrue([verifier completedWithSuccess],
               @"verifier does not completed with success as expected");

  // Encode, decode, verify the state is still valid.
  proverData = [NSKeyedArchiver archivedDataWithRootObject:prover];
  prover = [NSKeyedUnarchiver unarchiveObjectWithData:proverData];
  verifierData = [NSKeyedArchiver archivedDataWithRootObject:verifier];
  verifier = [NSKeyedUnarchiver unarchiveObjectWithData:verifierData];
  STAssertTrue([prover completedWithSuccess],
               @"prover does not completed with success as expected");
  STAssertTrue([verifier completedWithSuccess],
               @"verifier does not completed with success as expected");

  //NSLog(@"%@", prover);
  //NSLog(@"%@", verifier);
}

@end
