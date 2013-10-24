//
//  SchnorrVerifierChallenge.m
//  CryptoPill
//
//  Created by Sébastien Martini on 23/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SchnorrVerifierChallenge.h"

#include "schnorr_id.h"

#import "SchnorrVerifier.h"


@implementation SchnorrVerifierChallenge

#pragma mark - Overriden methods

- (BOOL)dispatchMessage:(id)message error:(NSError *__autoreleasing *)error {
  self.status = CryptoStateActive;

  if (message == nil || !self.stateMachine ||
      ![self.stateMachine isKindOfClass:[SchnorrVerifier class]]) {
    self.status = CryptoStateInvalid;
    return NO;
  }

  if (![message isKindOfClass:[NSData class]] ||
      [message length] != SCHNORR_PUBLICKEYBYTES) {
    if (error) {
      NSDictionary *userInfo = @{NSLocalizedDescriptionKey: NSLocalizedString(@"Invalid commitment data.", nil)};
      *error = [NSError errorWithDomain:CryptoStateMachineErrorDomain
                                   code:-1
                               userInfo:userInfo];
    }
    self.status = CryptoStateInvalid;
    return NO;
  }

  SchnorrVerifier *verifier = (SchnorrVerifier *)self.stateMachine;
  verifier.publicKeyR = (NSData *)message;

  int ret = schnorr_id_challenge([verifier.challenge mutableBytes]);
  if (ret) {
    if (error) {
      NSDictionary *userInfo = @{NSLocalizedDescriptionKey: NSLocalizedString(@"Challenge generation failed.", nil)};
      *error = [NSError errorWithDomain:CryptoStateMachineErrorDomain
                                   code:ret
                               userInfo:userInfo];
    }
    self.status = CryptoStateInvalid;
    return NO;
  }

  self.status = CryptoStateValid;
  return YES;
}

- (id<NSSecureCoding>)outputMessage {
  if (![self valid])
    return nil;
  return ((SchnorrVerifier *)self.stateMachine).challenge;
}

@end
