//
//  SchnorrProverCommit.m
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SchnorrProverCommit.h"

#include "schnorr_id.h"

#import "SchnorrProver.h"


@implementation SchnorrProverCommit

#pragma mark - Overriden methods

- (BOOL)dispatchMessage:(id)message error:(NSError *__autoreleasing *)error {
  self.status = CryptoStateActive;

  if (message || !self.stateMachine ||
      ![self.stateMachine isKindOfClass:[SchnorrProver class]]) {
    self.status = CryptoStateInvalid;
    return NO;
  }

  SchnorrProver *prover = (SchnorrProver *)self.stateMachine;

  int ret = schnorr_id_commitment([prover.publicKeyR mutableBytes],
                                  [prover.secretKeyR mutableBytes]);
  if (ret) {
    if (error) {
      NSDictionary *userInfo = @{NSLocalizedDescriptionKey: NSLocalizedString(@"Keypair generation failed.", nil)};
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
  return ((SchnorrProver *)self.stateMachine).publicKeyR;
}

@end
