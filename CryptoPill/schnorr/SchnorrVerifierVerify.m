//
//  SchnorrVerifierVerify.m
//  CryptoPill
//
//  Created by Sébastien Martini on 23/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SchnorrVerifierVerify.h"

#include "schnorr_id.h"

#import "SchnorrVerifier.h"


@implementation SchnorrVerifierVerify

#pragma mark - Overriden method

- (BOOL)dispatchMessage:(id)message error:(NSError *__autoreleasing *)error {
  self.status = CryptoStateActive;

  if (message == nil || !self.stateMachine ||
      ![self.stateMachine isKindOfClass:[SchnorrVerifier class]]) {
    self.status = CryptoStateInvalid;
    return NO;
  }

  if (![message isKindOfClass:[NSData class]] ||
      [message length] != SCHNORR_ID_RESPONSEBYTES) {
    if (error) {
      NSDictionary *userInfo = @{NSLocalizedDescriptionKey: NSLocalizedString(@"Invalid response data.", nil)};
      *error = [NSError errorWithDomain:CryptoStateMachineErrorDomain
                                   code:-1
                               userInfo:userInfo];
    }
    self.status = CryptoStateInvalid;
    return NO;
  }

  SchnorrVerifier *verifier = (SchnorrVerifier *)self.stateMachine;
  NSData *response = (NSData *)message;

  int ret = schnorr_id_verify([verifier.publicKey bytes], [verifier.publicKeyR bytes],
                              [verifier.challenge bytes], [response bytes]);
  if (ret) {
    if (error) {
      NSDictionary *userInfo = @{NSLocalizedDescriptionKey: NSLocalizedString(@"Verification failed.", nil)};
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

@end
