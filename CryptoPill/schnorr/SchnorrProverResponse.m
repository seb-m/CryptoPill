//
//  SchnorrProverResponse.m
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SchnorrProverResponse.h"

#include "schnorr_id.h"

#import "SchnorrProver.h"


@interface SchnorrProverResponse ()

@property (nonatomic, strong) NSMutableData *response;

@end


@implementation SchnorrProverResponse

- (id)initWithName:(NSString *)stateName {
  self = [super initWithName:stateName];
  if (self) {
    _response = [NSMutableData dataWithLength:SCHNORR_ID_RESPONSEBYTES];
  }
  return self;
}


#pragma mark - NSCopying protocol method

- (id)copyWithZone:(NSZone *)zone {
  SchnorrProverResponse *copiedState = [super copyWithZone:zone];
  copiedState.response = [self.response copyWithZone:zone];
  return copiedState;
}


#pragma mark - NSSecureCoding protocol methods

- (id)initWithCoder:(NSCoder *)coder {
  self = [super initWithCoder:coder];
  if (self) {
    _response = [[coder decodeObjectOfClass:[NSData class] forKey:@"response"]
                 mutableCopy];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  [coder encodeObject:self.response forKey:@"response"];
}


#pragma mark - Overriden methods

- (BOOL)dispatchMessage:(id)message error:(NSError *__autoreleasing *)error {
  self.status = CryptoStateActive;

  if (message == nil || !self.stateMachine ||
      ![self.stateMachine isKindOfClass:[SchnorrProver class]]) {
    self.status = CryptoStateInvalid;
    return NO;
  }

  if (![message isKindOfClass:[NSData class]] ||
      [message length] != SCHNORR_ID_CHALLENGEBYTES) {
    if (error) {
      NSDictionary *userInfo = @{NSLocalizedDescriptionKey: NSLocalizedString(@"Invalid challenge data.", nil)};
      *error = [NSError errorWithDomain:CryptoStateMachineErrorDomain
                                   code:-1
                               userInfo:userInfo];
    }
    self.status = CryptoStateInvalid;
    return NO;
  }

  SchnorrProver *prover = (SchnorrProver *)self.stateMachine;
  prover.challenge = (NSData *)message;

  int ret = schnorr_id_response([self.response mutableBytes], [prover.secretKey bytes],
                                [prover.secretKeyR bytes], [prover.challenge bytes]);
  if (ret) {
    if (error) {
      NSDictionary *userInfo = @{NSLocalizedDescriptionKey: NSLocalizedString(@"Response generation failed.", nil)};
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
  return self.response;
}

@end
