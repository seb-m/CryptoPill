//
//  SchnorrVerifier.m
//  CryptoPill
//
//  Created by Sébastien Martini on 23/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SchnorrVerifier.h"

#import "schnorr_id.h"


@interface SchnorrVerifier ()

@property (nonatomic, strong) NSData *publicKey;
@property (nonatomic, strong) NSMutableData *challenge;

@end


@implementation SchnorrVerifier

- (id)initWithPublicKey:(NSData *)pubKey {
  self = [super init];
  if (self) {
    _publicKey = pubKey;
    _challenge = [NSMutableData dataWithLength:SCHNORR_ID_CHALLENGEBYTES];
  }
  return self;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"<%@ pubKey: %@, pubKeyR: %@, challenge: %@>",
          [super description], self.publicKey, self.publicKeyR, self.challenge];
}


#pragma mark - NSCopying protocol method

- (id)copyWithZone:(NSZone *)zone {
  SchnorrVerifier *copiedStateMachine = [super copyWithZone:zone];
  copiedStateMachine.publicKey = self.publicKey;
  copiedStateMachine.publicKeyR = self.publicKeyR;
  copiedStateMachine.challenge = [self.challenge copyWithZone:zone];
  return copiedStateMachine;
}


#pragma mark - NSSecureCoding protocol methods

- (id)initWithCoder:(NSCoder *)coder {
  self = [super initWithCoder:coder];
  if (self) {
    _publicKey = [coder decodeObjectOfClass:[NSData class] forKey:@"publicKey"];
    _publicKeyR = [coder decodeObjectOfClass:[NSData class] forKey:@"publicKeyR"];
    _challenge = [[coder decodeObjectOfClass:[NSData class] forKey:@"challenge"]
                  mutableCopy];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  [coder encodeObject:self.publicKey forKey:@"publicKey"];
  [coder encodeObject:self.publicKeyR forKey:@"publicKeyR"];
  [coder encodeObject:self.challenge forKey:@"challenge"];
}

@end
