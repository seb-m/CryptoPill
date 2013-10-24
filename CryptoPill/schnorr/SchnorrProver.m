//
//  SchnorrProver.m
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "SchnorrProver.h"

#import "schnorr_keypair.h"


@interface SchnorrProver ()

@property (nonatomic, strong) NSData *publicKey;
@property (nonatomic, strong) SecureData *secretKey;
@property (nonatomic, strong) NSMutableData *publicKeyR;
@property (nonatomic, strong) SecureData *secretKeyR;

@end


@implementation SchnorrProver

- (id)initWithPublicKey:(NSData *)pubKey secretKey:(SecureData *)secKey {
  self = [super init];
  if (self) {
    _publicKey = pubKey;
    _secretKey = secKey;
    _publicKeyR = [NSMutableData dataWithLength:SCHNORR_PUBLICKEYBYTES];
    _secretKeyR = [SecureData secureDataWithLength:SCHNORR_SECRETKEYBYTES];
  }
  return self;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"<%@ pubKey: %@, pubKeyR: %@, challenge: %@>",
          [super description], self.publicKey, self.publicKeyR, self.challenge];
}


#pragma mark - NSCopying protocol method

- (id)copyWithZone:(NSZone *)zone {
  SchnorrProver *copiedStateMachine = [super copyWithZone:zone];
  copiedStateMachine.publicKey = self.publicKey;
  copiedStateMachine.secretKey = self.secretKey;
  copiedStateMachine.publicKeyR = [self.publicKeyR copyWithZone:zone];
  copiedStateMachine.secretKeyR = [self.secretKeyR copyWithZone:zone];
  copiedStateMachine.challenge = self.challenge;
  return copiedStateMachine;
}


#pragma mark - NSSecureCoding protocol methods

- (id)initWithCoder:(NSCoder *)coder {
  self = [super initWithCoder:coder];
  if (self) {
    _publicKey = [coder decodeObjectOfClass:[NSData class] forKey:@"publicKey"];
    _secretKey = [coder decodeObjectOfClass:[NSData class] forKey:@"secretKey"];
    _publicKeyR = [[coder decodeObjectOfClass:[NSData class] forKey:@"publicKeyR"]
                   mutableCopy];
    _secretKeyR = [coder decodeObjectOfClass:[NSData class] forKey:@"secretKeyR"];
    _challenge = [coder decodeObjectOfClass:[NSData class] forKey:@"challenge"];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  [coder encodeObject:self.publicKey forKey:@"publicKey"];
  [coder encodeObject:self.secretKey forKey:@"secretKey"];
  [coder encodeObject:self.publicKeyR forKey:@"publicKeyR"];
  [coder encodeObject:self.secretKeyR forKey:@"secretKeyR"];
  [coder encodeObject:self.challenge forKey:@"challenge"];
}

@end
