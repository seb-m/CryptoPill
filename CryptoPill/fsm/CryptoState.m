//
//  State.m
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "CryptoState.h"

#import "CryptoStateMachine.h"


@interface CryptoState ()

@property (nonatomic, copy) NSString *name;

@end


@implementation CryptoState

- (id)initWithName:(NSString *)stateName {
  self = [super init];
  if (self) {
    _name = [stateName copy];
    _status = CryptoStateInactive;
  }
  return self;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"<%@: %@, status: %u>",
          [self class], self.name, (unsigned int)self.status];
}


#pragma mark - NSCopying protocol method

- (id)copyWithZone:(NSZone *)zone {
  CryptoState *copiedState = [[[self class] allocWithZone:zone] init];
  copiedState.name = self.name;
  // StateMachine attribute is not copied. This attribute is only set by a
  // StateMachine object when the state is added to it.
  copiedState.stateMachine = nil;
  copiedState.status = self.status;
  return copiedState;
}


#pragma mark - NSSecureCoding protocol methods

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (id)initWithCoder:(NSCoder *)coder {
  self = [super init];
  if (self) {
    _name = [coder decodeObjectOfClass:[NSString class] forKey:@"name"];
    _stateMachine = [coder decodeObjectOfClass:[NSString class]
                                        forKey:@"statemMachine"];
    _status = [[coder decodeObjectOfClass:[NSNumber class]
                                   forKey:@"status"] unsignedIntegerValue];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeObject:self.name forKey:@"name"];
  [coder encodeConditionalObject:self.stateMachine forKey:@"statemMachine"];
  [coder encodeObject:@(self.status)
               forKey:@"status"];
}


#pragma mark - Public methods

- (void)terminate {
  self.status = CryptoStateValid;
}

- (BOOL)valid {
  return self.status == CryptoStateValid;
}


#pragma mark - Methods to override in subclasses

- (BOOL)dispatchMessage:(id)message error:(NSError *__autoreleasing *)error {
  self.status = CryptoStateActive;
  self.status = CryptoStateValid;
  return [self valid];
}

- (id<NSSecureCoding>)outputMessage {
  return nil;
}

@end
