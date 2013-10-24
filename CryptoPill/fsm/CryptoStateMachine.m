//
//  CryptoStateMachine.m
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "CryptoStateMachine.h"

#import "CryptoState.h"


NSString *CryptoStateMachineErrorDomain = @"org.dbzteam.CryptoStateMachine.errors";


@interface CryptoStateMachine ()

@property (nonatomic, strong) NSMutableArray *states;
@property (assign) NSInteger currentStateIndex;

@end


@implementation CryptoStateMachine

- (id)init {
  self = [super init];
  if (self) {
    _states = [NSMutableArray array];
    _currentStateIndex = -1;
  }
  return self;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"<%@, current_state: %ld, states: %@>",
          [self class], (long)self.currentStateIndex, self.states];
}

#pragma mark - NSCopying protocol method

- (id)copyWithZone:(NSZone *)zone {
  CryptoStateMachine *copiedStateMachine = [[[self class] allocWithZone:zone] init];
  copiedStateMachine.currentStateIndex = self.currentStateIndex;
  copiedStateMachine.states = [[NSMutableArray alloc] initWithArray:self.states
                                                          copyItems:YES];
  return copiedStateMachine;
}


#pragma mark - NSSecureCoding protocol methods

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (id)initWithCoder:(NSCoder *)coder {
  self = [super init];
  if (self) {
    _states = [[coder decodeObjectOfClass:[NSArray class]
                                   forKey:@"states"] mutableCopy];
    _currentStateIndex = [coder decodeIntegerForKey:@"currentStateIndex"];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeObject:self.states forKey:@"states"];
  [coder encodeInteger:self.currentStateIndex forKey:@"currentStateIndex"];
}


#pragma mark - Public methods

- (BOOL)validStateIndex:(NSInteger)index {
  return index >= 0 && [self.states count] > index;
}

- (void)addState:(CryptoState *)state {
  state.stateMachine = self;
  [self.states addObject:state];
}

- (BOOL)insertState:(CryptoState *)state afterState:(CryptoState *)indexState {
  NSInteger index = [self.states indexOfObject:indexState];
  if (index == NSNotFound)
    return NO;
  state.stateMachine = self;
  [self.states insertObject:state atIndex:index];
  return YES;
}

- (CryptoState *)currentState {
  NSInteger index = self.currentStateIndex;
  if (![self validStateIndex:index])
    return nil;
  return (self.states)[index];
}

- (BOOL)checkCurrentStateName:(NSString *)expectedStateName {
  CryptoState *currentState = [self currentState];
  if (!currentState)
    return NO;
  return [currentState.name isEqualToString:expectedStateName];
}

- (BOOL)transitionWithMessage:(id)message error:(NSError *__autoreleasing *)error {
  @synchronized(self) {
    if ([self finalState])
      return NO;

    NSInteger index = self.currentStateIndex + 1;
    if (![self validStateIndex:index])
      return NO;

    self.currentStateIndex = index;
    return [[self currentState] dispatchMessage:message error:error];
  }
}

- (BOOL)transition {
  return [self transitionWithMessage:nil error:nil];
}

- (BOOL)finalState {
  return [self.states count] == self.currentStateIndex + 1;
}

- (BOOL)completedWithSuccess {
  return [self finalState] && [[self currentState] valid];
}

@end
