//
//  CryptoStateMachine.h
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


extern NSString *CryptoStateMachineErrorDomain;


@class CryptoState;

@interface CryptoStateMachine : NSObject<NSSecureCoding, NSCopying>

// Append a new state at the end of the current array of states. The first item
// of the array is the root state and the last one is the final state.
- (void)addState:(CryptoState *)state;
- (BOOL)insertState:(CryptoState *)state afterState:(CryptoState *)indexState;

// Return the current state or nil if it is undefined.
- (CryptoState *)currentState;
- (BOOL)checkCurrentStateName:(NSString *)expectedStateName;

// Transition to the next state and dispatch a message. Return YES if it has
// transitionned to its next state and this new state is currently valid and if
// the processing of the message has succeeded.
- (BOOL)transitionWithMessage:(id)message error:(NSError *__autoreleasing *)error;
// Return YES if it has successfully transitionned to its next state.
- (BOOL)transition;

// YES if the fsm is in its final state.
- (BOOL)finalState;
// YES if the fsm is in its final state and this state terminated with success.
- (BOOL)completedWithSuccess;

@end
