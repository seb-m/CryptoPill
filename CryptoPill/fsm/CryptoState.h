//
//  CryptoState.h
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


typedef NS_ENUM(NSUInteger, CryptoStateStatus){
  CryptoStateInactive = 0,  // State not entered
  CryptoStateActive,        // State entered
  CryptoStateValid,         // State successfully finished
  CryptoStateInvalid        // State failed
};


@class CryptoStateMachine;

@interface CryptoState : NSObject<NSSecureCoding, NSCopying>

// State's name.
@property (nonatomic, readonly, copy) NSString *name;

// Parent state machine wherein state is inserted. Used for accessing context's
// attributes from state's subclass.
@property (nonatomic, weak) CryptoStateMachine *stateMachine;

// Current state's status.
@property (nonatomic, assign) CryptoStateStatus status;


// New named state.
- (id)initWithName:(NSString *)stateName;

// Formally enters this state by dispatching a message. This method automatically
// activates this state. At the end of this method the state is either left in a
// final valid or invalid state (the return value reflect this status). Method to
// subclass.
- (BOOL)dispatchMessage:(id)message error:(NSError *__autoreleasing *)error;

// Alternative to the previous method, automatically set the state in a valid
// state. Useful when only -outputMessage needs to be overriden.
- (void)terminate;

// YES if its state is valid.
- (BOOL)valid;

// Optional output message available only after state is activated. Method to
// subclass.
- (id<NSSecureCoding>)outputMessage;

@end
