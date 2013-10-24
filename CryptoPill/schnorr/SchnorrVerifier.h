//
//  SchnorrVerifier.h
//  CryptoPill
//
//  Created by Sébastien Martini on 23/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "CryptoStateMachine.h"


@interface SchnorrVerifier : CryptoStateMachine

@property (nonatomic, readonly, strong) NSData *publicKey;
@property (nonatomic, strong) NSData *publicKeyR;
@property (nonatomic, readonly, strong) NSMutableData *challenge;

- (id)initWithPublicKey:(NSData *)pubKey;

@end
