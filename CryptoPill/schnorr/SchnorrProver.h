//
//  SchnorrProver.h
//  CryptoPill
//
//  Created by Sébastien Martini on 22/04/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import "CryptoStateMachine.h"

#import "SecureData.h"


@interface SchnorrProver : CryptoStateMachine

@property (nonatomic, readonly, strong) NSData *publicKey;
@property (nonatomic, readonly, strong) SecureData *secretKey;
@property (nonatomic, readonly, strong) NSMutableData *publicKeyR;
@property (nonatomic, readonly, strong) SecureData *secretKeyR;
@property (nonatomic, strong) NSData *challenge;

- (id)initWithPublicKey:(NSData *)pubKey secretKey:(SecureData *)secKey;

@end
