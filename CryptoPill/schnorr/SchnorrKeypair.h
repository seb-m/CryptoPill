//
//  SchnorrKeypair.h
//  CryptoPill
//
//  Created by Sébastien Martini on 12/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


extern const NSUInteger kSchnorrSecretKeySize;
extern const NSUInteger kSchnorrPublicKeySize;


@class SecureData;

@interface SchnorrKeypair : NSObject

// Generate a new secret key, equivalent to a Curve25519 secret key.
+ (SecureData *)generateSecretKey;

// Return the public key associated with provided secret key.
+ (NSData *)publicKeyFromSecretKey:(SecureData *)secretKey;

@end
