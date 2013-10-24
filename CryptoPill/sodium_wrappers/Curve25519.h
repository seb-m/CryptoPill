//
//  Curve25519.h
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


extern const NSUInteger kCurve25519ScalarSize;
extern const NSUInteger kCurve25519PublicKeySize;


@class SecureData;

@interface Curve25519 : NSObject

+ (SecureData *)scalarmultCurve25519GenerateScalar;
+ (NSData *)scalarmultCurve25519BaseWithScalar:(SecureData *)scalar;
+ (SecureData *)scalarmultCurve25519WithScalar:(SecureData *)scalar publicKey:(NSData *)publicKey;

+ (NSData *)publicKeyFromEd25519PublicKey:(NSData *)ed25519PublicKey;

@end
