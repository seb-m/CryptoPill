//
//  SchnorrSign.h
//  CryptoPill
//
//  Created by Sébastien Martini on 04/10/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

#import <Foundation/Foundation.h>


extern const NSUInteger kSchnorrSignatureKeySize;


@class SecureData;

@interface SchnorrSign : NSObject

// Return the signature; or nil if it failed.
+ (NSData *)signData:(NSData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey;

// Return YES if signature is valid; NO otherwise.
+ (BOOL)verifySignature:(NSData *)signature forData:(NSData *)data publicKey:(NSData *)publicKey;

@end
