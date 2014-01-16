//
//  Box.h
//  CryptoPill
//
//  Created by Sébastien Martini on 03/05/13.
//  Copyright (c) 2013 Dbzteam.org. All rights reserved.
//

@import Foundation;


@class SecureData;

@interface Box : NSObject

// Encryptions without nonces internally generate random nonces. These class
// methods return nil if an error happened. Each method has also its SecureData
// counterpart method.

// Encryption
+ (NSData *)boxData:(NSData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey nonce:(NSData *)nonce;
+ (NSData *)boxSecureData:(SecureData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey nonce:(NSData *)nonce;

+ (NSData *)boxData:(NSData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey;
+ (NSData *)boxSecureData:(SecureData *)data publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey;

// Decryption
+ (NSData *)boxDataOpen:(NSData *)encryptedData publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey;
+ (SecureData *)boxSecureDataOpen:(NSData *)encryptedData publicKey:(NSData *)publicKey secretKey:(SecureData *)secretKey;

// Helpers to remove / insert leading zero bytes. See NaCl documentation for more
// details.
//
// Example:
//  NSData *encryptedData = [Box boxRemoveZeroBytes:[Box boxData:plaintext publicKey:pk secretKey:sk]]
//  NSData *decryptedData = [Box boxDataOpen:[Box boxInsertZeroBytes:encryptedData]
//                                 publicKey:pk
//                                 secretKey:sk]
//
+ (NSData *)boxRemoveZeroBytes:(NSData *)encryptedData;
+ (NSData *)boxInsertZeroBytes:(NSData *)encryptedData;

@end
